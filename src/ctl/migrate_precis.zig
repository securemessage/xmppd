//! Offline migration of account-bearing keys to RFC 7622 localparts.
//!
//! The planner rewrites only keys and JID-valued index fields. Stanza and
//! other payload bytes are never rewritten. A plan with any collision or
//! unpreparable localpart is rejected before the first write. Reapplication
//! is idempotent: once every key is prepared, the next plan is empty.

const std = @import("std");
const backend_mod = @import("backend");
const precis = @import("precis_username");

/// Per-thread migration scratch. Prepared localparts are copied into plan
/// storage before the next row is read, so reuse never aliases plan data.
threadlocal var migrate_precis_scratch: precis.Scratch = undefined;

const NS_USERS = backend_mod.registered("users");
const NS_LOCKS = backend_mod.registered("locks");
const NS_ROSTERS = backend_mod.registered("rosters");
const NS_BLOCKLIST = backend_mod.registered("blocklist");
const NS_VCARDS = backend_mod.registered("vcards");
const NS_PEP = backend_mod.registered("pep");
const NS_LASTACT = backend_mod.registered("lastact");
const NS_OFFLINE = backend_mod.registered("offline");
const NS_OFFLINE_V2 = backend_mod.registered("offline_v2");
const NS_OFFLINE_SEQ = backend_mod.registered("offline_seq");
const NS_OFFLINE_HOLD_V2 = backend_mod.registered("offline_hold_v2");
const NS_OFFLINE_HOLD_TOKEN = backend_mod.registered("offline_hold_token");
const NS_ROOM_AFFILIATIONS = backend_mod.registered("room_affiliations");
const NS_PENDING_SUB = backend_mod.registered("pending_sub");
const NS_MESSAGES = backend_mod.registered("messages");
const NS_BY_CONTACT = backend_mod.registered("by_contact");
/// Internal, unregistered namespace for migrate-precis completion markers.
/// It is written atomically with the data batch it describes.
const NS_MIGRATION_STATE: []const u8 = &[_]u8{
    'm', 'i', 'g', 'r', 'a', 't', 'e', '-', 's', 't', 'a', 't', 'e',
};

pub const Database = enum { auth, op, archive };

pub const ForcedRename = struct {
    old_localpart: []const u8,
    new_localpart: []const u8,
};

pub const IssueKind = enum {
    collision,
    invalid_name,
    key_too_long,
    /// Non-blocking: a duplicate reference row was dropped because the
    /// prepared-key row already occupies the target.
    deduplicated,
    /// Non-blocking: a data row with a colliding key and different value was
    /// moved to a deterministic stanza-id suffix instead of being deleted.
    rekeyed,
};

pub const Issue = struct {
    db: Database,
    namespace: []const u8,
    kind: IssueKind,
    key: []u8,
    target: []u8,
};

pub const Rename = struct {
    db: Database,
    namespace: []const u8,
    old_key: []u8,
    new_key: []u8,
    /// A replacement for a JID-valued index field; null keeps the stored value.
    new_value: ?[]u8,
    same_key: bool,
    value_len: usize,
    /// The changed component is a reference; an occupied prepared key is a
    /// dedupe, not a collision.
    reference_duplicate: bool = false,
    /// The changed component is a data-only owner; an occupied target row is
    /// the same nonexistent identity and is deduplicated.
    data_duplicate: bool = false,
    /// Remove old_key without writing new_key (deduplicated reference row).
    delete_only: bool = false,
    /// The source spelling names a users row; used to pick the winner when
    /// several references move into one freed prepared key.
    has_users: bool = false,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    renames: std.ArrayListUnmanaged(Rename) = .{},
    issues: std.ArrayListUnmanaged(Issue) = .{},
    rename_bytes: usize = 0,
    rekey_count: usize = 0,
    recovery_digest: ?[]u8 = null,
    seq_targets: std.StringHashMapUnmanaged(void) = .{},
    rekey_ids: std.StringHashMapUnmanaged([]u8) = .{},

    pub fn init(allocator: std.mem.Allocator) Plan {
        return .{ .allocator = allocator };
    }

    /// Deduplicated reference drops are reported but do not block apply.
    pub fn hasBlockingIssues(self: *const Plan) bool {
        for (self.issues.items) |issue| {
            if (issue.kind != .deduplicated and issue.kind != .rekeyed) return true;
        }
        return false;
    }

    pub fn deinit(self: *Plan) void {
        for (self.renames.items) |rename| {
            self.allocator.free(rename.old_key);
            self.allocator.free(rename.new_key);
            if (rename.new_value) |value| self.allocator.free(value);
        }
        self.renames.deinit(self.allocator);
        for (self.issues.items) |issue| {
            self.allocator.free(issue.key);
            self.allocator.free(issue.target);
        }
        self.issues.deinit(self.allocator);
        if (self.recovery_digest) |digest| self.allocator.free(digest);
        var seq_keys = self.seq_targets.keyIterator();
        while (seq_keys.next()) |key| self.allocator.free(key.*);
        self.seq_targets.deinit(self.allocator);
        var rekey_it = self.rekey_ids.iterator();
        while (rekey_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.rekey_ids.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const ApplyOptions = struct {
    /// Above this many rewritten key+value bytes, LMDB uses per-prefix batches
    /// instead of one write transaction per DB. The archive always uses one
    /// WriteBatch per prefix.
    single_txn_budget: usize = 64 * 1024 * 1024,
    /// Enables resumable apply. The full fixed plan, a digest and a
    /// `migrate-precis.pending` marker are written before the first commit;
    /// per-DB and per-prefix done markers are committed atomically with their
    /// data. If a commit fails, rerunning `migrate-precis --apply` loads the
    /// stored plan and replays only unfinished batches. `--rename` and
    /// `deluser --raw` are refused while the marker exists.
    journal_dir: ?[]const u8 = null,
};

pub const recovery_pending_file = "migrate-precis.pending";
pub const recovery_plan_file = "migrate-precis.resume";
const recovery_header = "xmppd-migrate-precis-v1\n";

fn dbFromTag(tag: []const u8) !Database {
    if (std.mem.eql(u8, tag, "auth")) return .auth;
    if (std.mem.eql(u8, tag, "op")) return .op;
    if (std.mem.eql(u8, tag, "archive")) return .archive;
    return error.InvalidRecoveryPlan;
}

fn canonicalNamespace(name: []const u8) ?[]const u8 {
    const all = [_][]const u8{
        NS_USERS,             NS_LOCKS,       NS_ROSTERS,         NS_BLOCKLIST,
        NS_VCARDS,            NS_PEP,         NS_LASTACT,         NS_OFFLINE,
        NS_OFFLINE_V2,        NS_OFFLINE_SEQ, NS_OFFLINE_HOLD_V2, NS_OFFLINE_HOLD_TOKEN,
        NS_ROOM_AFFILIATIONS, NS_PENDING_SUB, NS_MESSAGES,        NS_BY_CONTACT,
    };
    for (all) |ns| if (std.mem.eql(u8, ns, name)) return ns;
    return null;
}

fn hexDecodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (text.len % 2 != 0) return error.InvalidRecoveryPlan;
    const result = try allocator.alloc(u8, text.len / 2);
    errdefer allocator.free(result);
    for (0..result.len) |i| {
        result[i] = (try std.fmt.charToDigit(text[i * 2], 16)) << 4 |
            try std.fmt.charToDigit(text[i * 2 + 1], 16);
    }
    return result;
}

fn artifactPathAbs(allocator: std.mem.Allocator, dir: []const u8, basename: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ dir, basename });
}

fn writeRecoveryMarker(allocator: std.mem.Allocator, dir: []const u8, digest_hex: []const u8) !void {
    const path = try artifactPathAbs(allocator, dir, recovery_pending_file);
    defer allocator.free(path);
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(digest_hex);
    try file.writeAll("\n");
    try file.sync();
}

fn writeRecoveryPlan(allocator: std.mem.Allocator, dir: []const u8, plan: *const Plan) ![]u8 {
    const path = try artifactPathAbs(allocator, dir, recovery_plan_file);
    defer allocator.free(path);
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    try file.writeAll(recovery_header);
    hasher.update(recovery_header);
    for (plan.renames.items) |rename| {
        const ns_hex = try hexEncodeAlloc(allocator, rename.namespace);
        defer allocator.free(ns_hex);
        const old_hex = try hexEncodeAlloc(allocator, rename.old_key);
        defer allocator.free(old_hex);
        const new_hex = try hexEncodeAlloc(allocator, rename.new_key);
        defer allocator.free(new_hex);
        const value_hex = if (rename.new_value) |value| try hexEncodeAlloc(allocator, value) else null;
        defer if (value_hex) |value| allocator.free(value);
        var flags: u8 = 0;
        if (rename.same_key) flags |= 1;
        if (rename.delete_only) flags |= 2;
        const line = try std.fmt.allocPrint(
            allocator,
            "{s}\t{d}\t{s}\t{s}\t{s}\t{s}\n",
            .{
                @tagName(rename.db),
                flags,
                ns_hex,
                old_hex,
                new_hex,
                value_hex orelse "-",
            },
        );
        defer allocator.free(line);
        try file.writeAll(line);
        hasher.update(line);
    }
    try file.sync();
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const digest_hex = try hexEncodeAlloc(allocator, &digest);
    errdefer allocator.free(digest_hex);
    try writeRecoveryMarker(allocator, dir, digest_hex);
    return digest_hex;
}

fn readRecoveryPlan(allocator: std.mem.Allocator, dir: []const u8) !Plan {
    const pending_path = try artifactPathAbs(allocator, dir, recovery_pending_file);
    defer allocator.free(pending_path);
    const plan_path = try artifactPathAbs(allocator, dir, recovery_plan_file);
    defer allocator.free(plan_path);

    const pending = try std.fs.cwd().readFileAlloc(allocator, pending_path, 256);
    defer allocator.free(pending);
    const expected_digest = std.mem.trim(u8, pending, " \t\r\n");
    const data = try std.fs.cwd().readFileAlloc(allocator, plan_path, 256 * 1024 * 1024);
    defer allocator.free(data);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const actual_hex = try hexEncodeAlloc(allocator, &digest);
    defer allocator.free(actual_hex);
    if (!std.mem.eql(u8, expected_digest, actual_hex)) return error.RecoveryDigestMismatch;

    var plan = Plan.init(allocator);
    errdefer plan.deinit();
    plan.recovery_digest = try allocator.dupe(u8, expected_digest);
    var lines = std.mem.splitScalar(u8, data, '\n');
    const header = lines.next() orelse return error.InvalidRecoveryPlan;
    if (!std.mem.eql(u8, header, std.mem.trimRight(u8, recovery_header, "\n"))) return error.InvalidRecoveryPlan;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const db_text = fields.next() orelse return error.InvalidRecoveryPlan;
        const flags_text = fields.next() orelse return error.InvalidRecoveryPlan;
        const ns_hex = fields.next() orelse return error.InvalidRecoveryPlan;
        const old_hex = fields.next() orelse return error.InvalidRecoveryPlan;
        const new_hex = fields.next() orelse return error.InvalidRecoveryPlan;
        const value_hex = fields.next() orelse return error.InvalidRecoveryPlan;
        if (fields.next() != null) return error.InvalidRecoveryPlan;

        const ns_raw = try hexDecodeAlloc(allocator, ns_hex);
        defer allocator.free(ns_raw);
        const namespace = canonicalNamespace(ns_raw) orelse return error.InvalidRecoveryPlan;
        const old_key = try hexDecodeAlloc(allocator, old_hex);
        errdefer allocator.free(old_key);
        const new_key = try hexDecodeAlloc(allocator, new_hex);
        errdefer allocator.free(new_key);
        const new_value = if (std.mem.eql(u8, value_hex, "-"))
            null
        else
            try hexDecodeAlloc(allocator, value_hex);
        errdefer if (new_value) |value| allocator.free(value);
        const flags = try std.fmt.parseInt(u8, flags_text, 10);
        try plan.renames.append(allocator, .{
            .db = try dbFromTag(db_text),
            .namespace = namespace,
            .old_key = old_key,
            .new_key = new_key,
            .new_value = new_value,
            .same_key = (flags & 1) != 0,
            .delete_only = (flags & 2) != 0,
            .value_len = 0,
        });
        plan.rename_bytes += new_key.len;
    }
    return plan;
}

fn clearRecovery(allocator: std.mem.Allocator, dir: []const u8) void {
    const pending = artifactPathAbs(allocator, dir, recovery_pending_file) catch return;
    defer allocator.free(pending);
    std.fs.cwd().deleteFile(pending) catch {};
    const plan = artifactPathAbs(allocator, dir, recovery_plan_file) catch return;
    defer allocator.free(plan);
    std.fs.cwd().deleteFile(plan) catch {};
}

pub fn recoveryPending(allocator: std.mem.Allocator, dir: []const u8) !bool {
    const path = try artifactPathAbs(allocator, dir, recovery_pending_file);
    defer allocator.free(path);
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

const Rewrite = struct {
    new_key: ?[]u8 = null,
    new_value: ?[]u8 = null,
    /// The changed component is a pure reference (lock key, roster/blocklist
    /// contact, MUC member, by_contact contact). If another row already
    /// occupies the prepared key, this row is deduplicated rather than a
    /// collision: the prepared-key row wins.
    reference_duplicate: bool = false,
    /// The changed component is a data-only owner; an occupied target row is
    /// deduplicated because it is the same nonexistent identity.
    data_duplicate: bool = false,

    fn deinit(self: *Rewrite, allocator: std.mem.Allocator) void {
        if (self.new_key) |key| allocator.free(key);
        if (self.new_value) |value| allocator.free(value);
    }
};

/// Tracks owner spellings per prepared target. Only `users` and account-owned
/// rows (roster, blocklist, vCard, PEP, lastact) define an account. Offline,
/// pending-subscription contact and archive owners are data-only: third
/// parties create them by addressing a spelling, so a data-only spelling
/// whose target has a users row merges into that account instead of blocking.
/// Two data-only spellings with no users row are the same nonexistent
/// identity and also merge.
const OwnerKind = enum { users, account, data };

const Identity = struct {
    users_source: ?[]u8 = null,
    account_source: ?[]u8 = null,
    data_source: ?[]u8 = null,
};

const IdentityTracker = struct {
    plan: *Plan,
    identities: std.StringHashMapUnmanaged(Identity) = .{},
    db: Database,
    namespace: []const u8,

    fn deinit(self: *IdentityTracker, allocator: std.mem.Allocator) void {
        var iterator = self.identities.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            if (entry.value_ptr.users_source) |source| allocator.free(source);
            if (entry.value_ptr.account_source) |source| allocator.free(source);
            if (entry.value_ptr.data_source) |source| allocator.free(source);
        }
        self.identities.deinit(allocator);
    }

    fn record(self: *IdentityTracker, source: []const u8, target: []const u8, ownership: Ownership) !void {
        const kind: OwnerKind = switch (ownership) {
            .users => .users,
            .account => .account,
            .data => .data,
            .reference => return,
        };
        const allocator = self.plan.allocator;
        const gop = try self.identities.getOrPut(allocator, target);
        if (!gop.found_existing) {
            const target_copy = try allocator.dupe(u8, target);
            errdefer allocator.free(target_copy);
            gop.key_ptr.* = target_copy;
            gop.value_ptr.* = .{};
        }
        const identity = gop.value_ptr;

        switch (kind) {
            .users => {
                if (identity.users_source) |existing| {
                    if (!std.mem.eql(u8, existing, source)) try self.report(source, existing, target);
                } else {
                    identity.users_source = try allocator.dupe(u8, source);
                }
                if (identity.account_source) |existing| {
                    if (!std.mem.eql(u8, existing, source)) try self.report(source, existing, target);
                }
            },
            .account => {
                if (identity.account_source) |existing| {
                    if (!std.mem.eql(u8, existing, source)) try self.report(source, existing, target);
                } else {
                    identity.account_source = try allocator.dupe(u8, source);
                }
                if (identity.users_source) |existing| {
                    if (!std.mem.eql(u8, existing, source)) try self.report(source, existing, target);
                }
            },
            .data => {
                if (identity.data_source == null) {
                    identity.data_source = try allocator.dupe(u8, source);
                }
            },
        }
    }

    fn report(self: *IdentityTracker, source: []const u8, existing: []const u8, target: []const u8) !void {
        const detail = try std.fmt.allocPrint(
            self.plan.allocator,
            "'{s}' and '{s}' both fold to '{s}'",
            .{ existing, source, target },
        );
        defer self.plan.allocator.free(detail);
        try addIssue(self.plan, self.db, self.namespace, .collision, source, detail);
    }
};

const RewriteContext = struct {
    hosted_domains: []const []const u8,
    forced: ?ForcedRename,
    identities: *IdentityTracker,
    users_sources: *const std.StringHashMapUnmanaged(void),
};

const Ownership = enum {
    users,
    account,
    data,
    reference,
};

fn isHosted(domain: []const u8, hosted_domains: []const []const u8) bool {
    for (hosted_domains) |hosted| {
        if (std.mem.eql(u8, domain, hosted)) return true;
    }
    return false;
}

fn rewriteLocalpart(allocator: std.mem.Allocator, name: []const u8, ctx: *const RewriteContext, ownership: Ownership) !?[]u8 {
    if (ctx.forced) |rename| {
        if (std.mem.eql(u8, name, rename.old_localpart)) {
            if (ownership != .reference) try ctx.identities.record(name, rename.new_localpart, ownership);
            return try allocator.dupe(u8, rename.new_localpart);
        }
    }

    const prepared = migrate_precis_scratch.localpart(name) catch
        return error.InvalidAccountName;
    if (ownership != .reference) try ctx.identities.record(name, prepared, ownership);
    if (std.mem.eql(u8, prepared, name)) return null;
    return try allocator.dupe(u8, prepared);
}

fn rewriteJid(allocator: std.mem.Allocator, jid: []const u8, ctx: *const RewriteContext, ownership: Ownership) !?[]u8 {
    // A domain-only JID (with or without a resource) has no account
    // localpart and must stay exactly as stored.
    const at = std.mem.indexOfScalar(u8, jid, '@') orelse return null;
    const remainder = jid[at + 1 ..];
    const slash = std.mem.indexOfScalar(u8, remainder, '/');
    const domain = if (slash) |pos| remainder[0..pos] else remainder;
    if (!isHosted(domain, ctx.hosted_domains)) return null;

    const new_local = try rewriteLocalpart(allocator, jid[0..at], ctx, ownership) orelse return null;
    defer allocator.free(new_local);
    const suffix = jid[at..];
    const result = try allocator.alloc(u8, new_local.len + suffix.len);
    @memcpy(result[0..new_local.len], new_local);
    @memcpy(result[new_local.len..], suffix);
    return result;
}

fn rewriteTwoParts(
    allocator: std.mem.Allocator,
    key: []const u8,
    ctx: *const RewriteContext,
    first_is_localpart: bool,
    second_is_localpart: bool,
    first_ownership: Ownership,
    second_ownership: Ownership,
) !?[]u8 {
    const sep = std.mem.indexOfScalar(u8, key, 0) orelse return null;
    const first = key[0..sep];
    const second = key[sep + 1 ..];
    const new_first = if (first_is_localpart)
        try rewriteLocalpart(allocator, first, ctx, first_ownership)
    else
        try rewriteJid(allocator, first, ctx, first_ownership);
    errdefer if (new_first) |value| allocator.free(value);
    const new_second = if (second_is_localpart)
        try rewriteLocalpart(allocator, second, ctx, second_ownership)
    else
        try rewriteJid(allocator, second, ctx, second_ownership);
    errdefer if (new_second) |value| allocator.free(value);
    if (new_first == null and new_second == null) return null;

    const first_bytes = new_first orelse first;
    const second_bytes = new_second orelse second;
    defer if (new_first) |value| allocator.free(value);
    defer if (new_second) |value| allocator.free(value);
    const result = try allocator.alloc(u8, first_bytes.len + 1 + second_bytes.len);
    @memcpy(result[0..first_bytes.len], first_bytes);
    result[first_bytes.len] = 0;
    @memcpy(result[first_bytes.len + 1 ..], second_bytes);
    return result;
}

fn rewriteFirstAndSuffix(
    allocator: std.mem.Allocator,
    key: []const u8,
    ctx: *const RewriteContext,
    ownership: Ownership,
) !?[]u8 {
    const sep = std.mem.indexOfScalar(u8, key, 0) orelse
        return rewriteJid(allocator, key, ctx, ownership);
    const new_first = try rewriteJid(allocator, key[0..sep], ctx, ownership) orelse
        return null;
    defer allocator.free(new_first);
    const suffix = key[sep..];
    const result = try allocator.alloc(u8, new_first.len + suffix.len);
    @memcpy(result[0..new_first.len], new_first);
    @memcpy(result[new_first.len..], suffix);
    return result;
}

fn rewriteByContact(
    allocator: std.mem.Allocator,
    key: []const u8,
    ctx: *const RewriteContext,
) !?[]u8 {
    const first_sep = std.mem.indexOfScalar(u8, key, 0) orelse return null;
    const second_sep_relative = std.mem.indexOfScalar(u8, key[first_sep + 1 ..], 0) orelse
        return rewriteTwoParts(allocator, key, ctx, false, false, .data, .reference);
    const second_sep = first_sep + 1 + second_sep_relative;

    const new_owner = try rewriteJid(allocator, key[0..first_sep], ctx, .data);
    errdefer if (new_owner) |value| allocator.free(value);
    const new_contact = try rewriteJid(
        allocator,
        key[first_sep + 1 .. second_sep],
        ctx,
        .reference,
    );
    errdefer if (new_contact) |value| allocator.free(value);
    if (new_owner == null and new_contact == null) return null;

    const owner = new_owner orelse key[0..first_sep];
    const contact = new_contact orelse key[first_sep + 1 .. second_sep];
    defer if (new_owner) |value| allocator.free(value);
    defer if (new_contact) |value| allocator.free(value);
    const suffix = key[second_sep..];
    const result = try allocator.alloc(u8, owner.len + 1 + contact.len + suffix.len);
    @memcpy(result[0..owner.len], owner);
    result[owner.len] = 0;
    @memcpy(result[owner.len + 1 ..][0..contact.len], contact);
    @memcpy(result[owner.len + 1 + contact.len ..], suffix);
    return result;
}

const REKEY_SEQ_BASE: u64 = 1 << 40;
const REKEY_SEQ_HIGH: u64 = REKEY_SEQ_BASE + 1_000_000;

fn rekeyV2Key(allocator: std.mem.Allocator, key: []const u8, sequence: u64) !?[]u8 {
    const first_sep = std.mem.indexOfScalar(u8, key, 0) orelse return null;
    if (key.len < first_sep + 9) return null;
    const result = try allocator.alloc(u8, key.len);
    @memcpy(result, key);
    std.mem.writeInt(u64, result[first_sep + 1 ..][0..8], sequence, .big);
    return result;
}

fn sequenceValue(sequence: u64) [8]u8 {
    var value: [8]u8 = undefined;
    std.mem.writeInt(u64, &value, sequence, .big);
    return value;
}

fn addSeqHighWater(plan: *Plan, owner: []const u8) !void {
    if (plan.seq_targets.contains(owner)) return;
    const owner_key = try plan.allocator.dupe(u8, owner);
    errdefer plan.allocator.free(owner_key);
    try plan.seq_targets.put(plan.allocator, owner_key, {});
    const high = sequenceValue(REKEY_SEQ_HIGH);
    const seq_old = try plan.allocator.dupe(u8, owner);
    const seq_new = try plan.allocator.dupe(u8, owner);
    const seq_value = try plan.allocator.dupe(u8, &high);
    try plan.renames.append(plan.allocator, .{
        .db = .op,
        .namespace = NS_OFFLINE_SEQ,
        .old_key = seq_old,
        .new_key = seq_new,
        .new_value = seq_value,
        .same_key = true,
        .value_len = high.len,
    });
    plan.rename_bytes += seq_new.len + seq_value.len;
}

fn rekeyComposite(allocator: std.mem.Allocator, owner: []const u8, ts8: []const u8, id: []const u8) ![]u8 {
    const key = try allocator.alloc(u8, owner.len + 1 + ts8.len + 1 + id.len);
    @memcpy(key[0..owner.len], owner);
    key[owner.len] = 0;
    @memcpy(key[owner.len + 1 ..][0..ts8.len], ts8);
    key[owner.len + 1 + ts8.len] = 0;
    @memcpy(key[owner.len + 1 + ts8.len + 1 ..], id);
    return key;
}

fn lookupRekeyId(plan: *const Plan, owner: []const u8, ts8: []const u8, id: []const u8) ?[]const u8 {
    const key = rekeyComposite(plan.allocator, owner, ts8, id) catch return null;
    defer plan.allocator.free(key);
    return plan.rekey_ids.get(key);
}

fn getOrCreateRekeyId(plan: *Plan, owner: []const u8, ts8: []const u8, id: []const u8) ![]const u8 {
    const key = try rekeyComposite(plan.allocator, owner, ts8, id);
    if (plan.rekey_ids.get(key)) |existing| {
        plan.allocator.free(key);
        return existing;
    }
    const stored = try std.fmt.allocPrint(plan.allocator, "~mig-{x:0>16}", .{std.crypto.random.int(u64)});
    try plan.rekey_ids.put(plan.allocator, key, stored);
    return stored;
}

fn rekeyStanzaKeyWithId(allocator: std.mem.Allocator, key: []const u8, new_id: []const u8) !?[]u8 {
    const first_sep = std.mem.indexOfScalar(u8, key, 0) orelse return null;
    if (key.len < first_sep + 10 or key[first_sep + 9] != 0) return null;
    const prefix_len = first_sep + 10;
    const result = try allocator.alloc(u8, prefix_len + new_id.len);
    @memcpy(result[0..prefix_len], key[0..prefix_len]);
    @memcpy(result[prefix_len..], new_id);
    return result;
}

fn rekeyStanzaKey(allocator: std.mem.Allocator, key: []const u8, counter: usize) !?[]u8 {
    const first_sep = std.mem.indexOfScalar(u8, key, 0) orelse return null;
    const rest = key[first_sep + 1 ..];
    const second_rel = std.mem.indexOfScalar(u8, rest, 0) orelse return null;
    const second_sep = first_sep + 1 + second_rel;
    const stanza_id = key[second_sep + 1 ..];
    const new_id = try std.fmt.allocPrint(allocator, "{s}-mig-{d}", .{ stanza_id, counter });
    defer allocator.free(new_id);
    const result = try allocator.alloc(u8, second_sep + 1 + new_id.len);
    @memcpy(result[0 .. second_sep + 1], key[0 .. second_sep + 1]);
    @memcpy(result[second_sep + 1 ..], new_id);
    return result;
}

fn rewriteOfflineV2Value(
    allocator: std.mem.Allocator,
    value: []const u8,
    ctx: *const RewriteContext,
    target_owner: []const u8,
) !?[]u8 {
    if (value.len < 12) return null;
    const id_len = std.mem.readInt(u32, value[8..12], .big);
    const from_offset = 12 + @as(usize, id_len);
    if (from_offset > value.len) return null;
    const ts8 = value[0..8];
    const old_id = value[12..from_offset];
    const new_id = lookupRekeyId(ctx.identities.plan, target_owner, ts8, old_id) orelse old_id;
    const new_from = try rewriteJid(allocator, value[from_offset..], ctx, .reference) orelse return null;
    defer allocator.free(new_from);
    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, value[0..8]);
    var id_len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &id_len_buf, @intCast(new_id.len), .big);
    try out.appendSlice(allocator, &id_len_buf);
    try out.appendSlice(allocator, new_id);
    try out.appendSlice(allocator, new_from);
    return try out.toOwnedSlice(allocator);
}

fn firstPartUnchanged(old_key: []const u8, new_key: []const u8) bool {
    const old_sep = std.mem.indexOfScalar(u8, old_key, 0) orelse return false;
    const new_sep = std.mem.indexOfScalar(u8, new_key, 0) orelse return false;
    return std.mem.eql(u8, old_key[0..old_sep], new_key[0..new_sep]);
}

fn rewriteRoomAffiliation(
    allocator: std.mem.Allocator,
    key: []const u8,
    ctx: *const RewriteContext,
) !?[]u8 {
    const sep = std.mem.indexOfScalar(u8, key, 0) orelse return null;
    // The room JID is an OpaqueString room name and stays as stored. Only the
    // member JID is an account localpart in scope for this migration.
    const new_member = try rewriteJid(allocator, key[sep + 1 ..], ctx, .reference) orelse
        return null;
    defer allocator.free(new_member);
    const room = key[0 .. sep + 1];
    const result = try allocator.alloc(u8, room.len + new_member.len);
    @memcpy(result[0..room.len], room);
    @memcpy(result[room.len..], new_member);
    return result;
}

fn rewriteEntry(
    allocator: std.mem.Allocator,
    db: Database,
    namespace: []const u8,
    key: []const u8,
    value: []const u8,
    ctx: *const RewriteContext,
) !Rewrite {
    var rewrite: Rewrite = .{};
    errdefer rewrite.deinit(allocator);
    ctx.identities.db = db;
    ctx.identities.namespace = namespace;

    if (db == .auth and std.mem.eql(u8, namespace, NS_USERS)) {
        rewrite.new_key = try rewriteLocalpart(allocator, key, ctx, .users);
    } else if (db == .auth and std.mem.eql(u8, namespace, NS_LOCKS)) {
        rewrite.new_key = try rewriteLocalpart(allocator, key, ctx, .reference);
        rewrite.reference_duplicate = rewrite.new_key != null;
    } else if (std.mem.eql(u8, namespace, NS_ROSTERS) or
        std.mem.eql(u8, namespace, NS_BLOCKLIST))
    {
        rewrite.new_key = try rewriteTwoParts(allocator, key, ctx, false, false, .account, .reference);
        if (rewrite.new_key) |new_key| rewrite.reference_duplicate = firstPartUnchanged(key, new_key);
    } else if (std.mem.eql(u8, namespace, NS_PENDING_SUB)) {
        // The contact half is data-only: third parties create it by
        // subscribing to a spelling. The subscriber is a reference.
        rewrite.new_key = try rewriteTwoParts(allocator, key, ctx, false, false, .data, .reference);
        if (rewrite.new_key) |new_key| {
            rewrite.reference_duplicate = firstPartUnchanged(key, new_key);
            rewrite.data_duplicate = !rewrite.reference_duplicate;
        }
    } else if (std.mem.eql(u8, namespace, NS_BY_CONTACT)) {
        rewrite.new_key = try rewriteByContact(allocator, key, ctx);
        if (rewrite.new_key) |new_key| {
            rewrite.reference_duplicate = firstPartUnchanged(key, new_key);
            rewrite.data_duplicate = !rewrite.reference_duplicate;
            const first_sep = std.mem.indexOfScalar(u8, new_key, 0) orelse 0;
            const rest = new_key[first_sep + 1 ..];
            const second_rel = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
            const second_sep = first_sep + 1 + second_rel;
            const owner = new_key[0..first_sep];
            const ts8 = new_key[second_sep + 1 ..];
            if (lookupRekeyId(ctx.identities.plan, owner, ts8, value)) |new_id| {
                rewrite.new_value = try allocator.dupe(u8, new_id);
            }
        }
    } else if (std.mem.eql(u8, namespace, NS_ROOM_AFFILIATIONS)) {
        rewrite.new_key = try rewriteRoomAffiliation(allocator, key, ctx);
        rewrite.reference_duplicate = rewrite.new_key != null;
    } else if (std.mem.eql(u8, namespace, NS_OFFLINE_SEQ)) {
        // New offline schema: the sequence key is the recipient JID.
        rewrite.new_key = try rewriteJid(allocator, key, ctx, .data);
    } else if (std.mem.eql(u8, namespace, NS_OFFLINE_V2)) {
        rewrite.new_key = try rewriteFirstAndSuffix(allocator, key, ctx, .data);
        const target_owner = if (rewrite.new_key) |new_key|
            new_key[0 .. std.mem.indexOfScalar(u8, new_key, 0) orelse new_key.len]
        else
            key[0 .. std.mem.indexOfScalar(u8, key, 0) orelse key.len];
        rewrite.new_value = try rewriteOfflineV2Value(allocator, value, ctx, target_owner);
    } else if (std.mem.eql(u8, namespace, NS_OFFLINE_HOLD_V2) or
        std.mem.eql(u8, namespace, NS_OFFLINE_HOLD_TOKEN))
    {
        rewrite.new_key = try rewriteFirstAndSuffix(allocator, key, ctx, .data);
    } else if (std.mem.eql(u8, namespace, NS_VCARDS) or
        std.mem.eql(u8, namespace, NS_LASTACT) or
        std.mem.eql(u8, namespace, NS_PEP) or
        std.mem.eql(u8, namespace, NS_OFFLINE) or
        std.mem.eql(u8, namespace, NS_MESSAGES))
    {
        const ownership: Ownership = if (std.mem.eql(u8, namespace, NS_OFFLINE) or
            std.mem.eql(u8, namespace, NS_MESSAGES))
            .data
        else
            .account;
        rewrite.new_key = try rewriteFirstAndSuffix(allocator, key, ctx, ownership);
        if (ownership == .data) rewrite.data_duplicate = rewrite.new_key != null;
        if (std.mem.eql(u8, namespace, NS_OFFLINE)) {
            rewrite.new_value = try rewriteJid(allocator, value, ctx, .reference);
        }
    }

    // The op and auth LMDB stores share the 511-octet key bound. The archive
    // backend has no such bound.
    if (db != .archive) {
        if (rewrite.new_key) |new_key| {
            if (new_key.len > 511) return error.KeyTooLong;
        }
    }
    return rewrite;
}

fn localpartHasUsers(set: *const std.StringHashMapUnmanaged(void), jid_or_name: []const u8) bool {
    const local = if (std.mem.indexOfScalar(u8, jid_or_name, '@')) |at| jid_or_name[0..at] else jid_or_name;
    return set.contains(local);
}

fn renameHasUsers(ns: []const u8, key: []const u8, set: *const std.StringHashMapUnmanaged(void)) bool {
    if (std.mem.eql(u8, ns, NS_LOCKS) or std.mem.eql(u8, ns, NS_USERS)) {
        return localpartHasUsers(set, key);
    }
    if (std.mem.eql(u8, ns, NS_VCARDS) or
        std.mem.eql(u8, ns, NS_LASTACT) or
        std.mem.eql(u8, ns, NS_PEP) or
        std.mem.eql(u8, ns, NS_OFFLINE) or
        std.mem.eql(u8, ns, NS_OFFLINE_V2) or
        std.mem.eql(u8, ns, NS_OFFLINE_SEQ) or
        std.mem.eql(u8, ns, NS_OFFLINE_HOLD_V2) or
        std.mem.eql(u8, ns, NS_OFFLINE_HOLD_TOKEN) or
        std.mem.eql(u8, ns, NS_MESSAGES))
    {
        const sep = std.mem.indexOfScalar(u8, key, 0) orelse key.len;
        return localpartHasUsers(set, key[0..sep]);
    }
    const first_sep = std.mem.indexOfScalar(u8, key, 0) orelse return localpartHasUsers(set, key);
    // Only the changed component decides the winner: contact for roster,
    // blocklist, pending_sub and by_contact, member for room affiliations.
    // The owner half is often an account itself and must not mask a stale
    // contact such as BOB.
    const rest = key[first_sep + 1 ..];
    const second_sep = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
    return localpartHasUsers(set, rest[0..second_sep]);
}

fn addIssue(
    plan: *Plan,
    db: Database,
    namespace: []const u8,
    kind: IssueKind,
    key: []const u8,
    target: []const u8,
) !void {
    const key_copy = try plan.allocator.dupe(u8, key);
    errdefer plan.allocator.free(key_copy);
    const target_copy = try plan.allocator.dupe(u8, target);
    errdefer plan.allocator.free(target_copy);
    try plan.issues.append(plan.allocator, .{
        .db = db,
        .namespace = namespace,
        .kind = kind,
        .key = key_copy,
        .target = target_copy,
    });
}

fn targetId(allocator: std.mem.Allocator, db: Database, namespace: []const u8, key: []const u8) ![]u8 {
    const tag = @tagName(db);
    const result = try allocator.alloc(u8, tag.len + 1 + namespace.len + 1 + key.len);
    @memcpy(result[0..tag.len], tag);
    result[tag.len] = 0;
    @memcpy(result[tag.len + 1 ..][0..namespace.len], namespace);
    result[tag.len + 1 + namespace.len] = 0;
    @memcpy(result[tag.len + 1 + namespace.len + 1 ..], key);
    return result;
}

fn planNamespace(
    plan: *Plan,
    targets: *std.StringHashMapUnmanaged(void),
    db: Database,
    backend: anytype,
    namespace: []const u8,
    ctx: *const RewriteContext,
) !void {
    // LMDB allows one transaction per thread. Collect every rewrite first,
    // close the iterator's read transaction, and only then issue collision
    // reads against the same backend.
    var pending: std.ArrayListUnmanaged(Rename) = .{};
    var transferred: usize = 0;
    defer {
        for (pending.items[transferred..]) |rename| {
            plan.allocator.free(rename.old_key);
            plan.allocator.free(rename.new_key);
            if (rename.new_value) |value| plan.allocator.free(value);
        }
        pending.deinit(plan.allocator);
    }

    {
        var iterator = try backend.iterator(namespace, "");
        defer iterator.deinit();
        while (iterator.next()) |entry| {
            var rewrite = rewriteEntry(
                plan.allocator,
                db,
                namespace,
                entry.key,
                entry.value,
                ctx,
            ) catch |err| switch (err) {
                error.InvalidAccountName => {
                    try addIssue(plan, db, namespace, .invalid_name, entry.key, "");
                    continue;
                },
                error.KeyTooLong => {
                    try addIssue(plan, db, namespace, .key_too_long, entry.key, "");
                    continue;
                },
                else => return err,
            };
            defer rewrite.deinit(plan.allocator);
            if (rewrite.new_key == null and rewrite.new_value == null) continue;

            const new_key = rewrite.new_key orelse entry.key;
            const old_copy = try plan.allocator.dupe(u8, entry.key);
            errdefer plan.allocator.free(old_copy);
            const new_copy = try plan.allocator.dupe(u8, new_key);
            errdefer plan.allocator.free(new_copy);
            const new_value = if (rewrite.new_value) |value|
                try plan.allocator.dupe(u8, value)
            else
                null;
            errdefer if (new_value) |value| plan.allocator.free(value);
            try pending.append(plan.allocator, .{
                .db = db,
                .namespace = namespace,
                .old_key = old_copy,
                .new_key = new_copy,
                .new_value = new_value,
                .same_key = rewrite.new_key == null,
                .value_len = entry.value.len,
                .reference_duplicate = rewrite.reference_duplicate,
                .data_duplicate = rewrite.data_duplicate,
                .has_users = renameHasUsers(namespace, entry.key, ctx.users_sources),
            });
        }
    }

    // A rename whose target is another row's old key can proceed after that
    // occupant moves away (for example --rename bob bob2 frees bob for Bob).
    var old_keys: std.StringHashMapUnmanaged(void) = .{};
    defer old_keys.deinit(plan.allocator);
    for (pending.items) |rename| {
        if (!rename.same_key) try old_keys.put(plan.allocator, rename.old_key, {});
    }
    std.sort.heap(Rename, pending.items, {}, pendingLessThan);

    for (pending.items) |original| {
        var rename = original;
        var equal_data_value = false;
        if (!rename.same_key) {
            if (std.mem.eql(u8, namespace, NS_OFFLINE_SEQ)) {
                const target_value = try backend.get(plan.allocator, namespace, rename.new_key);
                defer if (target_value) |value| plan.allocator.free(value);
                if (target_value != null) {
                    try addIssue(plan, db, namespace, .deduplicated, rename.old_key, rename.new_key);
                    var dropped = rename;
                    dropped.delete_only = true;
                    dropped.same_key = false;
                    try plan.renames.append(plan.allocator, dropped);
                    transferred += 1;
                    plan.rename_bytes += dropped.new_key.len + dropped.value_len;

                    try addSeqHighWater(plan, rename.new_key);
                    continue;
                }
            }

            if (std.mem.eql(u8, namespace, NS_OFFLINE_V2)) {
                const target_value = try backend.get(plan.allocator, namespace, rename.new_key);
                defer if (target_value) |value| plan.allocator.free(value);
                if (target_value != null) {
                    const old_value = try backend.get(plan.allocator, namespace, rename.old_key);
                    defer if (old_value) |value| plan.allocator.free(value);
                    if (old_value != null and std.mem.eql(u8, old_value.?, target_value.?)) {
                        equal_data_value = true;
                    } else {
                        plan.rekey_count += 1;
                        const new_seq = REKEY_SEQ_BASE + plan.rekey_count;
                        const rekeyed = try rekeyV2Key(plan.allocator, rename.new_key, new_seq) orelse
                            return error.InvalidRecoveryPlan;
                        plan.allocator.free(rename.new_key);
                        rename.new_key = rekeyed;
                        rename.same_key = false;
                        try addIssue(plan, db, namespace, .rekeyed, rename.old_key, rename.new_key);

                        const first_sep = std.mem.indexOfScalar(u8, rename.new_key, 0).?;
                        const owner = rename.new_key[0..first_sep];
                        try addSeqHighWater(plan, owner);
                    }
                }
            }

            // Offline and messages keys contain a sender-controlled stanza id.
            // Equal keys with different values are re-keyed, never deleted.
            if (rename.data_duplicate and
                (std.mem.eql(u8, namespace, NS_OFFLINE) or std.mem.eql(u8, namespace, NS_MESSAGES)))
            {
                const key = rename.new_key;
                const first_sep = std.mem.indexOfScalar(u8, key, 0) orelse
                    return error.InvalidRecoveryPlan;
                if (key.len < first_sep + 10 or key[first_sep + 9] != 0)
                    return error.InvalidRecoveryPlan;
                const owner = key[0..first_sep];
                const ts8 = key[first_sep + 1 .. first_sep + 9];
                const old_id = key[first_sep + 10 ..];
                const target_value = try backend.get(plan.allocator, namespace, rename.new_key);
                defer if (target_value) |value| plan.allocator.free(value);
                var must_rekey = lookupRekeyId(plan, owner, ts8, old_id) != null;
                if (target_value != null) {
                    const old_value = try backend.get(plan.allocator, namespace, rename.old_key);
                    defer if (old_value) |value| plan.allocator.free(value);
                    const same_value = old_value != null and std.mem.eql(u8, old_value.?, target_value.?);
                    equal_data_value = same_value;
                    must_rekey = !same_value;
                }
                if (must_rekey) {
                    const new_id = try getOrCreateRekeyId(plan, owner, ts8, old_id);
                    const rekeyed = try rekeyStanzaKeyWithId(plan.allocator, key, new_id) orelse
                        return error.InvalidRecoveryPlan;
                    if (db != .archive and rekeyed.len > 511) {
                        plan.allocator.free(rekeyed);
                        try addIssue(plan, db, namespace, .key_too_long, rename.old_key, "");
                        plan.allocator.free(rename.old_key);
                        plan.allocator.free(rename.new_key);
                        if (rename.new_value) |value| plan.allocator.free(value);
                        transferred += 1;
                        continue;
                    }
                    plan.allocator.free(rename.new_key);
                    rename.new_key = rekeyed;
                    rename.same_key = false;
                    try addIssue(plan, db, namespace, .rekeyed, rename.old_key, rename.new_key);
                }
            }

            const id = try targetId(plan.allocator, db, namespace, rename.new_key);
            var id_owned = true;
            defer if (id_owned) plan.allocator.free(id);
            var occupied = targets.contains(id);
            if (!occupied) {
                const existing = try backend.get(plan.allocator, namespace, rename.new_key);
                if (existing) |value| {
                    plan.allocator.free(value);
                    // The occupant is itself renamed away by this plan, so the
                    // key will be free by the time this row is written.
                    occupied = !old_keys.contains(rename.new_key);
                }
            }
            if (occupied) {
                if (rename.reference_duplicate or equal_data_value or
                    (rename.data_duplicate and
                        (!std.mem.eql(u8, namespace, NS_OFFLINE) and !std.mem.eql(u8, namespace, NS_MESSAGES))))
                {
                    // The prepared-key row wins; the duplicate old row is
                    // deleted so it cannot survive the migration.
                    try addIssue(plan, db, namespace, .deduplicated, rename.old_key, rename.new_key);
                    var dropped = rename;
                    dropped.delete_only = true;
                    if (dropped.new_value) |value| plan.allocator.free(value);
                    dropped.new_value = null;
                    try plan.renames.append(plan.allocator, dropped);
                    transferred += 1;
                    plan.rename_bytes += dropped.new_key.len + dropped.value_len;
                    continue;
                }
                if (occupied) {
                    try addIssue(plan, db, namespace, .collision, rename.old_key, rename.new_key);
                }
            }
            if (!targets.contains(id)) {
                try targets.put(plan.allocator, id, {});
                id_owned = false;
            }
        }
        try plan.renames.append(plan.allocator, rename);
        transferred += 1;
        plan.rename_bytes += rename.new_key.len + rename.value_len;
    }
}

fn planDb(
    plan: *Plan,
    targets: *std.StringHashMapUnmanaged(void),
    db: Database,
    backend: anytype,
    namespaces: []const []const u8,
    ctx: *const RewriteContext,
) !void {
    for (namespaces) |namespace| {
        try planNamespace(plan, targets, db, backend, namespace, ctx);
    }
}

fn pendingLessThan(_: void, a: Rename, b: Rename) bool {
    if (a.has_users != b.has_users) return a.has_users;
    return std.mem.lessThan(u8, a.old_key, b.old_key);
}

fn renameLessThan(_: void, a: Rename, b: Rename) bool {
    const a_db = @intFromEnum(a.db);
    const b_db = @intFromEnum(b.db);
    if (a_db != b_db) return a_db < b_db;
    if (!std.mem.eql(u8, a.namespace, b.namespace)) {
        return std.mem.lessThan(u8, a.namespace, b.namespace);
    }
    return std.mem.lessThan(u8, a.old_key, b.old_key);
}

fn issueLessThan(_: void, a: Issue, b: Issue) bool {
    const a_db = @intFromEnum(a.db);
    const b_db = @intFromEnum(b.db);
    if (a_db != b_db) return a_db < b_db;
    if (!std.mem.eql(u8, a.namespace, b.namespace)) {
        return std.mem.lessThan(u8, a.namespace, b.namespace);
    }
    return std.mem.lessThan(u8, a.key, b.key);
}

/// Compute every planned rename and every collision or invalid localpart.
/// `forced`, when present, maps one exact stored localpart to an explicitly
/// chosen prepared replacement for collision resolution.
pub fn planMigration(
    allocator: std.mem.Allocator,
    auth: anytype,
    op: anytype,
    archive: anytype,
    hosted_domains: []const []const u8,
    forced: ?ForcedRename,
) !Plan {
    var plan = Plan.init(allocator);
    errdefer plan.deinit();

    if (forced) |rename| {
        const prepared = migrate_precis_scratch.localpart(rename.new_localpart) catch
            return error.InvalidAccountName;
        if (!std.mem.eql(u8, prepared, rename.new_localpart)) return error.InvalidAccountName;
    }

    var targets: std.StringHashMapUnmanaged(void) = .{};
    defer {
        var keys = targets.keyIterator();
        while (keys.next()) |key| allocator.free(key.*);
        targets.deinit(allocator);
    }

    var identities = IdentityTracker{ .plan = &plan, .db = .auth, .namespace = "" };
    defer identities.deinit(allocator);
    const empty_users: std.StringHashMapUnmanaged(void) = .{};
    const auth_ctx = RewriteContext{
        .hosted_domains = hosted_domains,
        .forced = forced,
        .identities = &identities,
        .users_sources = &empty_users,
    };
    try planDb(&plan, &targets, .auth, auth, &.{ NS_USERS, NS_LOCKS }, &auth_ctx);

    // Reference writers into one freed prepared key prefer the spelling that
    // is a real users row (bobref3: Bob over stale BOB).
    var users_sources: std.StringHashMapUnmanaged(void) = .{};
    defer {
        var keys = users_sources.keyIterator();
        while (keys.next()) |key| allocator.free(key.*);
        users_sources.deinit(allocator);
    }
    {
        var iterator = try auth.iterator(NS_USERS, "");
        defer iterator.deinit();
        while (iterator.next()) |entry| {
            const key = try allocator.dupe(u8, entry.key);
            errdefer allocator.free(key);
            try users_sources.put(allocator, key, {});
        }
    }
    const ctx = RewriteContext{
        .hosted_domains = hosted_domains,
        .forced = forced,
        .identities = &identities,
        .users_sources = &users_sources,
    };

    // Archive messages first: their rekey assignments are consumed by the
    // offline pointers and by_contact values planned below.
    try planDb(&plan, &targets, .archive, archive, &.{ NS_MESSAGES, NS_BY_CONTACT }, &ctx);
    try planDb(&plan, &targets, .op, op, &.{
        NS_ROSTERS,
        NS_BLOCKLIST,
        NS_VCARDS,
        NS_PEP,
        NS_LASTACT,
        NS_OFFLINE,
        NS_OFFLINE_V2,
        NS_OFFLINE_SEQ,
        NS_OFFLINE_HOLD_V2,
        NS_OFFLINE_HOLD_TOKEN,
        NS_ROOM_AFFILIATIONS,
        NS_PENDING_SUB,
    }, &ctx);

    std.sort.heap(Rename, plan.renames.items, {}, renameLessThan);
    std.sort.heap(Issue, plan.issues.items, {}, issueLessThan);
    return plan;
}

fn applyRename(batch: anytype, rename: Rename, stored: ?[]const u8) !void {
    if (rename.delete_only) {
        try batch.delete(rename.namespace, rename.old_key);
        return;
    }
    const value = rename.new_value orelse stored orelse return error.MissingSourceRow;
    try batch.put(rename.namespace, rename.new_key, value);
    if (!rename.same_key) try batch.delete(rename.namespace, rename.old_key);
}

fn sameNamespace(a: Rename, b: Rename) bool {
    return a.db == b.db and std.mem.eql(u8, a.namespace, b.namespace);
}

/// Order one namespace so a rename whose target is another row's old key runs
/// after that occupant moves away. Each key has at most one dependent because
/// duplicate targets are collisions or reference dedupes.
fn appendOrderedNamespace(
    allocator: std.mem.Allocator,
    items: []const Rename,
    base: usize,
    ordered: *std.ArrayListUnmanaged(usize),
) !void {
    const n = items.len;
    if (n == 0) return;
    var old_index: std.StringHashMapUnmanaged(usize) = .{};
    defer old_index.deinit(allocator);
    try old_index.ensureTotalCapacity(allocator, @intCast(n));
    for (items, 0..) |rename, i| try old_index.put(allocator, rename.old_key, i);

    const indegree = try allocator.alloc(u8, n);
    defer allocator.free(indegree);
    @memset(indegree, 0);
    const dependent = try allocator.alloc(?usize, n);
    defer allocator.free(dependent);
    @memset(dependent, null);
    for (items, 0..) |rename, i| {
        if (rename.delete_only) continue;
        if (old_index.get(rename.new_key)) |j| {
            if (j != i) {
                if (dependent[j] != null) return error.DuplicateRenameTarget;
                indegree[i] = 1;
                dependent[j] = i;
            }
        }
    }

    var queue: std.ArrayListUnmanaged(usize) = .{};
    defer queue.deinit(allocator);
    for (indegree, 0..) |degree, i| {
        if (degree == 0) try queue.append(allocator, i);
    }
    const before = ordered.items.len;
    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const index = queue.items[head];
        try ordered.append(allocator, base + index);
        if (dependent[index]) |next| {
            indegree[next] = 0;
            try queue.append(allocator, next);
        }
    }
    if (ordered.items.len - before != n) return error.RenameCycle;
}

fn orderForDb(allocator: std.mem.Allocator, plan: *const Plan, db: Database) ![]usize {
    var ordered: std.ArrayListUnmanaged(usize) = .{};
    errdefer ordered.deinit(allocator);
    var start: usize = 0;
    while (start < plan.renames.items.len) {
        if (plan.renames.items[start].db != db) {
            start += 1;
            continue;
        }
        var end = start + 1;
        while (end < plan.renames.items.len and sameNamespace(plan.renames.items[start], plan.renames.items[end])) : (end += 1) {}
        try appendOrderedNamespace(allocator, plan.renames.items[start..end], start, &ordered);
        start = end;
    }
    return ordered.toOwnedSlice(allocator);
}

fn stateMatches(backend: anytype, allocator: std.mem.Allocator, key: []const u8, digest: []const u8) !bool {
    const value = try backend.get(allocator, NS_MIGRATION_STATE, key);
    defer if (value) |bytes| allocator.free(bytes);
    return value != null and std.mem.eql(u8, value.?, digest);
}

fn clearState(backend: anytype, allocator: std.mem.Allocator) !void {
    var keys: std.ArrayListUnmanaged([]u8) = .{};
    defer {
        for (keys.items) |key| allocator.free(key);
        keys.deinit(allocator);
    }
    {
        var iter = try backend.iterator(NS_MIGRATION_STATE, "");
        defer iter.deinit();
        while (iter.next()) |entry| {
            try keys.append(allocator, try allocator.dupe(u8, entry.key));
        }
    }
    if (keys.items.len == 0) return;
    var batch = try backend.writeBatch();
    errdefer batch.abort();
    for (keys.items) |key| try batch.delete(NS_MIGRATION_STATE, key);
    try batch.commit();
}

fn applySingleDb(
    backend: anytype,
    allocator: std.mem.Allocator,
    plan: *const Plan,
    db: Database,
    order: []const usize,
    replay: bool,
    digest: ?[]const u8,
) !void {
    var any = false;
    for (plan.renames.items) |rename| {
        if (rename.db == db) {
            any = true;
            break;
        }
    }
    if (!any) return;
    if (replay and digest != null and try stateMatches(backend, allocator, "done", digest.?)) return;

    // Fetch source values before opening the write transaction, and retain
    // them through commit so the batch never references freed memory.
    var values: std.ArrayListUnmanaged(?[]u8) = .{};
    defer {
        for (values.items) |value| {
            if (value) |bytes| allocator.free(bytes);
        }
        values.deinit(allocator);
    }
    try values.resize(allocator, plan.renames.items.len);
    @memset(values.items, null);
    const skip = try allocator.alloc(bool, plan.renames.items.len);
    defer allocator.free(skip);
    @memset(skip, false);
    for (plan.renames.items, 0..) |rename, i| {
        if (rename.db != db or rename.new_value != null) continue;
        values.items[i] = try backend.get(allocator, rename.namespace, rename.old_key);
        if (values.items[i] == null) {
            if (replay and rename.delete_only) {
                skip[i] = true;
                continue;
            }
            if (replay) {
                const new_value = try backend.get(allocator, rename.namespace, rename.new_key);
                if (new_value) |value| {
                    allocator.free(value);
                    skip[i] = true;
                    continue;
                }
            }
            return error.MissingSourceRow;
        }
    }

    var batch = try backend.writeBatch();
    errdefer batch.abort();
    for (order) |i| {
        if (skip[i]) continue;
        const rename = plan.renames.items[i];
        try applyRename(&batch, rename, values.items[i]);
    }
    if (digest) |run_digest| try batch.put(NS_MIGRATION_STATE, "done", run_digest);
    try batch.commit();
}

fn preflightDb(backend: anytype, allocator: std.mem.Allocator, plan: *const Plan, db: Database) !void {
    for (plan.renames.items) |rename| {
        if (rename.db != db or rename.new_value != null) continue;
        const value = try backend.get(allocator, rename.namespace, rename.old_key);
        if (value == null) return error.MissingSourceRow;
        allocator.free(value.?);
    }
}

fn keyPrefix(key: []const u8) []const u8 {
    const sep = std.mem.indexOfScalar(u8, key, 0) orelse return key;
    return key[0..sep];
}

fn sameGroup(a: Rename, b: Rename) bool {
    return a.db == b.db and
        std.mem.eql(u8, a.namespace, b.namespace) and
        std.mem.eql(u8, keyPrefix(a.old_key), keyPrefix(b.old_key));
}

pub fn hexKey(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    return hexEncodeAlloc(allocator, bytes);
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const digits = "0123456789abcdef";
    const result = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        result[i * 2] = digits[byte >> 4];
        result[i * 2 + 1] = digits[byte & 0x0f];
    }
    return result;
}

fn writePlanLine(file: std.fs.File, allocator: std.mem.Allocator, prefix: []const u8, rename: Rename) !void {
    const old_hex = try hexEncodeAlloc(allocator, rename.old_key);
    defer allocator.free(old_hex);
    const new_hex = try hexEncodeAlloc(allocator, rename.new_key);
    defer allocator.free(new_hex);
    const line = try std.fmt.allocPrint(
        allocator,
        "{s}{s} {s} {s} {s}\n",
        .{ prefix, @tagName(rename.db), rename.namespace, old_hex, new_hex },
    );
    defer allocator.free(line);
    try file.writeAll(line);
}

fn artifactPath(allocator: std.mem.Allocator, dir: []const u8, basename: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ dir, basename });
}

fn writePlanFile(allocator: std.mem.Allocator, dir: []const u8, plan: *const Plan) !void {
    const path = try artifactPath(allocator, dir, "migrate-precis.plan");
    defer allocator.free(path);
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    for (plan.renames.items) |rename| try writePlanLine(file, allocator, "plan ", rename);
}

fn appendJournal(allocator: std.mem.Allocator, dir: []const u8, rename: Rename) !void {
    const path = try artifactPath(allocator, dir, "migrate-precis.journal");
    defer allocator.free(path);
    var file = try std.fs.cwd().createFile(path, .{ .truncate = false });
    defer file.close();
    try file.seekFromEnd(0);
    try writePlanLine(file, allocator, "applied ", rename);
}

fn applyGroupedDb(
    backend: anytype,
    allocator: std.mem.Allocator,
    plan: *const Plan,
    db: Database,
    order: []const usize,
    journal_dir: ?[]const u8,
    replay: bool,
    digest: ?[]const u8,
) !void {
    if (replay and digest != null and try stateMatches(backend, allocator, "done", digest.?)) return;
    var position: usize = 0;
    var batch_index: usize = 0;
    while (position < order.len) {
        const first = plan.renames.items[order[position]];
        var end = position + 1;
        while (end < order.len and sameGroup(first, plan.renames.items[order[end]])) : (end += 1) {}

        var marker_buf: [64]u8 = undefined;
        const marker = std.fmt.bufPrint(&marker_buf, "done.{s}.{d}", .{ @tagName(db), batch_index }) catch
            return error.NameTooLong;
        if (replay and digest != null and try stateMatches(backend, allocator, marker, digest.?)) {
            position = end;
            batch_index += 1;
            continue;
        }

        var values: std.ArrayListUnmanaged(?[]u8) = .{};
        defer {
            for (values.items) |value| {
                if (value) |bytes| allocator.free(bytes);
            }
            values.deinit(allocator);
        }
        try values.resize(allocator, end - position);
        @memset(values.items, null);
        const skip = try allocator.alloc(bool, end - position);
        defer allocator.free(skip);
        @memset(skip, false);
        for (order[position..end], 0..) |rename_index, i| {
            const rename = plan.renames.items[rename_index];
            if (rename.new_value != null) continue;
            values.items[i] = try backend.get(allocator, rename.namespace, rename.old_key);
            if (values.items[i] == null) {
                if (replay and rename.delete_only) {
                    skip[i] = true;
                    continue;
                }
                if (replay) {
                    const new_value = try backend.get(allocator, rename.namespace, rename.new_key);
                    if (new_value) |value| {
                        allocator.free(value);
                        skip[i] = true;
                        continue;
                    }
                }
                return error.MissingSourceRow;
            }
        }

        var batch = try backend.writeBatch();
        errdefer batch.abort();
        for (order[position..end], 0..) |rename_index, i| {
            if (skip[i]) continue;
            try applyRename(&batch, plan.renames.items[rename_index], values.items[i]);
        }
        if (digest) |run_digest| try batch.put(NS_MIGRATION_STATE, marker, run_digest);
        try batch.commit();

        if (journal_dir) |dir| {
            for (order[position..end]) |rename_index| try appendJournal(allocator, dir, plan.renames.items[rename_index]);
        }
        position = end;
        batch_index += 1;
    }
}

/// Apply a validated plan in dependency order. A replay skips batches whose
/// done marker matches the stored run digest.
fn applyValidated(
    allocator: std.mem.Allocator,
    auth: anytype,
    op: anytype,
    archive: anytype,
    plan: *const Plan,
    options: ApplyOptions,
    replay: bool,
    digest: ?[]const u8,
) !void {
    const auth_order = try orderForDb(allocator, plan, .auth);
    defer allocator.free(auth_order);
    const op_order = try orderForDb(allocator, plan, .op);
    defer allocator.free(op_order);
    const archive_order = try orderForDb(allocator, plan, .archive);
    defer allocator.free(archive_order);
    if (!replay) {
        // Validate every DB before the first mutation: dependency cycles,
        // missing source rows and key/order problems must never surface after
        // another env has committed.
        try preflightDb(auth, allocator, plan, .auth);
        try preflightDb(op, allocator, plan, .op);
        try preflightDb(archive, allocator, plan, .archive);
    }

    if (plan.rename_bytes <= options.single_txn_budget) {
        try applySingleDb(op, allocator, plan, .op, op_order, replay, digest);
        try applySingleDb(auth, allocator, plan, .auth, auth_order, replay, digest);
    } else {
        try applyGroupedDb(op, allocator, plan, .op, op_order, options.journal_dir, replay, digest);
        try applyGroupedDb(auth, allocator, plan, .auth, auth_order, options.journal_dir, replay, digest);
    }
    try applyGroupedDb(archive, allocator, plan, .archive, archive_order, options.journal_dir, replay, digest);
}

fn validatePlan(
    allocator: std.mem.Allocator,
    auth: anytype,
    op: anytype,
    archive: anytype,
    plan: *const Plan,
) !void {
    const auth_order = try orderForDb(allocator, plan, .auth);
    defer allocator.free(auth_order);
    const op_order = try orderForDb(allocator, plan, .op);
    defer allocator.free(op_order);
    const archive_order = try orderForDb(allocator, plan, .archive);
    defer allocator.free(archive_order);
    try preflightDb(auth, allocator, plan, .auth);
    try preflightDb(op, allocator, plan, .op);
    try preflightDb(archive, allocator, plan, .archive);
}

/// Apply a collision-free plan. LMDB uses one write transaction per DB when
/// `rename_bytes` fits the budget; larger plans and every archive pass use one
/// WriteBatch per key prefix. With `journal_dir`, the plan and a pending
/// marker are durable before the first commit and completion markers are
/// written in the same commits as the data they describe.
pub fn applyPlan(
    allocator: std.mem.Allocator,
    auth: anytype,
    op: anytype,
    archive: anytype,
    plan: *const Plan,
    options: ApplyOptions,
) !void {
    if (plan.hasBlockingIssues()) return error.MigrationBlocked;
    if (plan.renames.items.len == 0) return;

    var archive_work = false;
    for (plan.renames.items) |rename| {
        if (rename.db == .archive) archive_work = true;
    }
    const journaled = archive_work or plan.rename_bytes > options.single_txn_budget;
    if (journaled and options.journal_dir == null) return error.JournalRequired;

    // Everything that can fail without I/O runs before the pending marker is
    // written: a validation failure must never leave an install locked.
    try validatePlan(allocator, auth, op, archive, plan);

    var digest: ?[]u8 = null;
    defer if (digest) |value| allocator.free(value);
    if (options.journal_dir) |dir| {
        // The fixed plan and its digest are durable before the first commit.
        // A failure at any later boundary leaves the marker for replay.
        try clearState(auth, allocator);
        try clearState(op, allocator);
        try clearState(archive, allocator);
        try writePlanFile(allocator, dir, plan);
        digest = try writeRecoveryPlan(allocator, dir, plan);
    }
    try applyValidated(allocator, auth, op, archive, plan, options, false, digest);
    if (options.journal_dir) |dir| clearRecovery(allocator, dir);
}

/// Finish a stored plan after an interrupted apply. Replays are idempotent:
/// a rename whose old key is gone and whose new key exists is skipped.
pub fn resumeMigration(
    allocator: std.mem.Allocator,
    auth: anytype,
    op: anytype,
    archive: anytype,
    journal_dir: []const u8,
) !usize {
    var plan = try readRecoveryPlan(allocator, journal_dir);
    defer plan.deinit();
    // Replay in prefix batches so per-batch completion markers are honored.
    const options = ApplyOptions{ .journal_dir = journal_dir, .single_txn_budget = 0 };
    try applyValidated(allocator, auth, op, archive, &plan, options, true, plan.recovery_digest);
    clearRecovery(allocator, journal_dir);
    return plan.renames.items.len;
}

const Deletion = struct {
    db: Database,
    namespace: []const u8,
    key: []u8,
};

pub const RawDeleteKind = enum { account, data_only };

fn jidMatchesRaw(jid: []const u8, raw: []const u8, hosted_domains: []const []const u8) bool {
    const at = std.mem.indexOfScalar(u8, jid, '@') orelse return false;
    const remainder = jid[at + 1 ..];
    const slash = std.mem.indexOfScalar(u8, remainder, '/');
    const domain = if (slash) |pos| remainder[0..pos] else remainder;
    return isHosted(domain, hosted_domains) and std.mem.eql(u8, jid[0..at], raw);
}

fn firstJidMatchesRaw(key: []const u8, raw: []const u8, hosted_domains: []const []const u8) bool {
    const sep = std.mem.indexOfScalar(u8, key, 0) orelse return jidMatchesRaw(key, raw, hosted_domains);
    return jidMatchesRaw(key[0..sep], raw, hosted_domains);
}

fn offlineV2ValueMatchesRaw(value: []const u8, raw: []const u8, hosted_domains: []const []const u8) bool {
    if (value.len < 12) return false;
    const id_len = std.mem.readInt(u32, value[8..12], .big);
    const from_offset = 12 + @as(usize, id_len);
    if (from_offset > value.len) return false;
    return jidMatchesRaw(value[from_offset..], raw, hosted_domains);
}

fn entryOwnsRaw(
    namespace: []const u8,
    key: []const u8,
    raw: []const u8,
    hosted_domains: []const []const u8,
) bool {
    if (std.mem.eql(u8, namespace, NS_USERS)) return std.mem.eql(u8, key, raw);
    if (std.mem.eql(u8, namespace, NS_ROSTERS) or
        std.mem.eql(u8, namespace, NS_BLOCKLIST) or
        std.mem.eql(u8, namespace, NS_PENDING_SUB))
    {
        const sep = std.mem.indexOfScalar(u8, key, 0) orelse return false;
        return jidMatchesRaw(key[0..sep], raw, hosted_domains);
    }
    if (std.mem.eql(u8, namespace, NS_BY_CONTACT)) {
        const sep = std.mem.indexOfScalar(u8, key, 0) orelse return false;
        return jidMatchesRaw(key[0..sep], raw, hosted_domains);
    }
    if (std.mem.eql(u8, namespace, NS_VCARDS) or
        std.mem.eql(u8, namespace, NS_LASTACT) or
        std.mem.eql(u8, namespace, NS_PEP) or
        std.mem.eql(u8, namespace, NS_OFFLINE) or
        std.mem.eql(u8, namespace, NS_OFFLINE_V2) or
        std.mem.eql(u8, namespace, NS_OFFLINE_SEQ) or
        std.mem.eql(u8, namespace, NS_OFFLINE_HOLD_V2) or
        std.mem.eql(u8, namespace, NS_OFFLINE_HOLD_TOKEN) or
        std.mem.eql(u8, namespace, NS_MESSAGES))
    {
        return firstJidMatchesRaw(key, raw, hosted_domains);
    }
    return false;
}

fn hasOwnedRawData(
    db: Database,
    backend: anytype,
    namespaces: []const []const u8,
    raw: []const u8,
    hosted_domains: []const []const u8,
) !bool {
    _ = db;
    for (namespaces) |namespace| {
        var iterator = try backend.iterator(namespace, "");
        defer iterator.deinit();
        while (iterator.next()) |entry| {
            if (entryOwnsRaw(namespace, entry.key, raw, hosted_domains)) return true;
        }
    }
    return false;
}

fn entryMatchesRaw(
    db: Database,
    namespace: []const u8,
    key: []const u8,
    value: []const u8,
    raw: []const u8,
    hosted_domains: []const []const u8,
    delete_locks: bool,
) bool {
    _ = db;
    if (std.mem.eql(u8, namespace, NS_USERS)) return std.mem.eql(u8, key, raw);
    if (!delete_locks) {
        // No users row: delete only rows this exact raw spelling owns.
        // References (another roster's contact, a room member, an archive
        // index or offline sender) belong to the account the spelling folds
        // into, not to this data-only spelling.
        return entryOwnsRaw(namespace, key, raw, hosted_domains);
    }
    if (std.mem.eql(u8, namespace, NS_LOCKS)) {
        // A real users-row deletion may remove its exact raw lock.
        return std.mem.eql(u8, key, raw);
    }
    if (std.mem.eql(u8, namespace, NS_ROSTERS) or
        std.mem.eql(u8, namespace, NS_BLOCKLIST) or
        std.mem.eql(u8, namespace, NS_PENDING_SUB))
    {
        const sep = std.mem.indexOfScalar(u8, key, 0) orelse return false;
        return jidMatchesRaw(key[0..sep], raw, hosted_domains) or
            jidMatchesRaw(key[sep + 1 ..], raw, hosted_domains);
    }
    if (std.mem.eql(u8, namespace, NS_BY_CONTACT)) {
        const first_sep = std.mem.indexOfScalar(u8, key, 0) orelse return false;
        if (jidMatchesRaw(key[0..first_sep], raw, hosted_domains)) return true;
        const remainder = key[first_sep + 1 ..];
        const second_sep = std.mem.indexOfScalar(u8, remainder, 0) orelse remainder.len;
        return jidMatchesRaw(remainder[0..second_sep], raw, hosted_domains);
    }
    if (std.mem.eql(u8, namespace, NS_ROOM_AFFILIATIONS)) {
        const sep = std.mem.indexOfScalar(u8, key, 0) orelse return false;
        return jidMatchesRaw(key[sep + 1 ..], raw, hosted_domains);
    }
    if (std.mem.eql(u8, namespace, NS_VCARDS) or
        std.mem.eql(u8, namespace, NS_LASTACT) or
        std.mem.eql(u8, namespace, NS_PEP) or
        std.mem.eql(u8, namespace, NS_OFFLINE) or
        std.mem.eql(u8, namespace, NS_OFFLINE_V2) or
        std.mem.eql(u8, namespace, NS_OFFLINE_SEQ) or
        std.mem.eql(u8, namespace, NS_OFFLINE_HOLD_V2) or
        std.mem.eql(u8, namespace, NS_OFFLINE_HOLD_TOKEN) or
        std.mem.eql(u8, namespace, NS_MESSAGES))
    {
        if (firstJidMatchesRaw(key, raw, hosted_domains)) return true;
        if (std.mem.eql(u8, namespace, NS_OFFLINE)) return jidMatchesRaw(value, raw, hosted_domains);
        if (std.mem.eql(u8, namespace, NS_OFFLINE_V2)) return offlineV2ValueMatchesRaw(value, raw, hosted_domains);
        return false;
    }
    return false;
}

fn collectRawDeletions(
    deletions: *std.ArrayListUnmanaged(Deletion),
    allocator: std.mem.Allocator,
    db: Database,
    backend: anytype,
    namespaces: []const []const u8,
    raw: []const u8,
    hosted_domains: []const []const u8,
    delete_locks: bool,
) !void {
    for (namespaces) |namespace| {
        var iterator = try backend.iterator(namespace, "");
        defer iterator.deinit();
        while (iterator.next()) |entry| {
            if (!entryMatchesRaw(db, namespace, entry.key, entry.value, raw, hosted_domains, delete_locks)) continue;
            const key = try allocator.dupe(u8, entry.key);
            errdefer allocator.free(key);
            try deletions.append(allocator, .{ .db = db, .namespace = namespace, .key = key });
        }
    }
}

fn deleteRawDb(backend: anytype, deletions: []const Deletion, db: Database) !void {
    var any = false;
    for (deletions) |deletion| {
        if (deletion.db == db) {
            any = true;
            break;
        }
    }
    if (!any) return;
    var batch = try backend.writeBatch();
    errdefer batch.abort();
    for (deletions) |deletion| {
        if (deletion.db != db) continue;
        try batch.delete(deletion.namespace, deletion.key);
    }
    try batch.commit();
}

fn freeDeletions(deletions: *std.ArrayListUnmanaged(Deletion), allocator: std.mem.Allocator) void {
    for (deletions.items) |deletion| allocator.free(deletion.key);
    deletions.deinit(allocator);
}

/// Delete every row belonging to one exact source localpart, in every
/// namespace, or fail without applying a partial migration. Only exact source
/// spellings match, so the prepared account that survives a collision keeps its
/// own rows. Folded lock rows and JID index fields are included; stanza payload
/// bytes are not inspected.
pub fn deleteRawAccount(
    allocator: std.mem.Allocator,
    auth: anytype,
    op: anytype,
    archive: anytype,
    hosted_domains: []const []const u8,
    raw: []const u8,
) !RawDeleteKind {
    const existing = try auth.get(allocator, NS_USERS, raw);
    const raw_has_users = existing != null;
    if (existing) |value| {
        allocator.free(value);
    } else {
        // A spelling with no users row can still own data written by third
        // parties addressing it (offline, archive, pending subscription).
        // --raw must be able to delete that data; it never touches another
        // account's users row or prepared lock.
        var owned = try hasOwnedRawData(.auth, auth, &.{NS_USERS}, raw, hosted_domains);
        if (!owned) owned = try hasOwnedRawData(.op, op, &.{
            NS_ROSTERS,
            NS_BLOCKLIST,
            NS_VCARDS,
            NS_PEP,
            NS_LASTACT,
            NS_OFFLINE,
            NS_OFFLINE_V2,
            NS_OFFLINE_SEQ,
            NS_OFFLINE_HOLD_V2,
            NS_OFFLINE_HOLD_TOKEN,
            NS_ROOM_AFFILIATIONS,
            NS_PENDING_SUB,
        }, raw, hosted_domains);
        if (!owned) owned = try hasOwnedRawData(.archive, archive, &.{ NS_MESSAGES, NS_BY_CONTACT }, raw, hosted_domains);
        if (!owned) return error.UserNotFound;
    }

    var deletions: std.ArrayListUnmanaged(Deletion) = .{};
    defer freeDeletions(&deletions, allocator);
    try collectRawDeletions(&deletions, allocator, .auth, auth, &.{ NS_USERS, NS_LOCKS }, raw, hosted_domains, raw_has_users);
    try collectRawDeletions(&deletions, allocator, .op, op, &.{
        NS_ROSTERS,
        NS_BLOCKLIST,
        NS_VCARDS,
        NS_PEP,
        NS_LASTACT,
        NS_OFFLINE,
        NS_OFFLINE_V2,
        NS_OFFLINE_SEQ,
        NS_OFFLINE_HOLD_V2,
        NS_OFFLINE_HOLD_TOKEN,
        NS_ROOM_AFFILIATIONS,
        NS_PENDING_SUB,
    }, raw, hosted_domains, raw_has_users);
    try collectRawDeletions(&deletions, allocator, .archive, archive, &.{ NS_MESSAGES, NS_BY_CONTACT }, raw, hosted_domains, raw_has_users);

    try deleteRawDb(auth, deletions.items, .auth);
    try deleteRawDb(op, deletions.items, .op);
    try deleteRawDb(archive, deletions.items, .archive);

    var remaining: std.ArrayListUnmanaged(Deletion) = .{};
    defer freeDeletions(&remaining, allocator);
    try collectRawDeletions(&remaining, allocator, .auth, auth, &.{ NS_USERS, NS_LOCKS }, raw, hosted_domains, raw_has_users);
    try collectRawDeletions(&remaining, allocator, .op, op, &.{
        NS_ROSTERS,
        NS_BLOCKLIST,
        NS_VCARDS,
        NS_PEP,
        NS_LASTACT,
        NS_OFFLINE,
        NS_OFFLINE_V2,
        NS_OFFLINE_SEQ,
        NS_OFFLINE_HOLD_V2,
        NS_OFFLINE_HOLD_TOKEN,
        NS_ROOM_AFFILIATIONS,
        NS_PENDING_SUB,
    }, raw, hosted_domains, raw_has_users);
    try collectRawDeletions(&remaining, allocator, .archive, archive, &.{ NS_MESSAGES, NS_BY_CONTACT }, raw, hosted_domains, raw_has_users);
    if (remaining.items.len != 0) return error.DataRemaining;
    return if (raw_has_users) .account else .data_only;
}

/// Refuse to operate while any daemon named by the master's pid files is live.
pub fn assertOffline(run_dir: []const u8) !void {
    const names = [_][]const u8{ "xmppd.pid", "auth.pid", "core.pid", "s2s.pid" };
    for (names) |name| {
        var path_buf: [1024]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ run_dir, name });
        if (try pidFileLive(path)) return error.DaemonsRunning;
    }
}

fn pidFileLive(path: []const u8) !bool {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close();
    var buf: [128]u8 = undefined;
    const count = try file.readAll(&buf);
    const text = std.mem.trim(u8, buf[0..count], " \t\r\n");
    const end = std.mem.indexOfAny(u8, text, " \t") orelse text.len;
    const pid = std.fmt.parseInt(std.posix.pid_t, text[0..end], 10) catch return true;
    std.posix.kill(pid, 0) catch |err| switch (err) {
        error.ProcessNotFound => return false,
        else => return true,
    };
    return true;
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

const MemoryBackend = backend_mod.MemoryBackend;

fn expectRow(backend: anytype, namespace: []const u8, key: []const u8, value: []const u8) !void {
    const stored = try backend.get(std.testing.allocator, namespace, key);
    defer if (stored) |bytes| std.testing.allocator.free(bytes);
    try std.testing.expect(stored != null);
    try std.testing.expectEqualStrings(value, stored.?);
}

fn expectMissing(backend: anytype, namespace: []const u8, key: []const u8) !void {
    const stored = try backend.get(std.testing.allocator, namespace, key);
    defer if (stored) |bytes| std.testing.allocator.free(bytes);
    try std.testing.expect(stored == null);
}

const SnapshotRow = struct {
    db: Database,
    namespace: []const u8,
    key: []u8,
    value: []u8,
};

const Snapshot = struct {
    allocator: std.mem.Allocator,
    rows: std.ArrayListUnmanaged(SnapshotRow) = .{},

    fn deinit(self: *Snapshot) void {
        for (self.rows.items) |row| {
            self.allocator.free(row.key);
            self.allocator.free(row.value);
        }
        self.rows.deinit(self.allocator);
    }
};

fn snapshotLessThan(_: void, a: SnapshotRow, b: SnapshotRow) bool {
    if (@intFromEnum(a.db) != @intFromEnum(b.db)) return @intFromEnum(a.db) < @intFromEnum(b.db);
    if (!std.mem.eql(u8, a.namespace, b.namespace)) {
        return std.mem.lessThan(u8, a.namespace, b.namespace);
    }
    return std.mem.lessThan(u8, a.key, b.key);
}

fn snapshotDb(snapshot: *Snapshot, db: Database, backend: anytype) !void {
    for (backend_mod.canonical_namespaces) |namespace| {
        var iterator = try backend.iterator(namespace, "");
        defer iterator.deinit();
        while (iterator.next()) |entry| {
            const key = try snapshot.allocator.dupe(u8, entry.key);
            errdefer snapshot.allocator.free(key);
            const value = try snapshot.allocator.dupe(u8, entry.value);
            errdefer snapshot.allocator.free(value);
            try snapshot.rows.append(snapshot.allocator, .{
                .db = db,
                .namespace = namespace,
                .key = key,
                .value = value,
            });
        }
    }
}

fn takeSnapshot(allocator: std.mem.Allocator, auth: anytype, op: anytype, archive: anytype) !Snapshot {
    var snapshot = Snapshot{ .allocator = allocator };
    errdefer snapshot.deinit();
    try snapshotDb(&snapshot, .auth, auth);
    try snapshotDb(&snapshot, .op, op);
    try snapshotDb(&snapshot, .archive, archive);
    std.sort.heap(SnapshotRow, snapshot.rows.items, {}, snapshotLessThan);
    return snapshot;
}

fn expectSnapshotEqual(before: *const Snapshot, after: *const Snapshot) !void {
    try std.testing.expectEqual(before.rows.items.len, after.rows.items.len);
    for (before.rows.items, after.rows.items) |a, b| {
        try std.testing.expectEqual(a.db, b.db);
        try std.testing.expectEqualStrings(a.namespace, b.namespace);
        try std.testing.expectEqualStrings(a.key, b.key);
        try std.testing.expectEqualStrings(a.value, b.value);
    }
}

test "migrate-precis: a collision aborts with every DB byte-identical" {
    const allocator = std.testing.allocator;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();

    try auth.put(NS_USERS, "NaplesTB", "creds-a");
    try auth.put(NS_USERS, "naplestb", "creds-b");
    try op.put(NS_ROSTERS, "NaplesTB@us.example\x00friend@us.example", "roster");
    try archive.put(NS_MESSAGES, "NaplesTB@us.example\x00id", "stanza");

    var before = try takeSnapshot(allocator, &auth, &op, &archive);
    defer before.deinit();
    const domains = [_][]const u8{"us.example"};
    var plan = try planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expect(plan.issues.items.len > 0);
    try std.testing.expectEqual(IssueKind.collision, plan.issues.items[0].kind);
    try std.testing.expectError(error.MigrationBlocked, applyPlan(allocator, &auth, &op, &archive, &plan, .{}));

    var after = try takeSnapshot(allocator, &auth, &op, &archive);
    defer after.deinit();
    try expectSnapshotEqual(&before, &after);
}

test "migrate-precis: two unprepared keys folding to one new key collide" {
    const allocator = std.testing.allocator;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();

    try auth.put(NS_USERS, "NaplesTB", "creds-a");
    try auth.put(NS_USERS, "NAPLESTB", "creds-b");
    const domains = [_][]const u8{"us.example"};
    var plan = try planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expect(plan.issues.items.len > 0);
    try std.testing.expectError(error.MigrationBlocked, applyPlan(allocator, &auth, &op, &archive, &plan, .{}));
    try expectRow(&auth, NS_USERS, "NaplesTB", "creds-a");
    try expectRow(&auth, NS_USERS, "NAPLESTB", "creds-b");
}

test "migrate-precis: an unpreparable account name blocks the apply" {
    const allocator = std.testing.allocator;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();
    try auth.put(NS_USERS, "bad name", "creds");

    const domains = [_][]const u8{"us.example"};
    var plan = try planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.issues.items.len);
    try std.testing.expectEqual(IssueKind.invalid_name, plan.issues.items[0].kind);
    try std.testing.expectError(error.MigrationBlocked, applyPlan(allocator, &auth, &op, &archive, &plan, .{}));
    try expectRow(&auth, NS_USERS, "bad name", "creds");
}

test "migrate-precis: an explicit rename resolves a collision" {
    const allocator = std.testing.allocator;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();
    try auth.put(NS_USERS, "NaplesTB", "creds-a");
    try auth.put(NS_USERS, "naplestb", "creds-b");
    try op.put(NS_ROSTERS, "NaplesTB@us.example\x00friend@us.example", "roster");

    const domains = [_][]const u8{"us.example"};
    const forced = ForcedRename{ .old_localpart = "NaplesTB", .new_localpart = "naples_tb" };
    var plan = try planMigration(allocator, &auth, &op, &archive, &domains, forced);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan.issues.items.len);
    try applyPlan(allocator, &auth, &op, &archive, &plan, .{});
    try expectRow(&auth, NS_USERS, "naples_tb", "creds-a");
    try expectRow(&auth, NS_USERS, "naplestb", "creds-b");
    try expectRow(&op, NS_ROSTERS, "naples_tb@us.example\x00friend@us.example", "roster");
}

test "migrate-precis: live and stale pid files drive the offline guard" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const run_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(run_dir);

    var pid_buf: [64]u8 = undefined;
    const pid_text = try std.fmt.bufPrint(&pid_buf, "{d} 0 test\n", .{std.c.getpid()});
    var live = try tmp.dir.createFile("xmppd.pid", .{});
    try live.writeAll(pid_text);
    live.close();
    try std.testing.expectError(error.DaemonsRunning, assertOffline(run_dir));
    try tmp.dir.deleteFile("xmppd.pid");

    var stale = try tmp.dir.createFile("auth.pid", .{});
    try stale.writeAll("2147483647 0 test\n");
    stale.close();
    try assertOffline(run_dir);
}
