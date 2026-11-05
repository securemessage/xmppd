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
const NS_ROOM_AFFILIATIONS = backend_mod.registered("room_affiliations");
const NS_PENDING_SUB = backend_mod.registered("pending_sub");
const NS_MESSAGES = backend_mod.registered("messages");
const NS_BY_CONTACT = backend_mod.registered("by_contact");

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
    /// Remove old_key without writing new_key (deduplicated reference row).
    delete_only: bool = false,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    renames: std.ArrayListUnmanaged(Rename) = .{},
    issues: std.ArrayListUnmanaged(Issue) = .{},
    rename_bytes: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Plan {
        return .{ .allocator = allocator };
    }

    /// Deduplicated reference drops are reported but do not block apply.
    pub fn hasBlockingIssues(self: *const Plan) bool {
        for (self.issues.items) |issue| {
            if (issue.kind != .deduplicated) return true;
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
        self.* = undefined;
    }
};

pub const ApplyOptions = struct {
    /// Above this many rewritten key+value bytes, LMDB uses per-prefix batches
    /// instead of one write transaction per DB. The archive always uses one
    /// WriteBatch per prefix.
    single_txn_budget: usize = 64 * 1024 * 1024,
    /// Required for a journaled pass. The plan is written before any write and
    /// each committed prefix is appended to the journal; a rerun resumes by
    /// recomputing the remaining work from the idempotent key rewrites.
    journal_dir: ?[]const u8 = null,
};

const Rewrite = struct {
    new_key: ?[]u8 = null,
    new_value: ?[]u8 = null,
    /// The changed component is a pure reference (lock key, roster/blocklist
    /// contact, MUC member, by_contact contact). If another row already
    /// occupies the prepared key, this row is deduplicated rather than a
    /// collision: the prepared-key row wins.
    reference_duplicate: bool = false,

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
        // The contact half is written by third-party subscription traffic;
        // only the subscriber is the account.
        rewrite.new_key = try rewriteTwoParts(allocator, key, ctx, false, false, .data, .reference);
        if (rewrite.new_key) |new_key| rewrite.reference_duplicate = firstPartUnchanged(key, new_key);
    } else if (std.mem.eql(u8, namespace, NS_BY_CONTACT)) {
        rewrite.new_key = try rewriteByContact(allocator, key, ctx);
        if (rewrite.new_key) |new_key| rewrite.reference_duplicate = firstPartUnchanged(key, new_key);
    } else if (std.mem.eql(u8, namespace, NS_ROOM_AFFILIATIONS)) {
        rewrite.new_key = try rewriteRoomAffiliation(allocator, key, ctx);
        rewrite.reference_duplicate = rewrite.new_key != null;
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

    for (pending.items) |rename| {
        if (!rename.same_key) {
            const id = try targetId(plan.allocator, db, namespace, rename.new_key);
            var id_owned = true;
            defer if (id_owned) plan.allocator.free(id);
            var occupied = targets.contains(id);
            var existing_row = false;
            if (!occupied) {
                const existing = try backend.get(plan.allocator, namespace, rename.new_key);
                if (existing) |value| {
                    plan.allocator.free(value);
                    existing_row = true;
                    // The occupant is itself renamed away by this plan, so the
                    // key will be free by the time this row is written.
                    occupied = !old_keys.contains(rename.new_key);
                }
            }
            if (occupied or existing_row) {
                if (rename.reference_duplicate) {
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
    const ctx = RewriteContext{
        .hosted_domains = hosted_domains,
        .forced = forced,
        .identities = &identities,
    };

    try planDb(&plan, &targets, .auth, auth, &.{ NS_USERS, NS_LOCKS }, &ctx);
    try planDb(&plan, &targets, .op, op, &.{
        NS_ROSTERS,
        NS_BLOCKLIST,
        NS_VCARDS,
        NS_PEP,
        NS_LASTACT,
        NS_OFFLINE,
        NS_ROOM_AFFILIATIONS,
        NS_PENDING_SUB,
    }, &ctx);
    try planDb(&plan, &targets, .archive, archive, &.{ NS_MESSAGES, NS_BY_CONTACT }, &ctx);

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
        if (old_index.get(rename.new_key)) |j| {
            if (j != i) {
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

fn applySingleDb(backend: anytype, allocator: std.mem.Allocator, plan: *const Plan, db: Database) !void {
    var any = false;
    for (plan.renames.items) |rename| {
        if (rename.db == db) {
            any = true;
            break;
        }
    }
    if (!any) return;

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
    for (plan.renames.items, 0..) |rename, i| {
        if (rename.db != db or rename.new_value != null) continue;
        values.items[i] = try backend.get(allocator, rename.namespace, rename.old_key);
        if (values.items[i] == null) return error.MissingSourceRow;
    }

    const order = try orderForDb(allocator, plan, db);
    defer allocator.free(order);
    var batch = try backend.writeBatch();
    errdefer batch.abort();
    for (order) |i| {
        const rename = plan.renames.items[i];
        try applyRename(&batch, rename, values.items[i]);
    }
    try batch.commit();
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
    journal_dir: ?[]const u8,
) !void {
    const order = try orderForDb(allocator, plan, db);
    defer allocator.free(order);

    var position: usize = 0;
    while (position < order.len) {
        const first = plan.renames.items[order[position]];
        var end = position + 1;
        while (end < order.len and sameGroup(first, plan.renames.items[order[end]])) : (end += 1) {}

        var values: std.ArrayListUnmanaged(?[]u8) = .{};
        defer {
            for (values.items) |value| {
                if (value) |bytes| allocator.free(bytes);
            }
            values.deinit(allocator);
        }
        try values.resize(allocator, end - position);
        @memset(values.items, null);
        for (order[position..end], 0..) |rename_index, i| {
            const rename = plan.renames.items[rename_index];
            if (rename.new_value != null) continue;
            values.items[i] = try backend.get(allocator, rename.namespace, rename.old_key);
            if (values.items[i] == null) return error.MissingSourceRow;
        }

        var batch = try backend.writeBatch();
        errdefer batch.abort();
        for (order[position..end], 0..) |rename_index, i| {
            try applyRename(&batch, plan.renames.items[rename_index], values.items[i]);
        }
        try batch.commit();

        if (journal_dir) |dir| {
            for (order[position..end]) |rename_index| try appendJournal(allocator, dir, plan.renames.items[rename_index]);
        }
        position = end;
    }
}

/// Apply a collision-free plan. LMDB uses one write transaction per DB when
/// `rename_bytes` fits the budget; larger plans and every archive pass use one
/// WriteBatch per key prefix. A journaled pass writes its plan before any
/// mutation and journals each committed prefix. Nothing is written when the
/// plan contains any issue.
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
    if (options.journal_dir) |dir| {
        if (journaled) try writePlanFile(allocator, dir, plan);
    }

    if (plan.rename_bytes <= options.single_txn_budget) {
        try applySingleDb(auth, allocator, plan, .auth);
        try applySingleDb(op, allocator, plan, .op);
    } else {
        try applyGroupedDb(auth, allocator, plan, .auth, options.journal_dir);
        try applyGroupedDb(op, allocator, plan, .op, options.journal_dir);
    }
    try applyGroupedDb(archive, allocator, plan, .archive, options.journal_dir);
}

const Deletion = struct {
    db: Database,
    namespace: []const u8,
    key: []u8,
};

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
    if (std.mem.eql(u8, namespace, NS_LOCKS)) {
        // A data-only spelling can equal a prepared lock key owned by the
        // surviving account. Only a real users-row deletion may remove the
        // exact raw lock.
        return delete_locks and std.mem.eql(u8, key, raw);
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
        std.mem.eql(u8, namespace, NS_MESSAGES))
    {
        if (firstJidMatchesRaw(key, raw, hosted_domains)) return true;
        return std.mem.eql(u8, namespace, NS_OFFLINE) and jidMatchesRaw(value, raw, hosted_domains);
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
) !void {
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
        NS_ROOM_AFFILIATIONS,
        NS_PENDING_SUB,
    }, raw, hosted_domains, raw_has_users);
    try collectRawDeletions(&remaining, allocator, .archive, archive, &.{ NS_MESSAGES, NS_BY_CONTACT }, raw, hosted_domains, raw_has_users);
    if (remaining.items.len != 0) return error.DataRemaining;
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
