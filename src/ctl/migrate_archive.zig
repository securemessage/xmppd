//! Offline migration of the MAM `by_contact` index to the v2 key format.
//!
//! - v1: `owner\0with\0timestamp_be(8)` -> stanza_id
//! - v2: `owner\0with\0timestamp_be(8)\0stanza_id` -> stanza_id
//!
//! Two passes over a quiescent archive DB:
//!
//! - rekey: every surviving v1 row gains its v2 key (the stanza id comes
//!   from the row's value) and loses the v1 key in the same batch.
//! - rebuild: every `messages` row derives its `with` from the stored
//!   stanza and gains the index row the v1 overwrite dropped. Sender
//!   copies pair the owner with the recipient's bare JID; recipient
//!   copies pair it with the sender's bare JID when the sender domain is
//!   hosted, or with the wire form for s2s; groupchat rows pair the room
//!   JID with the stanza's `from` attribute. Rebuild only adds rows that
//!   are missing; it never deletes.
//!
//! A plan with ops is journaled before the first commit
//! (`migrate-archive.pending` marker + `migrate-archive.resume` plan),
//! so an interrupted `--apply` replays from the stored plan. Every op is
//! idempotent: a rerun is a no-op once all v2 rows are written.

const std = @import("std");
const backend_mod = @import("backend");
const xml = @import("xml");

const NS_MESSAGES = backend_mod.registered("messages");
const NS_BY_CONTACT = backend_mod.registered("by_contact");

const MAX_KEY_LEN = 511;

pub const pending_file = "migrate-archive.pending";
pub const resume_file = "migrate-archive.resume";
const journal_header = "xmppd-migrate-archive-v1\n";

pub const OpKind = enum {
    /// v1 row rekeyed to v2; the v1 key is deleted.
    rekey,
    /// Index row recovered from the primary stanza; put only.
    rebuild,
    /// v1 row whose v2 target already exists; delete only.
    drop_v1,
};

pub const Op = struct {
    kind: OpKind,
    /// v1 key to delete (rekey, drop_v1); null for rebuild.
    old_key: ?[]u8 = null,
    new_key: []u8,
    /// stanza_id stored as the row value.
    value: []u8,
};

pub const IssueKind = enum {
    /// A key in either namespace does not match the v1 or v2 layout.
    malformed_key,
    /// The stored stanza does not expose enough to derive `with`.
    underivable_with,
    /// The recipient/sender split needs a hosted-domain list that was
    /// not supplied.
    needs_domain,
    /// The derived v2 key exceeds the backend key limit.
    key_too_long,
};

pub const Issue = struct {
    kind: IssueKind,
    key: []u8,
    detail: []u8,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    ops: std.ArrayListUnmanaged(Op) = .{},
    issues: std.ArrayListUnmanaged(Issue) = .{},

    pub fn init(allocator: std.mem.Allocator) Plan {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Plan) void {
        for (self.ops.items) |op| {
            if (op.old_key) |old| self.allocator.free(old);
            self.allocator.free(op.new_key);
            self.allocator.free(op.value);
        }
        self.ops.deinit(self.allocator);
        for (self.issues.items) |issue| {
            self.allocator.free(issue.key);
            self.allocator.free(issue.detail);
        }
        self.issues.deinit(self.allocator);
        self.* = undefined;
    }
};

fn addIssue(plan: *Plan, kind: IssueKind, key: []const u8, detail: []const u8) !void {
    try plan.issues.append(plan.allocator, .{
        .kind = kind,
        .key = try plan.allocator.dupe(u8, key),
        .detail = try plan.allocator.dupe(u8, detail),
    });
}

const ContactKey = struct {
    owner: []const u8,
    with: []const u8,
    /// null on a v1 row: the stanza id lives only in the value.
    stanza_id: ?[]const u8,
};

/// owner\0with\0ts_be(8) or owner\0with\0ts_be(8)\0stanza_id.
fn parseContactKey(key: []const u8) ?ContactKey {
    const owner_end = std.mem.indexOfScalar(u8, key, 0) orelse return null;
    const with_start = owner_end + 1;
    const with_end_rel = std.mem.indexOfScalar(u8, key[with_start..], 0) orelse return null;
    const with_end = with_start + with_end_rel;
    const tail = key[with_end + 1 ..];
    if (tail.len == 8) {
        return .{ .owner = key[0..owner_end], .with = key[with_start..with_end], .stanza_id = null };
    }
    if (tail.len > 9 and tail[8] == 0) {
        return .{ .owner = key[0..owner_end], .with = key[with_start..with_end], .stanza_id = tail[9..] };
    }
    return null;
}

const PrimaryKey = struct {
    owner: []const u8,
    timestamp: u64,
    stanza_id: []const u8,
};

/// owner\0ts_be(8)\0stanza_id.
fn parsePrimaryKey(key: []const u8) ?PrimaryKey {
    const owner_end = std.mem.indexOfScalar(u8, key, 0) orelse return null;
    const rest = key[owner_end + 1 ..];
    if (rest.len < 10) return null;
    const timestamp = std.mem.readInt(u64, rest[0..8], .big);
    if (rest[8] != 0) return null;
    return .{ .owner = key[0..owner_end], .timestamp = timestamp, .stanza_id = rest[9..] };
}

fn contactKeyV2(allocator: std.mem.Allocator, owner: []const u8, with: []const u8, timestamp: u64, stanza_id: []const u8) ![]u8 {
    const len = owner.len + 1 + with.len + 1 + 8 + 1 + stanza_id.len;
    if (len > MAX_KEY_LEN) return error.KeyTooLong;
    const key = try allocator.alloc(u8, len);
    var pos: usize = 0;
    @memcpy(key[pos..][0..owner.len], owner);
    pos += owner.len;
    key[pos] = 0;
    pos += 1;
    @memcpy(key[pos..][0..with.len], with);
    pos += with.len;
    key[pos] = 0;
    pos += 1;
    std.mem.writeInt(u64, key[pos..][0..8], timestamp, .big);
    pos += 8;
    key[pos] = 0;
    pos += 1;
    @memcpy(key[pos..][0..stanza_id.len], stanza_id);
    return key;
}

/// JID without the resource: everything before the first '/'.
fn bareJid(jid: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, jid, '/')) |slash| return jid[0..slash];
    return jid;
}

/// Domain part of a JID: after the last '@' before the resource.
fn jidDomain(jid: []const u8) []const u8 {
    const bare = bareJid(jid);
    if (std.mem.lastIndexOfScalar(u8, bare, '@')) |at| return bare[at + 1 ..];
    return bare;
}

fn isHosted(domain: []const u8, hosted_domains: []const []const u8) bool {
    for (hosted_domains) |hosted| {
        if (std.mem.eql(u8, domain, hosted)) return true;
    }
    return false;
}

const StanzaAttrs = struct {
    from: ?[]const u8 = null,
    to: ?[]const u8 = null,
    type_: ?[]const u8 = null,
};

/// Extract from/to/type from the stanza's root tag. Handles single and
/// double quoted attributes; values are returned entity-decoded into
/// `out` (one buffer, all three slices alias it). Returns null when the
/// root tag cannot be scanned.
fn firstTagAttrs(stanza_xml: []const u8, out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator) !?StanzaAttrs {
    out.clearRetainingCapacity();
    var i: usize = 0;
    // Skip a prolog or leading whitespace; the stored form starts with '<'.
    while (i < stanza_xml.len and (stanza_xml[i] == ' ' or stanza_xml[i] == '\t' or stanza_xml[i] == '\n' or stanza_xml[i] == '\r')) i += 1;
    if (i >= stanza_xml.len or stanza_xml[i] != '<') return null;
    if (i + 1 < stanza_xml.len and stanza_xml[i + 1] == '?') return null;
    if (i + 1 < stanza_xml.len and stanza_xml[i + 1] == '!') return null;
    i += 1;
    // Skip the tag name and any prefix.
    while (i < stanza_xml.len and stanza_xml[i] != ' ' and stanza_xml[i] != '\t' and stanza_xml[i] != '\n' and stanza_xml[i] != '\r' and stanza_xml[i] != '>' and stanza_xml[i] != '/') i += 1;

    var attrs = StanzaAttrs{};
    while (i < stanza_xml.len) {
        while (i < stanza_xml.len and (stanza_xml[i] == ' ' or stanza_xml[i] == '\t' or stanza_xml[i] == '\n' or stanza_xml[i] == '\r')) i += 1;
        if (i >= stanza_xml.len or stanza_xml[i] == '>' or stanza_xml[i] == '/') return attrs;
        const name_start = i;
        while (i < stanza_xml.len and stanza_xml[i] != '=' and stanza_xml[i] != ' ' and stanza_xml[i] != '\t' and stanza_xml[i] != '\n' and stanza_xml[i] != '\r' and stanza_xml[i] != '>' and stanza_xml[i] != '/') i += 1;
        const name = stanza_xml[name_start..i];
        while (i < stanza_xml.len and (stanza_xml[i] == ' ' or stanza_xml[i] == '\t' or stanza_xml[i] == '\n' or stanza_xml[i] == '\r')) i += 1;
        if (i >= stanza_xml.len or stanza_xml[i] != '=') return null;
        i += 1;
        while (i < stanza_xml.len and (stanza_xml[i] == ' ' or stanza_xml[i] == '\t' or stanza_xml[i] == '\n' or stanza_xml[i] == '\r')) i += 1;
        if (i >= stanza_xml.len or (stanza_xml[i] != '\'' and stanza_xml[i] != '"')) return null;
        const quote = stanza_xml[i];
        i += 1;
        const value_start = i;
        while (i < stanza_xml.len and stanza_xml[i] != quote) i += 1;
        if (i >= stanza_xml.len) return null;
        const raw_value = stanza_xml[value_start..i];
        i += 1;

        const want_from = std.mem.eql(u8, name, "from");
        const want_to = std.mem.eql(u8, name, "to");
        const want_type = std.mem.eql(u8, name, "type");
        if (want_from or want_to or want_type) {
            // JIDs never reach 2 KiB; a longer value cannot be a key
            // anyway, so decode into a bounded buffer before copying out.
            var dec_buf: [2048]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&dec_buf);
            xml.decodeWrite(fbs.writer(), raw_value) catch return null;
            const mark = out.items.len;
            try out.appendSlice(allocator, fbs.getWritten());
            const decoded = out.items[mark..];
            if (want_from) attrs.from = decoded;
            if (want_to) attrs.to = decoded;
            if (want_type) attrs.type_ = decoded;
        }
    }
    return attrs;
}

const Derived = union(enum) {
    with: []const u8,
    underivable,
    needs_domain,
};

/// Derive the `with` the writer used for this primary row. The decoded
/// slices alias `attr_buf`; the returned slice does too.
fn deriveWith(owner: []const u8, stanza_xml: []const u8, hosted_domains: []const []const u8, attr_buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator) !Derived {
    const attrs = try firstTagAttrs(stanza_xml, attr_buf, allocator) orelse return .underivable;
    const from = attrs.from orelse return .underivable;
    const bare_from = bareJid(from);

    if (attrs.type_) |t| {
        if (std.mem.eql(u8, t, "groupchat")) {
            // Room archives pair the room JID with the stanza's from
            // (room/nick) exactly as the fan-out writer stored it.
            if (!std.mem.eql(u8, owner, bare_from)) return .underivable;
            return .{ .with = from };
        }
    }

    const to = attrs.to orelse return .underivable;
    const bare_to = bareJid(to);
    if (std.mem.eql(u8, owner, bare_from)) return .{ .with = bare_to };
    if (std.mem.eql(u8, owner, bare_to)) {
        if (hosted_domains.len == 0) return .needs_domain;
        // Local senders archive the recipient copy under the sender's
        // bare JID; s2s keeps the wire form (full JID possible).
        if (isHosted(jidDomain(from), hosted_domains)) return .{ .with = bare_from };
        return .{ .with = from };
    }
    return .underivable;
}

/// Scan the archive DB and build the migration plan. `db` is any backend
/// opened on the archive store path.
pub fn planMigration(allocator: std.mem.Allocator, db: anytype, hosted_domains: []const []const u8) !Plan {
    var plan = Plan.init(allocator);
    errdefer plan.deinit();

    // v2 keys that will exist after apply: rows already stored plus every
    // target a planned op writes.
    var v2_keys = std.StringHashMapUnmanaged(void){};
    defer {
        var it = v2_keys.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        v2_keys.deinit(allocator);
    }

    // Pass 1: rekey surviving v1 rows.
    {
        var iter = try db.iterator(NS_BY_CONTACT, "");
        defer iter.deinit();
        while (iter.next()) |entry| {
            const parsed = parseContactKey(entry.key) orelse {
                try addIssue(&plan, .malformed_key, entry.key, "by_contact key matches neither v1 nor v2 layout");
                continue;
            };
            if (parsed.stanza_id != null) {
                const dup = try allocator.dupe(u8, entry.key);
                try v2_keys.put(allocator, dup, {});
                continue;
            }
            const stanza_id = entry.value;
            if (stanza_id.len == 0) {
                try addIssue(&plan, .malformed_key, entry.key, "v1 by_contact row has an empty stanza id");
                continue;
            }
            const new_key = contactKeyV2(allocator, parsed.owner, parsed.with, entryTimestamp(entry.key), stanza_id) catch {
                try addIssue(&plan, .key_too_long, entry.key, "v2 contact key exceeds 511 bytes");
                continue;
            };
            if (v2_keys.contains(new_key)) {
                allocator.free(new_key);
                try plan.ops.append(allocator, .{
                    .kind = .drop_v1,
                    .old_key = try allocator.dupe(u8, entry.key),
                    .new_key = try allocator.dupe(u8, entry.key),
                    .value = try allocator.dupe(u8, stanza_id),
                });
                continue;
            }
            try v2_keys.put(allocator, try allocator.dupe(u8, new_key), {});
            try plan.ops.append(allocator, .{
                .kind = .rekey,
                .old_key = try allocator.dupe(u8, entry.key),
                .new_key = new_key,
                .value = try allocator.dupe(u8, stanza_id),
            });
        }
    }

    // Pass 2: rebuild index rows the v1 overwrite lost.
    {
        var attr_buf: std.ArrayListUnmanaged(u8) = .{};
        defer attr_buf.deinit(allocator);

        var iter = try db.iterator(NS_MESSAGES, "");
        defer iter.deinit();
        while (iter.next()) |entry| {
            const pk = parsePrimaryKey(entry.key) orelse {
                try addIssue(&plan, .malformed_key, entry.key, "messages key does not match owner\\0ts\\0stanza_id");
                continue;
            };
            const derived = try deriveWith(pk.owner, entry.value, hosted_domains, &attr_buf, allocator);
            const with = switch (derived) {
                .with => |w| w,
                .underivable => {
                    try addIssue(&plan, .underivable_with, entry.key, "stanza does not expose owner/from/to for a with key");
                    continue;
                },
                .needs_domain => {
                    try addIssue(&plan, .needs_domain, entry.key, "recipient copy: rerun with --hosted-domain to pick the sender form");
                    continue;
                },
            };
            const new_key = contactKeyV2(allocator, pk.owner, with, pk.timestamp, pk.stanza_id) catch {
                try addIssue(&plan, .key_too_long, entry.key, "rebuilt contact key exceeds 511 bytes");
                continue;
            };
            if (v2_keys.contains(new_key)) {
                allocator.free(new_key);
                continue;
            }
            try v2_keys.put(allocator, try allocator.dupe(u8, new_key), {});
            try plan.ops.append(allocator, .{
                .kind = .rebuild,
                .new_key = new_key,
                .value = try allocator.dupe(u8, pk.stanza_id),
            });
        }
    }

    return plan;
}

fn entryTimestamp(key: []const u8) u64 {
    // Callers pass a key parseContactKey accepted: the 8 bytes after the
    // second NUL are the big-endian timestamp in both formats.
    const first = std.mem.indexOfScalar(u8, key, 0).?;
    const second_rel = std.mem.indexOfScalar(u8, key[first + 1 ..], 0).?;
    const ts_off = first + 1 + second_rel + 1;
    return std.mem.readInt(u64, key[ts_off..][0..8], .big);
}

/// One WriteBatch commit per this many ops; bounds the live batch and
/// keeps a crashed apply resumable in reasonably sized chunks.
const COMMIT_EVERY_OPS = 512;

fn applyOps(db: anytype, ops: []const Op) !void {
    var i: usize = 0;
    while (i < ops.len) {
        const end = @min(i + COMMIT_EVERY_OPS, ops.len);
        var batch = try db.writeBatch();
        {
            // A failed delete or put must end the write txn (S9). The
            // abort covers the op loop only: real backends destroy the
            // batch inside commit, so a failed commit must not abort.
            errdefer batch.abort();
            for (ops[i..end]) |op| {
                if (op.old_key) |old| try batch.delete(NS_BY_CONTACT, old);
                if (op.kind != .drop_v1) try batch.put(NS_BY_CONTACT, op.new_key, op.value);
            }
        }
        try batch.commit();
        i = end;
    }
}

fn artifactPath(allocator: std.mem.Allocator, dir: []const u8, basename: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ dir, basename });
}

fn syncDir(dir_path: []const u8) !void {
    var dir = try std.fs.cwd().openDir(dir_path, .{});
    defer dir.close();
    try std.posix.fsync(dir.fd);
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
    return out;
}

fn hexDecodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (text.len % 2 != 0) return error.InvalidJournal;
    const result = try allocator.alloc(u8, text.len / 2);
    errdefer allocator.free(result);
    for (0..result.len) |i| {
        result[i] = (try std.fmt.charToDigit(text[i * 2], 16)) << 4 |
            try std.fmt.charToDigit(text[i * 2 + 1], 16);
    }
    return result;
}

/// Serialize the op list to the resume file and write the digest marker.
/// Returns the digest hex; caller frees.
fn writeJournal(allocator: std.mem.Allocator, dir: []const u8, plan: *const Plan) ![]u8 {
    const path = try artifactPath(allocator, dir, resume_file);
    defer allocator.free(path);
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);
    var file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
    defer file.close();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    try file.writeAll(journal_header);
    hasher.update(journal_header);
    for (plan.ops.items) |op| {
        const old_hex = if (op.old_key) |old| try hexEncodeAlloc(allocator, old) else null;
        defer if (old_hex) |h| allocator.free(h);
        const new_hex = try hexEncodeAlloc(allocator, op.new_key);
        defer allocator.free(new_hex);
        const value_hex = try hexEncodeAlloc(allocator, op.value);
        defer allocator.free(value_hex);
        const line = try std.fmt.allocPrint(allocator, "{s}\t{s}\t{s}\t{s}\n", .{
            @tagName(op.kind),
            old_hex orelse "-",
            new_hex,
            value_hex,
        });
        defer allocator.free(line);
        try file.writeAll(line);
        hasher.update(line);
    }
    try file.sync();
    try std.fs.cwd().rename(tmp_path, path);
    try syncDir(dir);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const digest_hex = try hexEncodeAlloc(allocator, &digest);
    errdefer allocator.free(digest_hex);

    const marker_path = try artifactPath(allocator, dir, pending_file);
    defer allocator.free(marker_path);
    const marker_tmp = try std.fmt.allocPrint(allocator, "{s}.tmp", .{marker_path});
    defer allocator.free(marker_tmp);
    {
        var marker = try std.fs.cwd().createFile(marker_tmp, .{ .truncate = true });
        defer marker.close();
        try marker.writeAll(digest_hex);
        try marker.writeAll("\n");
        try marker.sync();
    }
    try std.fs.cwd().rename(marker_tmp, marker_path);
    try syncDir(dir);
    return digest_hex;
}

/// Load the journaled plan and verify it against the marker digest.
fn readJournal(allocator: std.mem.Allocator, dir: []const u8) !Plan {
    const pending_path = try artifactPath(allocator, dir, pending_file);
    defer allocator.free(pending_path);
    const plan_path = try artifactPath(allocator, dir, resume_file);
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
    if (!std.mem.eql(u8, expected_digest, actual_hex)) return error.JournalDigestMismatch;

    var plan = Plan.init(allocator);
    errdefer plan.deinit();
    var lines = std.mem.splitScalar(u8, data, '\n');
    const header = lines.next() orelse return error.InvalidJournal;
    if (!std.mem.eql(u8, header, std.mem.trimRight(u8, journal_header, "\n"))) return error.InvalidJournal;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const kind_text = fields.next() orelse return error.InvalidJournal;
        const old_hex = fields.next() orelse return error.InvalidJournal;
        const new_hex = fields.next() orelse return error.InvalidJournal;
        const value_hex = fields.next() orelse return error.InvalidJournal;
        if (fields.next() != null) return error.InvalidJournal;

        const kind = std.meta.stringToEnum(OpKind, kind_text) orelse return error.InvalidJournal;
        const old_key: ?[]u8 = if (std.mem.eql(u8, old_hex, "-"))
            null
        else
            try hexDecodeAlloc(allocator, old_hex);
        errdefer if (old_key) |k| allocator.free(k);
        const new_key = try hexDecodeAlloc(allocator, new_hex);
        errdefer allocator.free(new_key);
        const value = try hexDecodeAlloc(allocator, value_hex);
        errdefer allocator.free(value);
        try plan.ops.append(allocator, .{
            .kind = kind,
            .old_key = old_key,
            .new_key = new_key,
            .value = value,
        });
    }
    return plan;
}

/// Fault hooks for tests; production keeps the real fs calls.
var delete_journal_file: *const fn (path: []const u8) anyerror!void = deleteFileCwd;
var sync_journal_dir: *const fn (path: []const u8) anyerror!void = syncDir;

fn deleteFileCwd(path: []const u8) anyerror!void {
    try std.fs.cwd().deleteFile(path);
}

/// Removes the pending marker and resume plan, then fsyncs the journal
/// directory so the removals are durable. A marker left behind makes
/// every later run replay the plan, so removal and fsync failures
/// propagate; a delete that finds the artifact already gone is success.
/// On error `failed_path` names the artifact that could not be removed,
/// or the directory on an fsync failure; the caller owns the buffer.
fn clearJournal(allocator: std.mem.Allocator, dir: []const u8, failed_path: ?*std.ArrayListUnmanaged(u8)) !void {
    if (failed_path) |fp| fp.clearRetainingCapacity();
    const pending = try artifactPath(allocator, dir, pending_file);
    defer allocator.free(pending);
    delete_journal_file(pending) catch |err| switch (err) {
        error.FileNotFound => {},
        else => {
            if (failed_path) |fp| try fp.appendSlice(allocator, pending);
            return err;
        },
    };
    const journal = try artifactPath(allocator, dir, resume_file);
    defer allocator.free(journal);
    delete_journal_file(journal) catch |err| switch (err) {
        error.FileNotFound => {},
        else => {
            if (failed_path) |fp| try fp.appendSlice(allocator, journal);
            return err;
        },
    };
    sync_journal_dir(dir) catch |err| {
        if (failed_path) |fp| try fp.appendSlice(allocator, dir);
        return err;
    };
}

pub fn journalPending(allocator: std.mem.Allocator, dir: []const u8) !bool {
    const path = try artifactPath(allocator, dir, pending_file);
    defer allocator.free(path);
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

/// Journal the plan, then apply it in bounded write batches. On a commit
/// failure the journal stays; a rerun of --apply replays every op, which
/// is safe because puts rewrite the same key and deletes ignore misses.
/// A non-empty `cleanup_path` on return means the ops committed but the
/// journal cleanup failed; the buffer names the artifact left behind.
pub fn applyPlan(allocator: std.mem.Allocator, db: anytype, plan: *const Plan, journal_dir: []const u8, cleanup_path: ?*std.ArrayListUnmanaged(u8)) !void {
    if (plan.ops.items.len == 0) return;
    const digest_hex = try writeJournal(allocator, journal_dir, plan);
    defer allocator.free(digest_hex);
    try applyOps(db, plan.ops.items);
    try clearJournal(allocator, journal_dir, cleanup_path);
}

/// Replay a journaled plan after an interrupted apply. `cleanup_path`
/// has the same contract as in applyPlan.
pub fn resumeMigration(allocator: std.mem.Allocator, db: anytype, journal_dir: []const u8, cleanup_path: ?*std.ArrayListUnmanaged(u8)) !usize {
    var plan = try readJournal(allocator, journal_dir);
    defer plan.deinit();
    try applyOps(db, plan.ops.items);
    try clearJournal(allocator, journal_dir, cleanup_path);
    return plan.ops.items.len;
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;

fn seedV1Contact(db: *MemoryBackend, owner: []const u8, with: []const u8, timestamp: u64, stanza_id: []const u8) !void {
    var key_buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&key_buf);
    const w = fbs.writer();
    try w.writeAll(owner);
    try w.writeByte(0);
    try w.writeAll(with);
    try w.writeByte(0);
    var ts: [8]u8 = undefined;
    std.mem.writeInt(u64, &ts, timestamp, .big);
    try w.writeAll(&ts);
    try db.put(NS_BY_CONTACT, fbs.getWritten(), stanza_id);
}

fn seedMessage(db: *MemoryBackend, owner: []const u8, timestamp: u64, stanza_id: []const u8, stanza_xml: []const u8) !void {
    var key_buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&key_buf);
    const w = fbs.writer();
    try w.writeAll(owner);
    try w.writeByte(0);
    var ts: [8]u8 = undefined;
    std.mem.writeInt(u64, &ts, timestamp, .big);
    try w.writeAll(&ts);
    try w.writeByte(0);
    try w.writeAll(stanza_id);
    try db.put(NS_MESSAGES, fbs.getWritten(), stanza_xml);
}

test "migrate-archive: v1 rows rekey, lost rows rebuild, v2 rows stay" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    const chat = "<message from='alice@us.example/r1' to='bob@us.example' type='chat' id='c1'><body>x</body></message>";
    // bob's recipient copy kept its v1 index row: rekey.
    try seedMessage(&db, "bob@us.example", 1000, "m-001", chat);
    try seedV1Contact(&db, "bob@us.example", "alice@us.example", 1000, "m-001");
    // Two of alice's sender copies share one second: m-003 holds the v1
    // survivor (rekey) and m-002's index row was overwritten (rebuild).
    try seedMessage(&db, "alice@us.example", 1000, "m-002", chat);
    try seedMessage(&db, "alice@us.example", 1000, "m-003", chat);
    try seedV1Contact(&db, "alice@us.example", "bob@us.example", 1000, "m-003");

    const domains = [_][]const u8{"us.example"};
    var plan = try planMigration(allocator, &db, &domains);
    defer plan.deinit();

    try std.testing.expectEqual(@as(usize, 0), plan.issues.items.len);
    try std.testing.expectEqual(@as(usize, 3), plan.ops.items.len);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir);
    try applyPlan(allocator, &db, &plan, dir, null);

    // bob's rekeyed row.
    const bob_key = try contactKeyV2(allocator, "bob@us.example", "alice@us.example", 1000, "m-001");
    defer allocator.free(bob_key);
    const got_bob = try db.get(allocator, NS_BY_CONTACT, bob_key);
    defer if (got_bob) |v| allocator.free(v);
    try std.testing.expect(got_bob != null);

    // alice's lost sender copy rebuilt even though no v1 row named it.
    const alice_key = try contactKeyV2(allocator, "alice@us.example", "bob@us.example", 1000, "m-002");
    defer allocator.free(alice_key);
    const got_alice = try db.get(allocator, NS_BY_CONTACT, alice_key);
    defer if (got_alice) |v| allocator.free(v);
    try std.testing.expect(got_alice != null);

    // No v1 keys remain.
    var iter = try db.iterator(NS_BY_CONTACT, "");
    defer iter.deinit();
    while (iter.next()) |entry| {
        try std.testing.expect(parseContactKey(entry.key).?.stanza_id != null);
    }
}

test "migrate-archive: groupchat rebuilds under the room/nick from" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    const gc = "<message from='room@conf.example/alice' type='groupchat' id='g1'><body>hi</body></message>";
    try seedMessage(&db, "room@conf.example", 2000, "g-1", gc);
    // The v1 overwrite ate the index row: nothing seeded in by_contact.

    const domains = [_][]const u8{"us.example"};
    var plan = try planMigration(allocator, &db, &domains);
    defer plan.deinit();

    try std.testing.expectEqual(@as(usize, 1), plan.ops.items.len);
    try std.testing.expectEqual(OpKind.rebuild, plan.ops.items[0].kind);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir);
    try applyPlan(allocator, &db, &plan, dir, null);

    const key = try contactKeyV2(allocator, "room@conf.example", "room@conf.example/alice", 2000, "g-1");
    defer allocator.free(key);
    const got = try db.get(allocator, NS_BY_CONTACT, key);
    defer if (got) |v| allocator.free(v);
    try std.testing.expect(got != null);
}

test "migrate-archive: s2s recipient copy rebuilds under the wire from" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    const s2s = "<message from='peer@remote.example/res' to='bob@us.example' type='chat' id='s1'><body>x</body></message>";
    try seedMessage(&db, "bob@us.example", 3000, "s-1", s2s);

    const domains = [_][]const u8{"us.example"};
    var plan = try planMigration(allocator, &db, &domains);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.ops.items.len);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir);
    try applyPlan(allocator, &db, &plan, dir, null);

    const key = try contactKeyV2(allocator, "bob@us.example", "peer@remote.example/res", 3000, "s-1");
    defer allocator.free(key);
    const got = try db.get(allocator, NS_BY_CONTACT, key);
    defer if (got) |v| allocator.free(v);
    try std.testing.expect(got != null);
}

test "migrate-archive: without hosted domains a recipient copy reports needs_domain" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    const chat = "<message from='alice@us.example' to='bob@us.example' type='chat' id='c1'><body>x</body></message>";
    try seedMessage(&db, "bob@us.example", 4000, "m-1", chat);

    var plan = try planMigration(allocator, &db, &.{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan.ops.items.len);
    try std.testing.expectEqual(@as(usize, 1), plan.issues.items.len);
    try std.testing.expectEqual(IssueKind.needs_domain, plan.issues.items[0].kind);
}

test "migrate-archive: journal survives a torn apply and replays" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    const chat = "<message from='alice@us.example' to='bob@us.example' type='chat' id='c1'><body>x</body></message>";
    try seedMessage(&db, "bob@us.example", 5000, "m-1", chat);
    try seedV1Contact(&db, "bob@us.example", "alice@us.example", 5000, "m-1");

    const domains = [_][]const u8{"us.example"};
    var plan = try planMigration(allocator, &db, &domains);
    defer plan.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir);

    // Journal without applying: simulate a crash between writeJournal
    // and applyOps.
    const digest = try writeJournal(allocator, dir, &plan);
    allocator.free(digest);
    try std.testing.expect(try journalPending(allocator, dir));

    const replayed = try resumeMigration(allocator, &db, dir, null);
    try std.testing.expectEqual(@as(usize, 1), replayed);
    try std.testing.expect(!try journalPending(allocator, dir));

    const key = try contactKeyV2(allocator, "bob@us.example", "alice@us.example", 5000, "m-1");
    defer allocator.free(key);
    const got = try db.get(allocator, NS_BY_CONTACT, key);
    defer if (got) |v| allocator.free(v);
    try std.testing.expect(got != null);

    // Reapply is a no-op: the plan is empty once every row is v2.
    var plan2 = try planMigration(allocator, &db, &domains);
    defer plan2.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan2.ops.items.len);
}

test "migrate-archive: a journal delete failure propagates with the artifact path" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    const chat = "<message from='alice@us.example' to='bob@us.example' type='chat' id='c1'><body>x</body></message>";
    try seedMessage(&db, "bob@us.example", 6000, "m-1", chat);
    try seedV1Contact(&db, "bob@us.example", "alice@us.example", 6000, "m-1");

    const domains = [_][]const u8{"us.example"};
    var plan = try planMigration(allocator, &db, &domains);
    defer plan.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir);

    const saved_hook = delete_journal_file;
    defer delete_journal_file = saved_hook;
    delete_journal_file = struct {
        fn refusePending(path: []const u8) anyerror!void {
            if (std.mem.endsWith(u8, path, pending_file)) return error.InjectedDelete;
            try std.fs.cwd().deleteFile(path);
        }
    }.refusePending;

    var failed: std.ArrayListUnmanaged(u8) = .{};
    defer failed.deinit(allocator);
    try std.testing.expectError(error.InjectedDelete, applyPlan(allocator, &db, &plan, dir, &failed));
    // The named artifact is the pending marker, and it really is left.
    try std.testing.expect(std.mem.endsWith(u8, failed.items, pending_file));
    try std.testing.expect(try journalPending(allocator, dir));

    // The ops did commit: bob's row is v2 despite the cleanup failure.
    const key = try contactKeyV2(allocator, "bob@us.example", "alice@us.example", 6000, "m-1");
    defer allocator.free(key);
    const got = try db.get(allocator, NS_BY_CONTACT, key);
    defer if (got) |v| allocator.free(v);
    try std.testing.expect(got != null);
}

test "migrate-archive: a journal dir fsync failure propagates with the dir path" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir);

    const saved_hook = sync_journal_dir;
    defer sync_journal_dir = saved_hook;
    sync_journal_dir = struct {
        fn refuseSync(path: []const u8) anyerror!void {
            _ = path;
            return error.InjectedSync;
        }
    }.refuseSync;

    var failed: std.ArrayListUnmanaged(u8) = .{};
    defer failed.deinit(allocator);
    try std.testing.expectError(error.InjectedSync, clearJournal(allocator, dir, &failed));
    try std.testing.expectEqualStrings(dir, failed.items);
}
