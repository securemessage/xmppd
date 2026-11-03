//! # OidcIdentityStore — stable (iss, sub) to XMPP localpart bindings
//!
//! OIDC account identity is the (issuer, subject) pair (OIDC Core 5.7);
//! every other claim is mutable and only ever a localpart suggestion on
//! first login. This module owns the `oidc_identities` namespace in the
//! auth environment ({db}/auth), holding two indexes written atomically by
//! WriteBatch.putIfAbsent:
//!
//!   forward: 's' ++ u16be(iss.len) ++ iss ++ sub        -> localpart
//!   reverse: 'l' ++ localpart                           -> u16be(iss.len)
//!            ++ iss ++ sub ++ u8(source) ++ i64be(bound_at)
//!
//! The forward row is the permanent account identity: once written, a
//! renamed IdP claim can never re-map the subject. The reverse row is how
//! a suggested localpart is claimed exactly once and how operator tools
//! enumerate bindings.
//!
//! Resolver drives first-login resolution on IdP worker threads: bind
//! first, and only for unmapped subjects walk suggestion -> normalization
//! -> reverse check -> users row check -> account-data probe -> atomic
//! claim. Anything present blocks auto-claim and points the operator at
//! `xmppctl oidc-link`.

const std = @import("std");
const backend_mod = @import("backend");

const log = std.log.scoped(.oidc_identity_store);

pub const NAMESPACE = backend_mod.registered("oidc_identities");
const USERS_NS = backend_mod.registered("users");
const ROSTERS_NS = backend_mod.registered("rosters");
const OFFLINE_NS = backend_mod.registered("offline");
const VCARDS_NS = backend_mod.registered("vcards");
const LASTACT_NS = backend_mod.registered("lastact");
const PEP_NS = backend_mod.registered("pep");
const BLOCKLIST_NS = backend_mod.registered("blocklist");
const PENDING_SUB_NS = backend_mod.registered("pending_sub");
const ROOM_AFFIL_NS = backend_mod.registered("room_affiliations");
const MESSAGES_NS = backend_mod.registered("messages");
const BY_CONTACT_NS = backend_mod.registered("by_contact");

pub const max_iss_len = 192;
pub const max_sub_len = 256;
pub const max_localpart_len = 255;
const fwd_prefix: u8 = 's';
const rev_prefix: u8 = 'l';

/// Rows that end a room-affiliation scan without a verdict: keeps the
/// upgrade probe bounded on very large MUC deployments.
pub const room_scan_cap: u32 = 65536;

pub const Source = enum(u8) {
    auto = 0,
    operator = 1,
};

pub const StoreError = error{
    IssuerTooLong,
    SubjectTooLong,
    LocalpartTooLong,
    CorruptRow,
};

const RevRow = struct {
    iss: []const u8,
    sub: []const u8,
    source: Source,
    bound_at: i64,
};

fn forwardKey(buf: *[512]u8, iss: []const u8, sub: []const u8) StoreError![]const u8 {
    if (iss.len == 0 or iss.len > max_iss_len) return error.IssuerTooLong;
    if (sub.len == 0 or sub.len > max_sub_len) return error.SubjectTooLong;
    const need = 1 + 2 + iss.len + sub.len;
    buf[0] = fwd_prefix;
    std.mem.writeInt(u16, buf[1..3], @intCast(iss.len), .big);
    @memcpy(buf[3..][0..iss.len], iss);
    @memcpy(buf[3 + iss.len ..][0..sub.len], sub);
    return buf[0..need];
}

fn reverseKey(buf: *[512]u8, localpart: []const u8) StoreError![]const u8 {
    if (localpart.len == 0 or localpart.len > max_localpart_len) return error.LocalpartTooLong;
    buf[0] = rev_prefix;
    @memcpy(buf[1..][0..localpart.len], localpart);
    return buf[0 .. 1 + localpart.len];
}

fn decodeRevValue(data: []const u8) StoreError!RevRow {
    if (data.len < 2 + 1 + 8) return error.CorruptRow;
    const iss_len = std.mem.readInt(u16, data[0..2], .big);
    const fixed = 2 + @as(usize, iss_len) + 9;
    if (data.len <= fixed) return error.CorruptRow;
    const sub_end = data.len - 9;
    return .{
        .iss = data[2 .. 2 + iss_len],
        .sub = data[2 + iss_len .. sub_end],
        .source = @enumFromInt(data[sub_end]),
        .bound_at = std.mem.readInt(i64, data[sub_end + 1 ..][0..8], .big),
    };
}

fn encodeRevValue(buf: *[512]u8, iss: []const u8, sub: []const u8, source: Source, bound_at: i64) StoreError![]const u8 {
    const need = 2 + iss.len + sub.len + 9;
    if (need > buf.len) return error.SubjectTooLong;
    std.mem.writeInt(u16, buf[0..2], @intCast(iss.len), .big);
    @memcpy(buf[2..][0..iss.len], iss);
    @memcpy(buf[2 + iss.len ..][0..sub.len], sub);
    buf[2 + iss.len + sub.len] = @intFromEnum(source);
    std.mem.writeInt(i64, buf[2 + iss.len + sub.len + 1 ..][0..8], bound_at, .big);
    return buf[0..need];
}

/// The outcome of resolving an identity to an account.
pub const Resolution = union(enum) {
    /// lp_out holds the bound localpart; the value is its length.
    bound: usize,
    refused: Refusal,
    unavailable,
};

pub const Refusal = enum {
    /// iss or sub empty/oversized, or sub missing outright.
    no_subject,
    /// No usable suggestion claim on first login.
    no_suggestion,
    /// Suggestion failed prefix/domain/normalization checks.
    bad_suggestion,
    /// Suggested localpart is already bound to another subject.
    localpart_taken,
    /// A users-store row exists for the localpart (provisioned account).
    local_account,
    /// Existing account data was found; operator must oidc-link.
    unclaimed_data,
};

/// Type-erased resolver entry point registered on OidcStore: the daemon
/// builds a typed Resolver and hands the store this pair, keeping OidcStore
/// itself free of backend types.
pub const BindingOps = struct {
    ctx: *anyopaque,
    resolve_fn: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, iss: []const u8, sub: []const u8, suggestion: []const u8, lp_out: *[max_localpart_len]u8) anyerror!Resolution,
};

/// Key/value access on the oidc_identities namespace of one backend.
pub fn Store(comptime Backend: type) type {
    return struct {
        backend: *Backend,

        const Self = @This();

        pub fn init(backend: *Backend) Self {
            return .{ .backend = backend };
        }

        /// Localpart bound to (iss, sub), or null. Caller owns the slice.
        pub fn lookupSubject(self: *Self, allocator: std.mem.Allocator, iss: []const u8, sub: []const u8) !?[]u8 {
            var kbuf: [512]u8 = undefined;
            const key = try forwardKey(&kbuf, iss, sub);
            return try self.backend.get(allocator, NAMESPACE, key);
        }

        /// Reverse row for a localpart, or null. iss/sub borrow `value`,
        /// which the caller frees.
        pub const LocalpartBinding = struct {
            iss: []const u8,
            sub: []const u8,
            source: Source,
            bound_at: i64,
            value: []u8,
        };

        pub fn lookupLocalpart(self: *Self, allocator: std.mem.Allocator, localpart: []const u8) !?LocalpartBinding {
            var kbuf: [512]u8 = undefined;
            const key = try reverseKey(&kbuf, localpart);
            const v = (try self.backend.get(allocator, NAMESPACE, key)) orelse return null;
            errdefer allocator.free(v);
            const d = try decodeRevValue(v);
            return .{
                .iss = d.iss,
                .sub = d.sub,
                .source = d.source,
                .bound_at = d.bound_at,
                .value = v,
            };
        }

        /// Atomically claim (iss, sub) -> localpart with both index rows.
        /// Which side lost is reported so the caller can log and classify.
        pub const Claimed = enum { bound, localpart_taken, subject_taken };

        pub fn bind(self: *Self, iss: []const u8, sub: []const u8, localpart: []const u8, source: Source, bound_at: i64) !Claimed {
            var kbuf: [512]u8 = undefined;
            var vbuf: [512]u8 = undefined;
            const fkey = try forwardKey(&kbuf, iss, sub);
            const rkey = try reverseKey(&vbuf, localpart);
            var rbuf2: [512]u8 = undefined;
            const rval = try encodeRevValue(&rbuf2, iss, sub, source, bound_at);

            var batch = try self.backend.writeBatch();
            var rev_conflict = false;
            var fwd_conflict = false;
            batch.putIfAbsent(NAMESPACE, rkey, rval) catch |err| switch (err) {
                error.Conflict => rev_conflict = true,
                else => {
                    batch.abort();
                    return err;
                },
            };
            if (!rev_conflict) {
                batch.putIfAbsent(NAMESPACE, fkey, localpart) catch |err| switch (err) {
                    error.Conflict => fwd_conflict = true,
                    else => {
                        batch.abort();
                        return err;
                    },
                };
            }
            if (rev_conflict or fwd_conflict) {
                batch.abort();
                return if (rev_conflict) .localpart_taken else .subject_taken;
            }
            try batch.commit();
            return .bound;
        }

        /// Remove both rows for a localpart. False when it was not bound.
        pub fn unbind(self: *Self, allocator: std.mem.Allocator, localpart: []const u8) !bool {
            const found = try self.lookupLocalpart(allocator, localpart) orelse return false;
            defer allocator.free(found.value);

            var kbuf: [512]u8 = undefined;
            var kbuf2: [512]u8 = undefined;
            const fkey = try forwardKey(&kbuf, found.iss, found.sub);
            const rkey = try reverseKey(&kbuf2, localpart);

            var batch = try self.backend.writeBatch();
            try batch.delete(NAMESPACE, fkey);
            try batch.delete(NAMESPACE, rkey);
            try batch.commit();
            return true;
        }

        /// One binding row, borrowing the iterator's buffers until the
        /// next next() call (fine for ctl listing).
        pub const Binding = struct {
            iss: []const u8,
            sub: []const u8,
            localpart: []const u8,
            source: Source,
            bound_at: i64,
        };

        pub const BindingIterator = struct {
            inner: Backend.Iterator,

            pub fn next(self: *BindingIterator) !?Binding {
                while (self.inner.next()) |entry| {
                    if (entry.key.len < 2 or entry.key[0] != rev_prefix) continue;
                    const d = decodeRevValue(entry.value) catch continue;
                    return .{
                        .iss = d.iss,
                        .sub = d.sub,
                        .localpart = entry.key[1..],
                        .source = d.source,
                        .bound_at = d.bound_at,
                    };
                }
                return null;
            }

            pub fn deinit(self: *BindingIterator) void {
                self.inner.deinit();
            }
        };

        /// Iterate the reverse index (every binding, localpart order).
        pub fn iterateBindings(self: *Self) !BindingIterator {
            return .{ .inner = try self.backend.iterator(NAMESPACE, "l") };
        }
    };
}

/// Interim localpart normalization seam: ASCII-lowercase plus a
/// conservative allowlist, valid until the PRECIS work lands (PR #30),
/// when this becomes precis.xmppLocalpart() with the RFC 7622 exclusions.
/// Returns the normalized length written to out, or null when the raw
/// value cannot form a localpart at all.
pub fn normalizeLocalpart(raw: []const u8, out: *[max_localpart_len]u8) ?usize {
    if (raw.len == 0 or raw.len > max_localpart_len) return null;
    var len: usize = 0;
    for (raw) |ch| {
        const lower = std.ascii.toLower(ch);
        const ok = switch (lower) {
            'a'...'z', '0'...'9', '.', '_', '-' => true,
            else => false,
        };
        if (!ok) return null;
        out[len] = lower;
        len += 1;
    }
    return len;
}

/// First-login and operator-binding resolution. Generic over the
/// operational backend (used for both the auth env that holds the
/// bindings/users namespaces and the op env data probe) and the archive
/// backend (MAM probe). Both pointers are optional probes: a null env is
/// treated as "no data", a real backend error is a resolution failure.
pub fn Resolver(comptime Backend: type, comptime ArchiveBackend: type) type {
    return struct {
        store: Store(Backend),
        /// {db}/op env, read-only probe (same backend type as the auth env).
        op_backend: ?*Backend = null,
        /// {db}/archive env, read-only probe.
        archive_backend: ?*ArchiveBackend = null,
        /// Configured XMPP domain: suggestion domain checks and the
        /// localpart -> bare-JID probe prefix derive from it.
        user_domain: ?[]const u8 = null,
        /// Prefix stripped from the suggestion claim before normalization
        /// (e.g. "user:" for identity-oidc handle-form subjects).
        localpart_claim_prefix: []const u8 = "",
        /// Allow lp-2 .. lp-99 retries when the suggestion is taken.
        auto_suffix: bool = false,
        /// Row cap for the room_affiliations upgrade scan.
        room_scan_limit: u32 = room_scan_cap,

        const Self = @This();

        /// Type-erased entry point for OidcStore's bindings field.
        pub fn bindingOps(self: *Self) BindingOps {
            return .{ .ctx = self, .resolve_fn = resolveThunk };
        }

        fn resolveThunk(ctx: *anyopaque, allocator: std.mem.Allocator, iss: []const u8, sub: []const u8, suggestion: []const u8, lp_out: *[max_localpart_len]u8) anyerror!Resolution {
            const self: *Self = @ptrCast(@alignCast(ctx));
            var len: usize = 0;
            const out = try self.resolve(allocator, iss, sub, suggestion, lp_out, &len);
            return switch (out) {
                .bound => .{ .bound = len },
                .refused => |r| .{ .refused = r },
                .unavailable => .unavailable,
            };
        }

        /// Resolve (iss, sub) to the account localpart. Only the
        /// subject-bound mapping selects an account; the suggestion claim
        /// is a first-login hint and never binds identity.
        pub fn resolve(self: *Self, allocator: std.mem.Allocator, iss: []const u8, sub: []const u8, suggestion: []const u8, lp_out: *[max_localpart_len]u8, lp_len: *usize) anyerror!Resolution {
            if (sub.len == 0 or iss.len == 0 or iss.len > max_iss_len or sub.len > max_sub_len) {
                if (sub.len == 0 or iss.len == 0) {
                    log.info("oidc: refusing login with empty issuer or subject", .{});
                    return .{ .refused = .no_subject };
                }
                log.info("oidc: refusing login with oversized issuer ({d}) or subject ({d})", .{ iss.len, sub.len });
                return .{ .refused = .no_subject };
            }

            if (self.store.lookupSubject(allocator, iss, sub) catch |err| {
                log.warn("oidc: binding lookup failed for sub: {s}", .{@errorName(err)});
                return .unavailable;
            }) |lp| {
                defer allocator.free(lp);
                if (lp.len > lp_out.len) return .unavailable;
                @memcpy(lp_out[0..lp.len], lp);
                lp_len.* = lp.len;
                return .{ .bound = lp.len };
            }

            const base = self.suggestLocalpart(suggestion) orelse {
                log.info("oidc: no usable localpart suggestion for new subject (iss={s})", .{iss});
                return .{ .refused = .no_suggestion };
            };

            const max_attempts: usize = if (self.auto_suffix) 98 else 1;
            var attempt: usize = 0;
            while (attempt < max_attempts) : (attempt += 1) {
                var cand_buf: [max_localpart_len]u8 = undefined;
                var cand_len: usize = undefined;
                if (attempt == 0) {
                    cand_len = normalizeLocalpart(base, &cand_buf) orelse {
                        log.info("oidc: suggestion '{s}' cannot form a localpart", .{suggestion});
                        return .{ .refused = .bad_suggestion };
                    };
                } else {
                    cand_len = suffixCandidate(base, &cand_buf, attempt + 1) orelse {
                        return .{ .refused = .localpart_taken };
                    };
                }
                const cand = cand_buf[0..cand_len];

                switch (try self.tryClaim(allocator, iss, sub, cand, lp_out, lp_len)) {
                    .bound => return .{ .bound = lp_len.* },
                    .refused => |r| {
                        if (r != .localpart_taken or !self.auto_suffix) return .{ .refused = r };
                    },
                    .unavailable => return .unavailable,
                }
            }
            log.info("oidc: localpart '{s}' and all suffix candidates are taken", .{base});
            return .{ .refused = .localpart_taken };
        }

        /// The full first-login claim path for one candidate localpart.
        fn tryClaim(self: *Self, allocator: std.mem.Allocator, iss: []const u8, sub: []const u8, cand: []const u8, lp_out: *[max_localpart_len]u8, lp_len: *usize) anyerror!Resolution {
            if (self.store.lookupLocalpart(allocator, cand) catch |err| {
                log.warn("oidc: reverse lookup failed for '{s}': {s}", .{ cand, @errorName(err) });
                return .unavailable;
            }) |existing| {
                defer allocator.free(existing.value);
                if (std.mem.eql(u8, existing.iss, iss) and std.mem.eql(u8, existing.sub, sub)) {
                    @memcpy(lp_out[0..cand.len], cand);
                    lp_len.* = cand.len;
                    return .{ .bound = cand.len };
                }
                log.info("oidc: localpart '{s}' is already bound to another subject", .{cand});
                return .{ .refused = .localpart_taken };
            }

            const user_row = self.store.backend.get(allocator, USERS_NS, cand) catch |err| {
                log.warn("oidc: users lookup failed for '{s}': {s}", .{ cand, @errorName(err) });
                return .unavailable;
            };
            if (user_row) |v| {
                allocator.free(v);
                log.info("oidc: refusing auto-claim of '{s}': provisioned account exists; use xmppctl oidc-link", .{cand});
                return .{ .refused = .local_account };
            }

            if (self.accountHasData(allocator, cand) catch |err| {
                log.warn("oidc: account-data probe failed for '{s}': {s}", .{ cand, @errorName(err) });
                return .unavailable;
            }) {
                log.info("oidc: refusing auto-claim of '{s}': existing account data found; use xmppctl oidc-link", .{cand});
                return .{ .refused = .unclaimed_data };
            }

            switch (self.store.bind(iss, sub, cand, .auto, std.time.timestamp()) catch |err| {
                log.warn("oidc: bind failed for '{s}': {s}", .{ cand, @errorName(err) });
                return .unavailable;
            }) {
                .bound => {
                    @memcpy(lp_out[0..cand.len], cand);
                    lp_len.* = cand.len;
                    log.info("oidc: bound sub of iss={s} to localpart '{s}'", .{ iss, cand });
                    return .{ .bound = cand.len };
                },
                .localpart_taken => {
                    log.info("oidc: localpart '{s}' claimed concurrently; refusing", .{cand});
                    return .{ .refused = .localpart_taken };
                },
                .subject_taken => {
                    // Lost the forward race to another login of the same
                    // subject: adopt the winner's localpart.
                    const winner = (self.store.lookupSubject(allocator, iss, sub) catch return .unavailable) orelse return .unavailable;
                    defer allocator.free(winner);
                    if (winner.len > lp_out.len) return .unavailable;
                    @memcpy(lp_out[0..winner.len], winner);
                    lp_len.* = winner.len;
                    return .{ .bound = winner.len };
                },
            }
        }

        /// Derive the raw localpart suggestion: strip the configured claim
        /// prefix (required when set), then enforce the domain rule (a
        /// suggestion carrying @domain must match user_domain; the
        /// localpart is the part before @).
        fn suggestLocalpart(self: *Self, suggestion: []const u8) ?[]const u8 {
            var s = suggestion;
            if (s.len == 0) return null;
            if (self.localpart_claim_prefix.len > 0) {
                if (!std.mem.startsWith(u8, s, self.localpart_claim_prefix)) return null;
                s = s[self.localpart_claim_prefix.len..];
                if (s.len == 0) return null;
            }
            if (std.mem.indexOfScalar(u8, s, '@')) |at| {
                const domain = s[at + 1 ..];
                if (self.user_domain) |dom| {
                    if (!std.mem.eql(u8, domain, dom)) return null;
                }
                return s[0..at];
            }
            return s;
        }

        /// Bare-JID probe prefix for a localpart: "lp@dom" with a
        /// configured domain, else "lp@".
        fn barePrefix(self: *Self, buf: *[512]u8, localpart: []const u8) ![]const u8 {
            const dom_len = if (self.user_domain) |d| d.len else 0;
            if (localpart.len + 1 + dom_len > buf.len) return error.DomainTooLong;
            var len: usize = 0;
            @memcpy(buf[0..localpart.len], localpart);
            len += localpart.len;
            buf[len] = '@';
            len += 1;
            if (self.user_domain) |dom| {
                @memcpy(buf[len..][0..dom.len], dom);
                len += dom.len;
            }
            return buf[0..len];
        }

        /// Any namespace row owned by the localpart in the op or archive
        /// envs. Missing envs are no data; errors propagate so a storage
        /// failure never allows a claim.
        fn accountHasData(self: *Self, allocator: std.mem.Allocator, localpart: []const u8) !bool {
            _ = allocator;
            var pbuf: [512]u8 = undefined;
            const bare = try self.barePrefix(&pbuf, localpart);

            if (self.op_backend) |op| {
                const probe_nss = [_][]const u8{ ROSTERS_NS, OFFLINE_NS, VCARDS_NS, LASTACT_NS, PEP_NS, BLOCKLIST_NS, PENDING_SUB_NS };
                for (probe_nss) |ns| {
                    if (try hasPrefixRow(op, ns, bare)) return true;
                }
                switch (try self.roomAffiliationScan(op, bare)) {
                    .hit => return true,
                    .none => {},
                    .capped => {
                        log.warn("oidc: room_affiliations scan hit the {d}-row cap for '{s}'; refusing auto-claim, use xmppctl oidc-link", .{ self.room_scan_limit, bare });
                        return true;
                    },
                }
            }
            if (self.archive_backend) |arch| {
                if (try hasPrefixRow(arch, MESSAGES_NS, bare)) return true;
                if (try hasPrefixRow(arch, BY_CONTACT_NS, bare)) return true;
            }
            return false;
        }

        const AffilScan = enum { none, hit, capped };

        /// room_affiliations keys are room\x00member_bare_jid, so a member
        /// lookup needs a suffix match over the whole table, bounded by
        /// room_scan_limit rows.
        fn roomAffiliationScan(self: *Self, op: *Backend, bare: []const u8) !AffilScan {
            var suffix_buf: [512]u8 = undefined;
            suffix_buf[0] = 0;
            @memcpy(suffix_buf[1..][0..bare.len], bare);
            const suffix = suffix_buf[0 .. 1 + bare.len];

            var it = try op.iterator(ROOM_AFFIL_NS, "");
            defer it.deinit();
            var scanned: u32 = 0;
            while (it.next()) |entry| {
                scanned += 1;
                if (scanned > self.room_scan_limit) return .capped;
                if (std.mem.endsWith(u8, entry.key, suffix)) return .hit;
            }
            return .none;
        }
    };
}

fn hasPrefixRow(backend: anytype, ns: []const u8, prefix: []const u8) !bool {
    var it = try backend.iterator(ns, prefix);
    defer it.deinit();
    return it.next() != null;
}

/// Suffix candidate "base-N" for N in 2..99, bounded by the localpart cap.
fn suffixCandidate(base: []const u8, buf: *[max_localpart_len]u8, n: usize) ?usize {
    var nb: [8]u8 = undefined;
    const num = std.fmt.bufPrint(&nb, "-{d}", .{n}) catch return null;
    if (base.len + num.len > max_localpart_len) return null;
    var len: usize = 0;
    for (base) |ch| {
        const lower = std.ascii.toLower(ch);
        const ok = switch (lower) {
            'a'...'z', '0'...'9', '.', '_', '-' => true,
            else => false,
        };
        if (!ok) return null;
        buf[len] = lower;
        len += 1;
    }
    @memcpy(buf[len..][0..num.len], num);
    return len + num.len;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const lmdb_backend_mod = @import("lmdb_backend");

test "key and value codecs round-trip" {
    var kbuf: [512]u8 = undefined;
    var vbuf: [512]u8 = undefined;

    const fk = try forwardKey(&kbuf, "https://idp.example", "sub-123");
    try testing.expectEqualStrings("s", fk[0..1]);
    const rk = try reverseKey(&kbuf, "alice");
    try testing.expectEqualStrings("lalice", rk);

    const rv = try encodeRevValue(&vbuf, "https://idp.example", "sub-123", .operator, 42);
    const d = try decodeRevValue(rv);
    try testing.expectEqualStrings("https://idp.example", d.iss);
    try testing.expectEqualStrings("sub-123", d.sub);
    try testing.expectEqual(Source.operator, d.source);
    try testing.expectEqual(@as(i64, 42), d.bound_at);

    try testing.expectError(error.IssuerTooLong, forwardKey(&kbuf, &[_]u8{'x'} ** 200, "s"));
    try testing.expectError(error.SubjectTooLong, forwardKey(&kbuf, "i", &[_]u8{'x'} ** 300));
    try testing.expectError(error.SubjectTooLong, forwardKey(&kbuf, "i", ""));
    try testing.expectError(error.LocalpartTooLong, reverseKey(&kbuf, ""));
    try testing.expectError(error.CorruptRow, decodeRevValue("ab"));
}

const MemStore = Store(backend_mod.MemoryBackend);
const MemResolver = Resolver(backend_mod.MemoryBackend, backend_mod.MemoryBackend);

fn memResolver(auth: *backend_mod.MemoryBackend, op: *backend_mod.MemoryBackend, arch: *backend_mod.MemoryBackend) MemResolver {
    return .{
        .store = MemStore.init(auth),
        .op_backend = op,
        .archive_backend = arch,
        .user_domain = "morante.dev",
    };
}

test "Resolver: first login binds, rename keeps the account" {
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try backend_mod.MemoryBackend.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();
    var r = memResolver(&auth, &op, &arch);

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    const out1 = try r.resolve(testing.allocator, "https://idp.example", "sub-1", "Alice", &lp, &len);
    try testing.expectEqual(out1, Resolution{ .bound = 5 });
    try testing.expectEqualStrings("alice", lp[0..len]);

    // The IdP renames preferred_username: the binding still wins.
    const out2 = try r.resolve(testing.allocator, "https://idp.example", "sub-1", "mallory", &lp, &len);
    try testing.expectEqual(out2, Resolution{ .bound = 5 });
    try testing.expectEqualStrings("alice", lp[0..len]);

    // Reverse row decodes.
    const rev = (try r.store.lookupLocalpart(testing.allocator, "alice")).?;
    defer testing.allocator.free(rev.value);
    try testing.expectEqualStrings("sub-1", rev.sub);
    try testing.expectEqual(Source.auto, rev.source);
}

test "Resolver: second subject with a taken suggestion is refused" {
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try backend_mod.MemoryBackend.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();
    var r = memResolver(&auth, &op, &arch);

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    _ = try r.resolve(testing.allocator, "https://idp.example", "sub-1", "alice", &lp, &len);
    const out = try r.resolve(testing.allocator, "https://idp.example", "sub-2", "alice", &lp, &len);
    try testing.expectEqual(out, Resolution{ .refused = .localpart_taken });
}

test "Resolver: existing users row blocks auto-claim" {
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try backend_mod.MemoryBackend.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();
    try auth.put(USERS_NS, "alice", "creds");
    var r = memResolver(&auth, &op, &arch);

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    const out = try r.resolve(testing.allocator, "https://idp.example", "sub-1", "alice", &lp, &len);
    try testing.expectEqual(out, Resolution{ .refused = .local_account });
}

test "Resolver: existing account data blocks auto-claim" {
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try backend_mod.MemoryBackend.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();
    try op.put(ROSTERS_NS, "alice@morante.dev\x00bob@morante.dev", "{}");
    var r = memResolver(&auth, &op, &arch);

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    const out = try r.resolve(testing.allocator, "https://idp.example", "sub-1", "alice", &lp, &len);
    try testing.expectEqual(out, Resolution{ .refused = .unclaimed_data });
}

test "Resolver: room_affiliations cap refuses with data" {
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try backend_mod.MemoryBackend.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();
    var r = memResolver(&auth, &op, &arch);
    r.room_scan_limit = 2;
    try op.put(ROOM_AFFIL_NS, "room1\x00m@x", "owner");
    try op.put(ROOM_AFFIL_NS, "room2\x00m@x", "owner");
    try op.put(ROOM_AFFIL_NS, "room3\x00alice@morante.dev", "member");

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    const out = try r.resolve(testing.allocator, "https://idp.example", "sub-1", "alice", &lp, &len);
    try testing.expectEqual(out, Resolution{ .refused = .unclaimed_data });
}

test "Resolver: suggestion prefix and domain rules" {
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try backend_mod.MemoryBackend.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();
    var r = memResolver(&auth, &op, &arch);
    r.localpart_claim_prefix = "user:";

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    const out = try r.resolve(testing.allocator, "https://idp.example", "sub-1", "user:Alice", &lp, &len);
    try testing.expectEqual(out, Resolution{ .bound = 5 });
    try testing.expectEqualStrings("alice", lp[0..len]);

    // Missing prefix is not a usable suggestion.
    const bad = try r.resolve(testing.allocator, "https://idp.example", "sub-2", "alice", &lp, &len);
    try testing.expectEqual(bad, Resolution{ .refused = .no_suggestion });

    // Foreign domain is rejected.
    const foreign = try r.resolve(testing.allocator, "https://idp.example", "sub-3", "user:eve@evil.example", &lp, &len);
    try testing.expectEqual(foreign, Resolution{ .refused = .no_suggestion });
}

test "Resolver: operator bind wins over later auto claims" {
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try backend_mod.MemoryBackend.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();
    var r = memResolver(&auth, &op, &arch);

    const claimed = try r.store.bind("https://idp.example", "sub-9", "legacy-acct", .operator, 1);
    try testing.expectEqual(Store(backend_mod.MemoryBackend).Claimed.bound, claimed);

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    const out = try r.resolve(testing.allocator, "https://idp.example", "sub-9", "whatever", &lp, &len);
    try testing.expectEqual(out, Resolution{ .bound = 11 });
    try testing.expectEqualStrings("legacy-acct", lp[0..len]);

    // unbind frees the localpart for a new subject.
    try testing.expect(try r.store.unbind(testing.allocator, "legacy-acct"));
    const out2 = try r.resolve(testing.allocator, "https://idp.example", "sub-10", "legacy-acct", &lp, &len);
    try testing.expectEqual(out2, Resolution{ .bound = 11 });
}

test "Resolver: two subjects claiming one localpart bind exactly once" {
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try backend_mod.MemoryBackend.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();
    var r = memResolver(&auth, &op, &arch);

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    // Serialized putIfAbsent claims: two subjects, one localpart.
    const o1 = try r.resolve(testing.allocator, "https://idp.example", "s1", "race", &lp, &len);
    const o2 = try r.resolve(testing.allocator, "https://idp.example", "s2", "race", &lp, &len);
    const results = [_]Resolution{ o1, o2 };
    var bound: usize = 0;
    var refused: usize = 0;
    for (results) |o| switch (o) {
        .bound => bound += 1,
        .refused => |why| {
            refused += 1;
            try testing.expectEqual(Refusal.localpart_taken, why);
        },
        .unavailable => {},
    };
    try testing.expectEqual(@as(usize, 1), bound);
    try testing.expectEqual(@as(usize, 1), refused);
}

test "Resolver: auto_suffix finds a free candidate" {
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try backend_mod.MemoryBackend.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();
    var r = memResolver(&auth, &op, &arch);
    r.auto_suffix = true;

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    _ = try r.resolve(testing.allocator, "https://idp.example", "s1", "alice", &lp, &len);
    const out = try r.resolve(testing.allocator, "https://idp.example", "s2", "alice", &lp, &len);
    try testing.expectEqual(out, Resolution{ .bound = 7 });
    try testing.expectEqualStrings("alice-2", lp[0..len]);
}

test "Resolver: concurrent first logins for one localpart bind exactly one" {
    // LMDB serializes write transactions, so four subjects racing for the
    // same suggestion end with exactly one binding.
    const Lmdb = lmdb_backend_mod.Backend;
    const path = "/tmp/xmppd-test-oidcb-race";
    std.fs.cwd().deleteTree(path) catch {};
    defer std.fs.cwd().deleteTree(path) catch {};
    try std.fs.cwd().makePath(path);

    var auth = try Lmdb.open(path, .{ .create = false, .map_size = 16 * 1024 * 1024 });
    defer auth.close();

    const R = Resolver(Lmdb, Lmdb);
    const Ctx = struct {
        auth: *Lmdb,
        sub: []const u8,
        out: *Resolution,
        lp: *[max_localpart_len]u8,
    };
    const worker = struct {
        fn run(ctx: Ctx) void {
            var r = R{ .store = Store(Lmdb).init(ctx.auth), .user_domain = "morante.dev" };
            var len: usize = 0;
            ctx.out.* = r.resolve(std.heap.c_allocator, "https://idp.example", ctx.sub, "race", ctx.lp, &len) catch .unavailable;
        }
    }.run;

    const threads_n = 4;
    var results: [threads_n]Resolution = undefined;
    var lp_bufs: [threads_n][max_localpart_len]u8 = undefined;
    var threads: [threads_n]std.Thread = undefined;
    var subs: [threads_n][]const u8 = undefined;
    defer for (subs) |s| std.heap.c_allocator.free(s);
    for (0..threads_n) |i| {
        subs[i] = std.fmt.allocPrint(std.heap.c_allocator, "sub-{d}", .{i}) catch unreachable;
    }

    var spawned: usize = 0;
    for (0..threads_n) |i| {
        threads[i] = std.Thread.spawn(.{}, worker, .{Ctx{
            .auth = &auth,
            .sub = subs[i],
            .out = &results[i],
            .lp = &lp_bufs[i],
        }}) catch break;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    var bound: usize = 0;
    for (results[0..spawned]) |o| switch (o) {
        .bound => bound += 1,
        .refused => |why| try testing.expectEqual(Refusal.localpart_taken, why),
        .unavailable => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(usize, 1), bound);

    // Exactly one reverse row exists.
    var it = try Store(Lmdb).init(&auth).iterateBindings();
    defer it.deinit();
    var rows: usize = 0;
    while (try it.next()) |_| rows += 1;
    try testing.expectEqual(@as(usize, 1), rows);
}

/// Records every write op's namespace; the daemon-facing API may only
/// ever write oidc_identities rows through the store.
const WriteSpy = struct {
    inner: backend_mod.MemoryBackend,
    writes: std.ArrayListUnmanaged([]const u8) = .empty,

    const Self = @This();

    pub fn open(path: []const u8, opts: backend_mod.OpenOptions) !Self {
        return .{ .inner = try backend_mod.MemoryBackend.open(path, opts) };
    }
    pub fn close(self: *Self) void {
        self.writes.deinit(std.testing.allocator);
        self.inner.close();
    }
    pub fn get(self: *Self, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        return self.inner.get(allocator, ns, key);
    }
    fn note(self: *Self, ns: []const u8) void {
        // Namespace args are comptime-registered constants; borrow them.
        self.writes.append(std.testing.allocator, ns) catch unreachable;
    }
    pub fn put(self: *Self, ns: []const u8, key: []const u8, value: []const u8) !void {
        self.note(ns);
        return self.inner.put(ns, key, value);
    }
    pub fn delete(self: *Self, ns: []const u8, key: []const u8) !void {
        self.note(ns);
        return self.inner.delete(ns, key);
    }
    pub const Iterator = backend_mod.MemoryBackend.Iterator;
    pub fn iterator(self: *Self, ns: []const u8, prefix: []const u8) !Iterator {
        return self.inner.iterator(ns, prefix);
    }
    pub const WriteBatch = struct {
        owner: *Self,
        inner: backend_mod.MemoryBackend.WriteBatch,
        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            self.owner.note(ns);
            return self.inner.put(ns, key, value);
        }
        pub fn putIfAbsent(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            self.owner.note(ns);
            return self.inner.putIfAbsent(ns, key, value);
        }
        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            self.owner.note(ns);
            return self.inner.delete(ns, key);
        }
        pub fn commit(self: *WriteBatch) !void {
            return self.inner.commit();
        }
        pub fn abort(self: *WriteBatch) void {
            return self.inner.abort();
        }
    };
    pub fn writeBatch(self: *Self) !WriteBatch {
        return .{ .owner = self, .inner = try self.inner.writeBatch() };
    }
};

test "write surface: every store write targets only oidc_identities" {
    var auth = try WriteSpy.open("", .{});
    defer auth.close();
    var op = try WriteSpy.open("", .{});
    defer op.close();
    var arch = try backend_mod.MemoryBackend.open("", .{});
    defer arch.close();

    var r = Resolver(WriteSpy, backend_mod.MemoryBackend){
        .store = Store(WriteSpy).init(&auth),
        .op_backend = &op,
        .archive_backend = &arch,
        .user_domain = "morante.dev",
    };

    var lp: [max_localpart_len]u8 = undefined;
    var len: usize = 0;
    _ = try r.resolve(testing.allocator, "https://idp.example", "sub-1", "alice", &lp, &len);
    _ = try r.store.bind("https://idp.example", "sub-2", "bob", .operator, 1);
    _ = try r.store.unbind(testing.allocator, "bob");

    for (auth.writes.items) |ns| {
        try testing.expectEqualStrings(NAMESPACE, ns);
    }
}
