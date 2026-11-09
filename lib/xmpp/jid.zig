const std = @import("std");

/// A parsed XMPP JID (Jabber ID).
///
/// Format: [localpart@]domainpart[/resourcepart]
///
/// Examples:
/// - alice@example.com
/// - alice@example.com/mobile
/// - example.com
/// - example.com/resource
pub const Jid = struct {
    /// The localpart (before @). Empty if bare domain JID.
    local: []const u8 = "",
    /// The domain part (required).
    domain: []const u8 = "",
    /// The resource part (after /). Empty if bare JID.
    resource: []const u8 = "",

    /// Parse a JID string into its components.
    /// Returns error if the JID is malformed.
    pub fn parse(input: []const u8) !Jid {
        if (input.len == 0) return error.EmptyJid;

        var local: []const u8 = "";
        var domain: []const u8 = "";
        var resource: []const u8 = "";

        // Find @ and / positions
        const at_pos = std.mem.indexOfScalar(u8, input, '@');
        const slash_pos = std.mem.indexOfScalar(u8, input, '/');

        if (at_pos) |at| {
            // Has localpart
            if (at == 0) return error.EmptyLocalpart;
            local = input[0..at];

            if (slash_pos) |slash| {
                if (slash <= at) return error.InvalidJid;
                domain = input[at + 1 .. slash];
                if (slash + 1 < input.len) {
                    resource = input[slash + 1 ..];
                }
            } else {
                domain = input[at + 1 ..];
            }
        } else {
            // No localpart — domain only
            if (slash_pos) |slash| {
                domain = input[0..slash];
                if (slash + 1 < input.len) {
                    resource = input[slash + 1 ..];
                }
            } else {
                domain = input;
            }
        }

        if (domain.len == 0) return error.EmptyDomain;

        // Validate characters (ASCII subset for MVP)
        if (!isValidLocal(local)) return error.InvalidLocalpart;
        if (!isValidDomain(domain)) return error.InvalidDomain;
        if (!isValidResource(resource)) return error.InvalidResource;

        return Jid{
            .local = local,
            .domain = domain,
            .resource = resource,
        };
    }

    /// Returns the bare JID (without resource part).
    pub fn bare(self: Jid) Jid {
        return Jid{
            .local = self.local,
            .domain = self.domain,
            .resource = "",
        };
    }

    /// Returns true if this JID has a resource part.
    pub fn isFull(self: Jid) bool {
        return self.resource.len > 0;
    }

    /// Returns true if this JID has a localpart.
    pub fn hasLocal(self: Jid) bool {
        return self.local.len > 0;
    }

    /// Format the JID as a string into a buffer.
    pub fn format(self: Jid, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        if (self.local.len > 0) {
            try writer.writeAll(self.local);
            try writer.writeByte('@');
        }
        try writer.writeAll(self.domain);
        if (self.resource.len > 0) {
            try writer.writeByte('/');
            try writer.writeAll(self.resource);
        }

        return fbs.getWritten();
    }

    /// Check equality between two JIDs.
    pub fn eql(self: Jid, other: Jid) bool {
        return std.mem.eql(u8, self.local, other.local) and
            std.mem.eql(u8, self.domain, other.domain) and
            std.mem.eql(u8, self.resource, other.resource);
    }

    /// Check equality of bare JIDs (ignoring resource).
    pub fn bareEql(self: Jid, other: Jid) bool {
        return std.mem.eql(u8, self.local, other.local) and
            std.mem.eql(u8, self.domain, other.domain);
    }

    /// Compute a hash for use in hash maps.
    pub fn hash(self: Jid) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.local);
        hasher.update("@");
        hasher.update(self.domain);
        hasher.update("/");
        hasher.update(self.resource);
        return hasher.final();
    }
};

/// RFC 7622 section 3.1: an XMPP JID must not exceed 3071 octets and each
/// part (localpart, domainpart, resourcepart) must not exceed 1023 octets.
pub const max_jid_octets = 3071;
pub const max_part_octets = 1023;

/// Errors from prepareLocalDomainJid. Ingress call sites map every one to a
/// jid-malformed stanza error.
pub const PrepareError = error{
    EmptyJid,
    EmptyLocalpart,
    EmptyDomain,
    InvalidJid,
    JidTooLong,
    NoSpaceLeft,
};

const Parts = struct {
    local: []const u8,
    domain: []const u8,
    resource: []const u8,
};

/// Split a JID into its three parts. The resource is cut at the FIRST '/',
/// then the localpart at '@' inside the bare form: "host/res@other" must
/// parse domain=host (a resource may carry '@'). A second '@' inside the
/// bare form is structural garbage, never part of a domain. Character
/// classes are deliberately unchecked here; that validation is the PRECIS
/// profile's job and the legacy ASCII validator must not run ahead of it.
fn parseParts(raw: []const u8) PrepareError!Parts {
    if (raw.len == 0) return error.EmptyJid;
    if (raw.len > max_jid_octets) return error.JidTooLong;

    var head = raw;
    var resource: []const u8 = "";
    if (std.mem.indexOfScalar(u8, raw, '/')) |slash| {
        head = raw[0..slash];
        resource = raw[slash + 1 ..];
    }

    var local: []const u8 = "";
    var domain = head;
    if (std.mem.indexOfScalar(u8, head, '@')) |at| {
        if (at == 0) return error.EmptyLocalpart;
        local = head[0..at];
        domain = head[at + 1 ..];
        if (std.mem.indexOfScalar(u8, domain, '@') != null) return error.InvalidJid;
    }
    if (domain.len == 0) return error.EmptyDomain;
    if (local.len > max_part_octets or domain.len > max_part_octets or
        resource.len > max_part_octets)
    {
        return error.JidTooLong;
    }
    return .{ .local = local, .domain = domain, .resource = resource };
}

/// The account fold every local identity shares today: ASCII lowercase,
/// with U+212A KELVIN SIGN folded to "k". This is the single seam the
/// RFC 7622 localpart preparation replaces when lib/precis lands; until
/// then it must stay byte-identical to src/store/lock_store.zig
/// canonicalKey so keys built here match the lock store, the admission
/// policy and migrate-precis.
pub fn foldLocalpart(local: []const u8, out: []u8) error{NoSpaceLeft}![]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < local.len) {
        if (i + 3 <= local.len and local[i] == 0xE2 and local[i + 1] == 0x84 and local[i + 2] == 0xAA) {
            if (n >= out.len) return error.NoSpaceLeft;
            out[n] = 'k';
            i += 3;
        } else {
            if (n >= out.len) return error.NoSpaceLeft;
            out[n] = std.ascii.toLower(local[i]);
            i += 1;
        }
        n += 1;
    }
    return out[0..n];
}

/// Prepare one JID at ingress for the hosted account domain (F6). When the
/// domain equals `configured_domain` case-insensitively, the domain is
/// rewritten to the configured spelling; with a localpart present the
/// localpart is also folded, so "NaplesTB@US.EXAMPLE" becomes
/// "naplestb@us.example" and can never build keys that delivery or
/// migrate-precis fail to match. Remote-domain JIDs are returned as `raw`,
/// unchanged; the resource is preserved. `out` must not alias `raw`.
///
/// One trailing dot on the domainpart is ignored for the match (RFC 7622
/// 3.2), so "user@localhost." names the hosted domain; an unmatched remote
/// domain keeps its raw spelling, dot included.
///
/// The MUC domain gets no special handling: callers pass the account
/// domain, so room names and the conference host pass through untouched.
pub fn prepareLocalDomainJid(raw: []const u8, configured_domain: []const u8, out: []u8) PrepareError![]const u8 {
    const parts = try parseParts(raw);
    var domain = parts.domain;
    if (std.mem.endsWith(u8, domain, ".")) domain = domain[0 .. domain.len - 1];
    if (!std.ascii.eqlIgnoreCase(domain, configured_domain)) return raw;

    var pos: usize = 0;
    if (parts.local.len > 0) {
        const folded = try foldLocalpart(parts.local, out);
        pos = folded.len;
        if (pos >= out.len) return error.NoSpaceLeft;
        out[pos] = '@';
        pos += 1;
    }
    const tail_len = configured_domain.len + (if (parts.resource.len > 0) 1 + parts.resource.len else 0);
    if (pos + tail_len > out.len) return error.NoSpaceLeft;
    @memcpy(out[pos..][0..configured_domain.len], configured_domain);
    pos += configured_domain.len;
    if (parts.resource.len > 0) {
        out[pos] = '/';
        pos += 1;
        @memcpy(out[pos..][0..parts.resource.len], parts.resource);
        pos += parts.resource.len;
    }
    return out[0..pos];
}

/// Validate localpart characters (ASCII subset for MVP).
/// Per RFC 7622, localpart is a UTF-8 string processed by PRECIS UsernameCaseMapped.
/// For MVP, we allow: letters, digits, and common punctuation.
fn isValidLocal(s: []const u8) bool {
    if (s.len == 0) return true; // Empty is valid (means no localpart)
    if (s.len > 1023) return false;

    for (s) |c| {
        if (!isLocalChar(c)) return false;
    }
    return true;
}

fn isLocalChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '.', '-', '_', '+', '~' => true,
        else => false,
    };
}

/// Validate domain characters.
fn isValidDomain(s: []const u8) bool {
    if (s.len == 0) return false;
    if (s.len > 1023) return false;

    for (s) |c| {
        if (!isDomainChar(c)) return false;
    }
    return true;
}

fn isDomainChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '.', '-', '[', ']', ':' => true, // Allow IPv6 bracket notation
        else => false,
    };
}

/// Validate resource characters. Resource is more permissive.
fn isValidResource(s: []const u8) bool {
    if (s.len == 0) return true; // Empty is valid (means no resource)
    if (s.len > 1023) return false;

    // Resources can contain most characters except control chars
    for (s) |c| {
        if (c < 0x20) return false;
    }
    return true;
}

// --- Tests ---

test "parse full JID" {
    const jid = try Jid.parse("alice@example.com/mobile");
    try std.testing.expectEqualStrings("alice", jid.local);
    try std.testing.expectEqualStrings("example.com", jid.domain);
    try std.testing.expectEqualStrings("mobile", jid.resource);
    try std.testing.expect(jid.isFull());
    try std.testing.expect(jid.hasLocal());
}

test "parse bare JID" {
    const jid = try Jid.parse("bob@example.com");
    try std.testing.expectEqualStrings("bob", jid.local);
    try std.testing.expectEqualStrings("example.com", jid.domain);
    try std.testing.expectEqualStrings("", jid.resource);
    try std.testing.expect(!jid.isFull());
}

test "parse domain-only JID" {
    const jid = try Jid.parse("example.com");
    try std.testing.expectEqualStrings("", jid.local);
    try std.testing.expectEqualStrings("example.com", jid.domain);
    try std.testing.expect(!jid.hasLocal());
}

test "parse domain with resource" {
    const jid = try Jid.parse("conference.example.com/room1");
    try std.testing.expectEqualStrings("", jid.local);
    try std.testing.expectEqualStrings("conference.example.com", jid.domain);
    try std.testing.expectEqualStrings("room1", jid.resource);
}

test "JID equality" {
    const jid1 = try Jid.parse("alice@example.com/mobile");
    const jid2 = try Jid.parse("alice@example.com/mobile");
    const jid3 = try Jid.parse("alice@example.com/desktop");

    try std.testing.expect(jid1.eql(jid2));
    try std.testing.expect(!jid1.eql(jid3));
    try std.testing.expect(jid1.bareEql(jid3));
}

test "JID bare extraction" {
    const full = try Jid.parse("alice@example.com/mobile");
    const bare_jid = full.bare();
    try std.testing.expectEqualStrings("alice", bare_jid.local);
    try std.testing.expectEqualStrings("example.com", bare_jid.domain);
    try std.testing.expectEqualStrings("", bare_jid.resource);
}

test "JID format" {
    const jid = try Jid.parse("alice@example.com/mobile");
    var buf: [256]u8 = undefined;
    const formatted = try jid.format(&buf);
    try std.testing.expectEqualStrings("alice@example.com/mobile", formatted);
}

test "JID format bare" {
    const jid = try Jid.parse("alice@example.com");
    var buf: [256]u8 = undefined;
    const formatted = try jid.format(&buf);
    try std.testing.expectEqualStrings("alice@example.com", formatted);
}

test "JID format domain-only" {
    const jid = try Jid.parse("example.com");
    var buf: [256]u8 = undefined;
    const formatted = try jid.format(&buf);
    try std.testing.expectEqualStrings("example.com", formatted);
}

test "invalid JIDs" {
    try std.testing.expectError(error.EmptyJid, Jid.parse(""));
    try std.testing.expectError(error.EmptyLocalpart, Jid.parse("@example.com"));
    try std.testing.expectError(error.InvalidLocalpart, Jid.parse("al ice@example.com"));
    try std.testing.expectError(error.InvalidDomain, Jid.parse("alice@exam ple.com"));
}

test "JID hash" {
    const jid1 = try Jid.parse("alice@example.com/mobile");
    const jid2 = try Jid.parse("alice@example.com/mobile");
    const jid3 = try Jid.parse("bob@example.com");

    try std.testing.expectEqual(jid1.hash(), jid2.hash());
    try std.testing.expect(jid1.hash() != jid3.hash());
}

// --- F6 ingress preparation ---

test "foldLocalpart folds ASCII case and U+212A" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("naplestb", try foldLocalpart("NaplesTB", &buf));
    try std.testing.expectEqualStrings("kate", try foldLocalpart("Kate", &buf));
    // U+212A KELVIN SIGN folds to "k", matching lock_store.canonicalKey.
    try std.testing.expectEqualStrings("kate", try foldLocalpart("\xE2\x84\xAAate", &buf));
    // Non-ASCII beyond the Kelvin fold passes through byte-identical today;
    // the RFC 7622 profile takes over this seam when lib/precis lands.
    try std.testing.expectEqualStrings("\xC3\xA9", try foldLocalpart("\xC3\xA9", &buf));
    try std.testing.expectError(error.NoSpaceLeft, foldLocalpart("abcd", buf[0..3]));
}

test "prepareLocalDomainJid folds local accounts to the configured spelling" {
    var out: [512]u8 = undefined;
    const got = try prepareLocalDomainJid("NaplesTB@US.EXAMPLE", "us.example", &out);
    try std.testing.expectEqualStrings("naplestb@us.example", got);

    const full = try prepareLocalDomainJid("NaplesTB@US.EXAMPLE/Phone", "us.example", &out);
    try std.testing.expectEqualStrings("naplestb@us.example/Phone", full);
}

test "prepareLocalDomainJid: remote domain and MUC-shaped JIDs pass through" {
    var out: [512]u8 = undefined;
    // A remote domain is returned as the input slice, untouched.
    const remote = "NaplesTB@Remote.Example/Res";
    const got = try prepareLocalDomainJid(remote, "us.example", &out);
    try std.testing.expect(got.ptr == remote.ptr);
    try std.testing.expectEqualStrings(remote, got);

    // Room names are never folded; the conference host is not the account
    // domain, so the whole JID passes through.
    const room = "BigRoom@conference.us.example";
    const room_got = try prepareLocalDomainJid(room, "us.example", &out);
    try std.testing.expectEqualStrings(room, room_got);
}

test "prepareLocalDomainJid strips one trailing dot on a local domain" {
    var out: [max_jid_octets]u8 = undefined;
    const got = try prepareLocalDomainJid("NaplesTB@LOCALHOST.", "localhost", &out);
    try std.testing.expectEqualStrings("naplestb@localhost", got);
    const with_res = try prepareLocalDomainJid("NaplesTB@LOCALHOST./Phone", "localhost", &out);
    try std.testing.expectEqualStrings("naplestb@localhost/Phone", with_res);
    // A remote domain keeps its trailing dot and stays a passthrough.
    const remote = "user@REMOTE.EXAMPLE.";
    const remote_got = try prepareLocalDomainJid(remote, "localhost", &out);
    try std.testing.expectEqualStrings(remote, remote_got);
    // Two trailing dots are not stripped twice; the domain is remote.
    const dots = "user@localhost..";
    const dots_got = try prepareLocalDomainJid(dots, "localhost", &out);
    try std.testing.expectEqualStrings(dots, dots_got);
}

test "prepareLocalDomainJid: domain-only local JID takes configured spelling" {
    var out: [512]u8 = undefined;
    const got = try prepareLocalDomainJid("US.EXAMPLE", "us.example", &out);
    try std.testing.expectEqualStrings("us.example", got);
}

test "prepareLocalDomainJid rejects malformed input" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.EmptyJid, prepareLocalDomainJid("", "us.example", &out));
    try std.testing.expectError(error.EmptyLocalpart, prepareLocalDomainJid("@us.example", "us.example", &out));
    try std.testing.expectError(error.EmptyDomain, prepareLocalDomainJid("alice@", "us.example", &out));
    try std.testing.expectError(error.EmptyDomain, prepareLocalDomainJid("/res", "us.example", &out));
    try std.testing.expectError(error.InvalidJid, prepareLocalDomainJid("a@b@c", "us.example", &out));

    var long_local: [1024]u8 = undefined;
    @memset(&long_local, 'a');
    var big_in: [1100]u8 = undefined;
    const in_jid = try std.fmt.bufPrint(&big_in, "{s}@x.co", .{&long_local});
    try std.testing.expectError(error.JidTooLong, prepareLocalDomainJid(in_jid, "us.example", &out));
}

test "prepareLocalDomainJid: resource may carry '@' without confusing the domain" {
    var out: [512]u8 = undefined;
    const got = try prepareLocalDomainJid("NaplesTB@US.EXAMPLE/res@other", "us.example", &out);
    try std.testing.expectEqualStrings("naplestb@us.example/res@other", got);
}
