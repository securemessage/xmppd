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
