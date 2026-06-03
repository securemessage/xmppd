const std = @import("std");
pub const resolver = @import("resolver.zig");

/// DNS record types relevant to XMPP.
pub const RecordType = enum(u16) {
    a = 1,
    aaaa = 28,
    srv = 33,
    tlsa = 52,
};

/// A parsed SRV record (RFC 2782).
pub const SrvRecord = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: []const u8,

    /// Compare for sorting: lower priority first, then higher weight first.
    pub fn lessThan(_: void, a: SrvRecord, b: SrvRecord) bool {
        if (a.priority != b.priority) return a.priority < b.priority;
        return a.weight > b.weight; // Higher weight = preferred within same priority
    }
};

/// A parsed TLSA record (RFC 6698).
pub const TlsaRecord = struct {
    /// Certificate usage (0-3)
    usage: u8,
    /// Selector (0 = full cert, 1 = SPKI)
    selector: u8,
    /// Matching type (0 = exact, 1 = SHA-256, 2 = SHA-512)
    matching_type: u8,
    /// Certificate association data (hash or raw cert)
    association_data: []const u8,
};

/// XMPP SRV record names per RFC 6120.
pub const xmpp_client_srv = "_xmpp-client._tcp";
pub const xmpp_server_srv = "_xmpp-server._tcp";
/// Direct TLS SRV records per XEP-0368.
pub const xmpps_client_srv = "_xmpps-client._tcp";
pub const xmpps_server_srv = "_xmpps-server._tcp";

/// Build the SRV query name for a domain.
/// Example: srvQueryName("_xmpp-client._tcp", "example.com") → "_xmpp-client._tcp.example.com"
pub fn srvQueryName(buf: []u8, prefix: []const u8, domain: []const u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const writer = fbs.writer();
    try writer.writeAll(prefix);
    try writer.writeByte('.');
    try writer.writeAll(domain);
    return fbs.getWritten();
}

/// Build the TLSA query name for a host and port.
/// Example: tlsaQueryName("_5222._tcp", "example.com") → "_5222._tcp.example.com"
pub fn tlsaQueryName(buf: []u8, port: u16, domain: []const u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const writer = fbs.writer();
    try std.fmt.format(writer, "_{d}._tcp.{s}", .{ port, domain });
    return fbs.getWritten();
}

/// Parse a DNS SRV record from wire format (RDATA section).
/// Wire format: priority(2) + weight(2) + port(2) + target(compressed name)
pub fn parseSrvRdata(rdata: []const u8, alloc: std.mem.Allocator) !SrvRecord {
    if (rdata.len < 7) return error.InvalidSrvRecord; // Minimum: 6 bytes header + 1 byte name

    const priority = std.mem.readInt(u16, rdata[0..2], .big);
    const weight = std.mem.readInt(u16, rdata[2..4], .big);
    const port = std.mem.readInt(u16, rdata[4..6], .big);

    // Parse the target name (uncompressed labels in RDATA)
    const target = try parseDnsName(rdata[6..], alloc);

    return SrvRecord{
        .priority = priority,
        .weight = weight,
        .port = port,
        .target = target,
    };
}

/// Parse a DNS TLSA record from wire format (RDATA section).
/// Wire format: usage(1) + selector(1) + matching_type(1) + association_data(...)
pub fn parseTlsaRdata(rdata: []const u8, alloc: std.mem.Allocator) !TlsaRecord {
    if (rdata.len < 4) return error.InvalidTlsaRecord; // Minimum: 3 header bytes + 1 data byte

    const usage = rdata[0];
    const selector = rdata[1];
    const matching_type = rdata[2];
    const association_data = try alloc.dupe(u8, rdata[3..]);

    return TlsaRecord{
        .usage = usage,
        .selector = selector,
        .matching_type = matching_type,
        .association_data = association_data,
    };
}

/// Parse a DNS name from label format into a dotted string.
/// Label format: len byte + label bytes, terminated by 0x00.
fn parseDnsName(data: []const u8, alloc: std.mem.Allocator) ![]const u8 {
    var result = std.ArrayList(u8){};
    errdefer result.deinit(alloc);
    var pos: usize = 0;

    while (pos < data.len) {
        const label_len: usize = data[pos];
        if (label_len == 0) break; // Root label
        pos += 1;

        if (pos + label_len > data.len) return error.InvalidDnsName;

        if (result.items.len > 0) {
            try result.append(alloc, '.');
        }
        try result.appendSlice(alloc, data[pos .. pos + label_len]);
        pos += label_len;
    }

    if (result.items.len == 0) {
        result.deinit(alloc);
        return try alloc.dupe(u8, ".");
    }

    const duped = try alloc.dupe(u8, result.items);
    result.deinit(alloc);
    return duped;
}

/// XMPP connection target resolved from SRV records.
pub const ConnectionTarget = struct {
    host: []const u8,
    port: u16,
    is_direct_tls: bool,
};

/// Resolve XMPP connection targets for a domain.
/// Returns targets sorted by priority/weight, with direct TLS preferred.
/// This is the high-level function that combines SRV lookups.
///
/// In a real implementation, this would call res_query(). For now,
/// it defines the interface that the daemon will use.
pub fn resolveXmppTargets(
    alloc: std.mem.Allocator,
    domain: []const u8,
    is_server: bool,
    srv_records: []const SrvRecord,
    direct_tls_records: []const SrvRecord,
) ![]ConnectionTarget {
    var targets = std.ArrayList(ConnectionTarget){};
    errdefer {
        for (targets.items) |t| alloc.free(t.host);
        targets.deinit(alloc);
    }

    // Direct TLS targets first (preferred per XEP-0368)
    for (direct_tls_records) |srv| {
        try targets.append(alloc, .{
            .host = try alloc.dupe(u8, srv.target),
            .port = srv.port,
            .is_direct_tls = true,
        });
    }

    // Then STARTTLS targets
    for (srv_records) |srv| {
        try targets.append(alloc, .{
            .host = try alloc.dupe(u8, srv.target),
            .port = srv.port,
            .is_direct_tls = false,
        });
    }

    // If no SRV records, fall back to domain with default port
    if (targets.items.len == 0) {
        const default_port: u16 = if (is_server) 5269 else 5222;
        try targets.append(alloc, .{
            .host = try alloc.dupe(u8, domain),
            .port = default_port,
            .is_direct_tls = false,
        });
    }

    return try targets.toOwnedSlice(alloc);
}

// --- Tests ---

test "srvQueryName" {
    var buf: [256]u8 = undefined;
    const name = try srvQueryName(&buf, xmpp_client_srv, "example.com");
    try std.testing.expectEqualStrings("_xmpp-client._tcp.example.com", name);
}

test "tlsaQueryName" {
    var buf: [256]u8 = undefined;
    const name = try tlsaQueryName(&buf, 5222, "xmpp.example.com");
    try std.testing.expectEqualStrings("_5222._tcp.xmpp.example.com", name);
}

test "parseSrvRdata" {
    const alloc = std.testing.allocator;
    // priority=10, weight=5, port=5222, target="xmpp.example.com"
    var rdata: [128]u8 = undefined;
    std.mem.writeInt(u16, rdata[0..2], 10, .big); // priority
    std.mem.writeInt(u16, rdata[2..4], 5, .big); // weight
    std.mem.writeInt(u16, rdata[4..6], 5222, .big); // port
    // target in label format: 4"xmpp" 7"example" 3"com" 0
    rdata[6] = 4;
    @memcpy(rdata[7..11], "xmpp");
    rdata[11] = 7;
    @memcpy(rdata[12..19], "example");
    rdata[19] = 3;
    @memcpy(rdata[20..23], "com");
    rdata[23] = 0; // root

    const srv = try parseSrvRdata(rdata[0..24], alloc);
    defer alloc.free(srv.target);

    try std.testing.expectEqual(@as(u16, 10), srv.priority);
    try std.testing.expectEqual(@as(u16, 5), srv.weight);
    try std.testing.expectEqual(@as(u16, 5222), srv.port);
    try std.testing.expectEqualStrings("xmpp.example.com", srv.target);
}

test "parseTlsaRdata" {
    const alloc = std.testing.allocator;
    // usage=3 (DANE-EE), selector=1 (SPKI), matching=1 (SHA-256), 32 bytes hash
    var rdata: [35]u8 = undefined;
    rdata[0] = 3; // DANE-EE
    rdata[1] = 1; // SPKI
    rdata[2] = 1; // SHA-256
    @memset(rdata[3..35], 0xAB); // fake hash

    const tlsa = try parseTlsaRdata(rdata[0..35], alloc);
    defer alloc.free(tlsa.association_data);

    try std.testing.expectEqual(@as(u8, 3), tlsa.usage);
    try std.testing.expectEqual(@as(u8, 1), tlsa.selector);
    try std.testing.expectEqual(@as(u8, 1), tlsa.matching_type);
    try std.testing.expectEqual(@as(usize, 32), tlsa.association_data.len);
}

test "SrvRecord sorting" {
    var records = [_]SrvRecord{
        .{ .priority = 20, .weight = 0, .port = 5222, .target = "backup.example.com" },
        .{ .priority = 10, .weight = 50, .port = 5222, .target = "primary.example.com" },
        .{ .priority = 10, .weight = 100, .port = 5222, .target = "preferred.example.com" },
    };

    std.mem.sort(SrvRecord, &records, {}, SrvRecord.lessThan);

    try std.testing.expectEqualStrings("preferred.example.com", records[0].target);
    try std.testing.expectEqualStrings("primary.example.com", records[1].target);
    try std.testing.expectEqualStrings("backup.example.com", records[2].target);
}

test "resolveXmppTargets with SRV records" {
    const alloc = std.testing.allocator;

    const srv_records = [_]SrvRecord{
        .{ .priority = 10, .weight = 0, .port = 5222, .target = "xmpp.example.com" },
    };
    const direct_tls = [_]SrvRecord{
        .{ .priority = 5, .weight = 0, .port = 5223, .target = "xmpp.example.com" },
    };

    const targets = try resolveXmppTargets(alloc, "example.com", false, &srv_records, &direct_tls);
    defer {
        for (targets) |t| alloc.free(t.host);
        alloc.free(targets);
    }

    // Direct TLS should come first
    try std.testing.expectEqual(@as(usize, 2), targets.len);
    try std.testing.expect(targets[0].is_direct_tls);
    try std.testing.expectEqual(@as(u16, 5223), targets[0].port);
    try std.testing.expect(!targets[1].is_direct_tls);
    try std.testing.expectEqual(@as(u16, 5222), targets[1].port);
}

test "resolveXmppTargets fallback" {
    const alloc = std.testing.allocator;

    const targets = try resolveXmppTargets(alloc, "example.com", false, &.{}, &.{});
    defer {
        for (targets) |t| alloc.free(t.host);
        alloc.free(targets);
    }

    try std.testing.expectEqual(@as(usize, 1), targets.len);
    try std.testing.expectEqualStrings("example.com", targets[0].host);
    try std.testing.expectEqual(@as(u16, 5222), targets[0].port);
    try std.testing.expect(!targets[0].is_direct_tls);
}

test "parseDnsName" {
    const alloc = std.testing.allocator;
    // 3"foo" 3"bar" 0
    const data = [_]u8{ 3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 0 };
    const name = try parseDnsName(&data, alloc);
    defer alloc.free(name);
    try std.testing.expectEqualStrings("foo.bar", name);
}

test {
    _ = resolver;
}
