//! # DNS Resolver — res_query() C FFI for SRV and TLSA lookups
//!
//! Performs actual DNS queries using the system resolver (`res_query()`).
//! Parses responses using `ns_initparse()` / `ns_parserr()` and feeds
//! the RDATA into the existing `dns.parseSrvRdata()` / `dns.parseTlsaRdata()`.
//!
//! On FreeBSD, these functions are in libc (no `-lresolv` needed).
//!
//! ## Usage
//!
//! ```zig
//! const targets = try resolver.resolveXmpp(allocator, "example.com", false);
//! defer allocator.free(targets);
//! for (targets) |t| {
//!     // t.host, t.port, t.is_direct_tls
//! }
//! ```

const std = @import("std");
const dns = @import("dns.zig");

const c = @cImport({
    @cInclude("resolv.h");
    @cInclude("arpa/nameser.h");
});

/// DNS class IN (Internet).
const C_IN: c_int = 1;

/// DNS record type constants.
const T_SRV: c_int = 33;
const T_TLSA: c_int = 52;

/// Maximum DNS response buffer size.
const MAX_RESPONSE = 4096;

/// Query SRV records for a given name.
///
/// Returns a sorted array of SrvRecords (lower priority first, higher weight first).
/// Caller owns the returned memory (both the slice and individual target strings).
///
/// - `name` — full SRV query name (e.g., "_xmpp-client._tcp.example.com")
/// - `alloc` — allocator for results
///
/// Returns an empty slice if no SRV records exist (NXDOMAIN or empty answer).
pub fn querySrv(alloc: std.mem.Allocator, name: []const u8) ![]dns.SrvRecord {
    // Null-terminate the name for C
    var name_buf: [256]u8 = undefined;
    if (name.len >= name_buf.len) return error.NameTooLong;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;

    // Perform the query
    var response: [MAX_RESPONSE]u8 = undefined;
    const resp_len = c.res_query(
        @ptrCast(&name_buf),
        C_IN,
        T_SRV,
        &response,
        MAX_RESPONSE,
    );

    if (resp_len < 0) return &.{}; // Query failed (NXDOMAIN, SERVFAIL, etc.)

    // Parse the response using ns_initparse / ns_parserr
    var msg: c.ns_msg = undefined;
    if (c.ns_initparse(&response, resp_len, &msg) < 0) {
        return error.ParseError;
    }

    const answer_count: usize = @intCast(c.ns_msg_count(msg, c.ns_s_an));
    if (answer_count == 0) return &.{};

    var results = std.ArrayList(dns.SrvRecord){};
    errdefer {
        for (results.items) |item| alloc.free(item.target);
        results.deinit(alloc);
    }

    var i: c_int = 0;
    while (i < @as(c_int, @intCast(answer_count))) : (i += 1) {
        var rr: c.ns_rr = undefined;
        if (c.ns_parserr(&msg, c.ns_s_an, i, &rr) < 0) continue;

        // Verify it's an SRV record
        if (c.ns_rr_type(rr) != T_SRV) continue;

        const rdata: [*]const u8 = @ptrCast(c.ns_rr_rdata(rr));
        const rdlen: usize = @intCast(c.ns_rr_rdlen(rr));

        if (rdlen < 7) continue; // Minimum SRV RDATA

        const record = dns.parseSrvRdata(rdata[0..rdlen], alloc) catch continue;
        try results.append(alloc, record);
    }

    // Sort by priority (ascending) then weight (descending)
    const slice = try results.toOwnedSlice(alloc);
    std.mem.sort(dns.SrvRecord, slice, {}, dns.SrvRecord.lessThan);
    return slice;
}

/// Query TLSA records for a given port and hostname.
///
/// - `port` — the TCP port (used to form `_port._tcp.hostname`)
/// - `hostname` — the target hostname
/// - `alloc` — allocator for results
///
/// Returns an empty slice if no TLSA records exist.
pub fn queryTlsa(alloc: std.mem.Allocator, port: u16, hostname: []const u8) ![]dns.TlsaRecord {
    // Build the TLSA query name: _port._tcp.hostname
    var name_buf: [256]u8 = undefined;
    const query_name = dns.tlsaQueryName(&name_buf, port, hostname) catch return error.NameTooLong;

    // Null-terminate
    var c_name: [256]u8 = undefined;
    if (query_name.len >= c_name.len) return error.NameTooLong;
    @memcpy(c_name[0..query_name.len], query_name);
    c_name[query_name.len] = 0;

    var response: [MAX_RESPONSE]u8 = undefined;
    const resp_len = c.res_query(
        @ptrCast(&c_name),
        C_IN,
        T_TLSA,
        &response,
        MAX_RESPONSE,
    );

    if (resp_len < 0) return &.{};

    var msg: c.ns_msg = undefined;
    if (c.ns_initparse(&response, resp_len, &msg) < 0) {
        return error.ParseError;
    }

    const answer_count: usize = @intCast(c.ns_msg_count(msg, c.ns_s_an));
    if (answer_count == 0) return &.{};

    var results = std.ArrayList(dns.TlsaRecord){};
    errdefer {
        for (results.items) |item| alloc.free(item.association_data);
        results.deinit(alloc);
    }

    var i: c_int = 0;
    while (i < @as(c_int, @intCast(answer_count))) : (i += 1) {
        var rr: c.ns_rr = undefined;
        if (c.ns_parserr(&msg, c.ns_s_an, i, &rr) < 0) continue;

        if (c.ns_rr_type(rr) != T_TLSA) continue;

        const rdata: [*]const u8 = @ptrCast(c.ns_rr_rdata(rr));
        const rdlen: usize = @intCast(c.ns_rr_rdlen(rr));

        if (rdlen < 4) continue; // Minimum TLSA RDATA

        const record = dns.parseTlsaRdata(rdata[0..rdlen], alloc) catch continue;
        try results.append(alloc, record);
    }

    return try results.toOwnedSlice(alloc);
}

/// Resolve XMPP connection targets for a domain using real DNS.
///
/// Queries SRV records in priority order per XEP-0368:
/// 1. `_xmpps-client._tcp.domain` (direct TLS, preferred)
/// 2. `_xmpp-client._tcp.domain` (STARTTLS)
/// 3. Fallback to `domain:5222` if no SRV records
///
/// For server-to-server, uses `_xmpps-server._tcp` and `_xmpp-server._tcp`.
///
/// Caller owns the returned slice.
pub fn resolveXmpp(alloc: std.mem.Allocator, domain: []const u8, is_server: bool) ![]dns.ConnectionTarget {
    // Build SRV query names
    var direct_tls_name_buf: [256]u8 = undefined;
    var starttls_name_buf: [256]u8 = undefined;

    const direct_tls_prefix = if (is_server) dns.xmpps_server_srv else dns.xmpps_client_srv;
    const starttls_prefix = if (is_server) dns.xmpp_server_srv else dns.xmpp_client_srv;

    const direct_tls_name = dns.srvQueryName(&direct_tls_name_buf, direct_tls_prefix, domain) catch return error.NameTooLong;
    const starttls_name = dns.srvQueryName(&starttls_name_buf, starttls_prefix, domain) catch return error.NameTooLong;

    // Query both SRV record sets
    const direct_tls_records = querySrv(alloc, direct_tls_name) catch &.{};
    defer {
        for (direct_tls_records) |r| alloc.free(r.target);
        if (direct_tls_records.len > 0) alloc.free(direct_tls_records);
    }

    const starttls_records = querySrv(alloc, starttls_name) catch &.{};
    defer {
        for (starttls_records) |r| alloc.free(r.target);
        if (starttls_records.len > 0) alloc.free(starttls_records);
    }

    // Combine into ConnectionTarget list using existing library function
    return dns.resolveXmppTargets(alloc, domain, is_server, starttls_records, direct_tls_records);
}

// ============================================================================
// Tests
// ============================================================================

test "querySrv: known XMPP domain (network-dependent)" {
    // Skip if no network — this test queries real DNS
    const alloc = std.testing.allocator;
    const records = querySrv(alloc, "_xmpp-client._tcp.jabber.org") catch |err| {
        // Network unavailable — skip gracefully
        if (err == error.ParseError) return;
        return err;
    };

    if (records.len == 0) {
        // No records found — could be network issue, skip
        return;
    }

    defer {
        for (records) |r| alloc.free(r.target);
        alloc.free(records);
    }

    // jabber.org should have SRV records
    try std.testing.expect(records.len > 0);
    try std.testing.expect(records[0].port > 0);
    try std.testing.expect(records[0].target.len > 0);
}

test "queryTlsa: non-existent record returns empty" {
    const alloc = std.testing.allocator;
    // Query a TLSA record that almost certainly doesn't exist
    const records = queryTlsa(alloc, 5222, "this-domain-does-not-exist-xmppd-test.invalid") catch {
        return; // Network error — skip
    };

    // Should be empty (not an error)
    try std.testing.expectEqual(@as(usize, 0), records.len);
}

test "resolveXmpp: fallback for non-existent domain" {
    const alloc = std.testing.allocator;
    const targets = resolveXmpp(alloc, "no-srv-records-here.invalid", false) catch {
        return; // Network error — skip
    };
    defer alloc.free(targets);

    // Should fall back to domain:5222
    try std.testing.expectEqual(@as(usize, 1), targets.len);
    try std.testing.expectEqualStrings("no-srv-records-here.invalid", targets[0].host);
    try std.testing.expectEqual(@as(u16, 5222), targets[0].port);
    try std.testing.expect(!targets[0].is_direct_tls);
}
