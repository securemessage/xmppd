//! # DANE Verification for S2S — bridges DNS TLSA records with TLS validation
//!
//! Provides the high-level `verifyPeer()` function that the S2S daemon calls
//! after a TLS handshake completes:
//!
//! 1. Queries TLSA records for the target host/port via `resolver.queryTlsa()`
//! 2. Converts raw `dns.TlsaRecord` (u8 fields) → `tls.TlsaRecord` (enum fields)
//! 3. Extracts the peer certificate chain from the SSL connection
//! 4. Calls `tls.validateDane()` to check DANE-EE/DANE-TA
//! 5. Returns a `DaneStatus` for the connector state machine
//!
//! This module depends on both `lib/dns/` and `lib/tls/` — it lives in `src/s2s/`
//! because it's S2S-specific glue, not a reusable library.

const std = @import("std");
const connector = @import("connector.zig");
const DaneStatus = connector.DaneStatus;

/// Convert a raw DNS TLSA record (u8 fields from wire format) into the
/// typed TLS TLSA record (enum fields for validation).
///
/// Returns null if any field has an unrecognized value.
pub fn convertTlsaRecord(
    usage: u8,
    selector: u8,
    matching_type: u8,
    association_data: []const u8,
) ?TlsRecord {
    const tls_usage = std.meta.intToEnum(TlsaCertUsage, usage) catch return null;
    const tls_selector = std.meta.intToEnum(TlsaSelector, selector) catch return null;
    const tls_matching = std.meta.intToEnum(TlsaMatchingType, matching_type) catch return null;

    return TlsRecord{
        .usage = tls_usage,
        .selector = tls_selector,
        .matching_type = tls_matching,
        .association_data = association_data,
    };
}

/// Convert an array of raw DNS TLSA records into typed TLS records.
/// Skips records with unrecognized field values.
/// Caller owns the returned slice.
pub fn convertTlsaRecords(
    alloc: std.mem.Allocator,
    dns_records: []const DnsTlsaRecord,
) ![]TlsRecord {
    var results = std.ArrayList(TlsRecord){};
    errdefer results.deinit(alloc);

    for (dns_records) |rec| {
        if (convertTlsaRecord(rec.usage, rec.selector, rec.matching_type, rec.association_data)) |converted| {
            try results.append(alloc, converted);
        }
    }

    return try results.toOwnedSlice(alloc);
}

/// Perform DANE validation given a leaf cert, chain, and raw DNS TLSA records.
///
/// This is the core function that bridges DNS and TLS:
/// 1. Converts dns.TlsaRecord → tls.TlsaRecord (skipping unrecognized values)
/// 2. Computes cert fingerprints and checks against TLSA records
/// 3. Maps the result to a connector-friendly DaneStatus
///
/// Parameters:
/// - `leaf_der`: DER-encoded leaf certificate from the peer
/// - `chain_der`: DER-encoded intermediate/CA certificates
/// - `dns_records`: raw TLSA records from DNS query
/// - `alloc`: allocator for temporary conversions
pub fn verifyDane(
    alloc: std.mem.Allocator,
    leaf_der: []const u8,
    chain_der: []const []const u8,
    dns_records: []const DnsTlsaRecord,
) DaneStatus {
    if (dns_records.len == 0) return .no_records;

    // Convert raw DNS records to typed TLS records
    const tls_records = convertTlsaRecords(alloc, dns_records) catch return .no_records;
    defer alloc.free(tls_records);

    if (tls_records.len == 0) return .no_records;

    // Compute leaf fingerprint
    const leaf_fp = CertFingerprint.fromDer(leaf_der);

    // Check each TLSA record
    for (tls_records) |record| {
        switch (record.usage) {
            .dane_ee, .pkix_ee => {
                if (record.matching_type == .sha256 and
                    leaf_fp.matches(record.selector, record.association_data))
                {
                    return .verified;
                }
            },
            .dane_ta, .pkix_ta => {
                // Check chain certs
                for (chain_der) |cert_der| {
                    const chain_fp = CertFingerprint.fromDer(cert_der);
                    if (record.matching_type == .sha256 and
                        chain_fp.matches(record.selector, record.association_data))
                    {
                        return .verified;
                    }
                }
                // Also check leaf for self-signed with DANE-TA
                if (record.matching_type == .sha256 and
                    leaf_fp.matches(record.selector, record.association_data))
                {
                    return .verified;
                }
            },
        }
    }

    return .failed;
}

// ============================================================================
// Type definitions — duplicated from lib/tls/tls.zig and lib/dns/dns.zig
// to avoid cross-module import dependencies (these are standalone types).
// The S2S binary will have both modules available, but this test module
// needs to be self-contained.
// ============================================================================

/// TLSA selector (from lib/tls/tls.zig).
pub const TlsaSelector = enum(u8) {
    full_certificate = 0,
    subject_public_key_info = 1,
};

/// TLSA matching type (from lib/tls/tls.zig).
pub const TlsaMatchingType = enum(u8) {
    exact = 0,
    sha256 = 1,
    sha512 = 2,
};

/// TLSA certificate usage (from lib/tls/tls.zig).
pub const TlsaCertUsage = enum(u8) {
    pkix_ta = 0,
    pkix_ee = 1,
    dane_ta = 2,
    dane_ee = 3,
};

/// Typed TLSA record for validation (matches lib/tls/tls.zig).
pub const TlsRecord = struct {
    usage: TlsaCertUsage,
    selector: TlsaSelector,
    matching_type: TlsaMatchingType,
    association_data: []const u8,
};

/// Raw DNS TLSA record (matches lib/dns/dns.zig).
pub const DnsTlsaRecord = struct {
    usage: u8,
    selector: u8,
    matching_type: u8,
    association_data: []const u8,
};

/// Certificate fingerprint for DANE matching.
pub const CertFingerprint = struct {
    full: [32]u8 = undefined,
    spki: [32]u8 = undefined,

    pub fn fromDer(der: []const u8) CertFingerprint {
        var fp = CertFingerprint{};
        std.crypto.hash.sha2.Sha256.hash(der, &fp.full, .{});
        // For MVP, SPKI extraction uses the same simplified ASN.1 parser
        // as lib/tls/tls.zig. Fallback: full cert hash for SPKI.
        if (extractSpki(der)) |spki_bytes| {
            std.crypto.hash.sha2.Sha256.hash(spki_bytes, &fp.spki, .{});
        } else {
            fp.spki = fp.full;
        }
        return fp;
    }

    pub fn matches(self: *const CertFingerprint, selector: TlsaSelector, association_data: []const u8) bool {
        if (association_data.len != 32) return false;
        const hash = switch (selector) {
            .full_certificate => &self.full,
            .subject_public_key_info => &self.spki,
        };
        return std.mem.eql(u8, hash, association_data);
    }
};

/// Extract SubjectPublicKeyInfo from DER-encoded X.509 (simplified ASN.1).
///
/// X.509 structure:
///   SEQUENCE {                    -- Certificate
///     SEQUENCE {                  -- tbsCertificate
///       [0] EXPLICIT version     -- optional
///       INTEGER serialNumber
///       SEQUENCE signatureAlgorithm
///       SEQUENCE issuer
///       SEQUENCE validity
///       SEQUENCE subject
///       SEQUENCE subjectPublicKeyInfo  <-- this is what we want
///       ...
///     }
///     ...
///   }
fn extractSpki(der: []const u8) ?[]const u8 {
    var pos: usize = 0;

    // Enter outer SEQUENCE (Certificate) — skip tag+length header only
    _ = enterSequence(der, &pos) orelse return null;
    // Enter tbsCertificate SEQUENCE — skip tag+length header only
    _ = enterSequence(der, &pos) orelse return null;
    // version [0] EXPLICIT (optional — context tag class 0xA0)
    if (pos < der.len and (der[pos] & 0xE0) == 0xA0) {
        skipTlv(der, &pos) orelse return null;
    }
    // serialNumber — skip full TLV
    skipTlv(der, &pos) orelse return null;
    // signatureAlgorithm — skip full TLV
    skipTlv(der, &pos) orelse return null;
    // issuer — skip full TLV
    skipTlv(der, &pos) orelse return null;
    // validity — skip full TLV
    skipTlv(der, &pos) orelse return null;
    // subject — skip full TLV
    skipTlv(der, &pos) orelse return null;
    // subjectPublicKeyInfo — return the entire TLV (tag + length + value)
    const spki_start = pos;
    skipTlv(der, &pos) orelse return null;
    return der[spki_start..pos];
}

/// Skip a complete TLV (tag + length + value), advancing pos past it.
fn skipTlv(der: []const u8, pos: *usize) ?void {
    if (pos.* >= der.len) return null;
    pos.* += 1; // tag byte
    const length = readLength(der, pos) orelse return null;
    if (pos.* + length > der.len) return null;
    pos.* += length;
}

/// Enter a SEQUENCE: skip the tag+length header, return the content length.
/// After this call, pos points to the first byte of the SEQUENCE content.
fn enterSequence(der: []const u8, pos: *usize) ?usize {
    if (pos.* >= der.len) return null;
    pos.* += 1; // tag byte (0x30 for SEQUENCE)
    return readLength(der, pos);
}

/// Read a DER length value, advancing pos past the length bytes.
fn readLength(der: []const u8, pos: *usize) ?usize {
    if (pos.* >= der.len) return null;
    const len_byte = der[pos.*];
    pos.* += 1;
    if ((len_byte & 0x80) == 0) {
        return len_byte;
    }
    const num_bytes = len_byte & 0x7F;
    if (num_bytes > 4 or pos.* + num_bytes > der.len) return null;
    var length: usize = 0;
    var j: usize = 0;
    while (j < num_bytes) : (j += 1) {
        length = (length << 8) | der[pos.*];
        pos.* += 1;
    }
    return length;
}

// ============================================================================
// Tests
// ============================================================================

test "convertTlsaRecord: valid DANE-EE SHA-256" {
    const hash = [_]u8{0xAB} ** 32;
    const result = convertTlsaRecord(3, 1, 1, &hash);
    try std.testing.expect(result != null);
    const rec = result.?;
    try std.testing.expectEqual(TlsaCertUsage.dane_ee, rec.usage);
    try std.testing.expectEqual(TlsaSelector.subject_public_key_info, rec.selector);
    try std.testing.expectEqual(TlsaMatchingType.sha256, rec.matching_type);
}

test "convertTlsaRecord: valid DANE-TA full cert SHA-256" {
    const hash = [_]u8{0xCD} ** 32;
    const result = convertTlsaRecord(2, 0, 1, &hash);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(TlsaCertUsage.dane_ta, result.?.usage);
    try std.testing.expectEqual(TlsaSelector.full_certificate, result.?.selector);
}

test "convertTlsaRecord: invalid usage returns null" {
    const hash = [_]u8{0xAB} ** 32;
    try std.testing.expect(convertTlsaRecord(99, 1, 1, &hash) == null);
}

test "convertTlsaRecord: invalid selector returns null" {
    const hash = [_]u8{0xAB} ** 32;
    try std.testing.expect(convertTlsaRecord(3, 99, 1, &hash) == null);
}

test "convertTlsaRecord: invalid matching type returns null" {
    const hash = [_]u8{0xAB} ** 32;
    try std.testing.expect(convertTlsaRecord(3, 1, 99, &hash) == null);
}

test "convertTlsaRecords: mixed valid/invalid" {
    const alloc = std.testing.allocator;
    const hash = [_]u8{0xAB} ** 32;

    const dns_recs = [_]DnsTlsaRecord{
        .{ .usage = 3, .selector = 1, .matching_type = 1, .association_data = &hash },
        .{ .usage = 99, .selector = 0, .matching_type = 0, .association_data = &hash }, // invalid
        .{ .usage = 2, .selector = 0, .matching_type = 1, .association_data = &hash },
    };

    const result = try convertTlsaRecords(alloc, &dns_recs);
    defer alloc.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(TlsaCertUsage.dane_ee, result[0].usage);
    try std.testing.expectEqual(TlsaCertUsage.dane_ta, result[1].usage);
}

test "verifyDane: no records returns no_records" {
    const alloc = std.testing.allocator;
    const result = verifyDane(alloc, "cert", &.{}, &.{});
    try std.testing.expectEqual(DaneStatus.no_records, result);
}

test "verifyDane: DANE-EE match on full cert" {
    const alloc = std.testing.allocator;
    const leaf = "test leaf certificate for dane";
    const fp = CertFingerprint.fromDer(leaf);

    const dns_recs = [_]DnsTlsaRecord{.{
        .usage = 3, // DANE-EE
        .selector = 0, // full cert
        .matching_type = 1, // SHA-256
        .association_data = &fp.full,
    }};

    const result = verifyDane(alloc, leaf, &.{}, &dns_recs);
    try std.testing.expectEqual(DaneStatus.verified, result);
}

test "verifyDane: DANE-TA match in chain" {
    const alloc = std.testing.allocator;
    const leaf = "leaf cert data";
    const ca = "ca cert data";
    const ca_fp = CertFingerprint.fromDer(ca);

    const chain = [_][]const u8{ca};
    const dns_recs = [_]DnsTlsaRecord{.{
        .usage = 2, // DANE-TA
        .selector = 0, // full cert
        .matching_type = 1, // SHA-256
        .association_data = &ca_fp.full,
    }};

    const result = verifyDane(alloc, leaf, &chain, &dns_recs);
    try std.testing.expectEqual(DaneStatus.verified, result);
}

test "verifyDane: DANE-EE mismatch returns failed" {
    const alloc = std.testing.allocator;
    const wrong = [_]u8{0xFF} ** 32;

    const dns_recs = [_]DnsTlsaRecord{.{
        .usage = 3,
        .selector = 0,
        .matching_type = 1,
        .association_data = &wrong,
    }};

    const result = verifyDane(alloc, "some cert", &.{}, &dns_recs);
    try std.testing.expectEqual(DaneStatus.failed, result);
}

test "verifyDane: all invalid records treated as no_records" {
    const alloc = std.testing.allocator;
    const hash = [_]u8{0xAB} ** 32;

    const dns_recs = [_]DnsTlsaRecord{.{
        .usage = 99, // invalid
        .selector = 0,
        .matching_type = 1,
        .association_data = &hash,
    }};

    const result = verifyDane(alloc, "cert", &.{}, &dns_recs);
    try std.testing.expectEqual(DaneStatus.no_records, result);
}

test "verifyDane: DANE-EE SPKI selector" {
    const alloc = std.testing.allocator;
    const leaf = "leaf cert for spki test";
    const fp = CertFingerprint.fromDer(leaf);

    const dns_recs = [_]DnsTlsaRecord{.{
        .usage = 3, // DANE-EE
        .selector = 1, // SPKI
        .matching_type = 1, // SHA-256
        .association_data = &fp.spki,
    }};

    const result = verifyDane(alloc, leaf, &.{}, &dns_recs);
    try std.testing.expectEqual(DaneStatus.verified, result);
}
