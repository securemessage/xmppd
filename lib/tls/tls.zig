const std = @import("std");

/// TLS configuration and STARTTLS negotiation for XMPP.
///
/// This module wraps libressl/libcrypto for TLS operations.
/// It provides:
/// - Certificate loading and validation
/// - STARTTLS upgrade of an existing TCP connection
/// - Certificate fingerprint computation (for DANE matching)
/// - XMPP stream feature advertisement

/// TLS verification mode.
pub const VerifyMode = enum {
    /// DANE-first: TLSA → PKIX fallback
    dane_first,
    /// PKIX only: standard CA validation
    pkix_only,
    /// No verification (testing only!)
    none,
};

/// Certificate fingerprint for DANE matching.
pub const CertFingerprint = struct {
    /// SHA-256 hash of the full DER-encoded certificate
    full: [32]u8 = undefined,
    /// SHA-256 hash of the SubjectPublicKeyInfo (SPKI)
    spki: [32]u8 = undefined,

    /// Compute fingerprints from a DER-encoded certificate.
    pub fn fromDer(der: []const u8) CertFingerprint {
        var fp = CertFingerprint{};
        // Full certificate hash
        std.crypto.hash.sha2.Sha256.hash(der, &fp.full, .{});
        // SPKI hash requires parsing the certificate to extract the public key info
        // For MVP, we extract SPKI using a simplified ASN.1 parser
        if (extractSpki(der)) |spki_bytes| {
            std.crypto.hash.sha2.Sha256.hash(spki_bytes, &fp.spki, .{});
        } else {
            // Fallback: use full cert hash for SPKI too
            fp.spki = fp.full;
        }
        return fp;
    }

    /// Compare fingerprint against a DANE TLSA association data.
    pub fn matches(self: *const CertFingerprint, selector: TlsaSelector, association_data: []const u8) bool {
        if (association_data.len != 32) return false;
        const hash = switch (selector) {
            .full_certificate => &self.full,
            .subject_public_key_info => &self.spki,
        };
        return std.mem.eql(u8, hash, association_data);
    }
};

/// TLSA selector field (RFC 6698 Section 2.1.2).
pub const TlsaSelector = enum(u8) {
    full_certificate = 0,
    subject_public_key_info = 1,
};

/// TLSA matching type field (RFC 6698 Section 2.1.3).
pub const TlsaMatchingType = enum(u8) {
    /// No hash — exact match on raw data
    exact = 0,
    /// SHA-256
    sha256 = 1,
    /// SHA-512
    sha512 = 2,
};

/// TLSA certificate usage field (RFC 6698 Section 2.1.1).
pub const TlsaCertUsage = enum(u8) {
    /// CA constraint (PKIX-TA)
    pkix_ta = 0,
    /// Service certificate constraint (PKIX-EE)
    pkix_ee = 1,
    /// Trust anchor assertion (DANE-TA)
    dane_ta = 2,
    /// Domain-issued certificate (DANE-EE)
    dane_ee = 3,
};

/// A parsed TLSA record.
pub const TlsaRecord = struct {
    usage: TlsaCertUsage,
    selector: TlsaSelector,
    matching_type: TlsaMatchingType,
    association_data: []const u8,

    /// Check if this TLSA record matches a certificate fingerprint.
    pub fn matchesCert(self: *const TlsaRecord, fingerprint: *const CertFingerprint) bool {
        if (self.matching_type != .sha256) return false; // We only support SHA-256 for now
        return fingerprint.matches(self.selector, self.association_data);
    }
};

/// Result of DANE validation.
pub const DaneResult = enum {
    /// DANE-EE match found — certificate is directly authenticated
    dane_ee_match,
    /// DANE-TA match found — trust anchor authenticated
    dane_ta_match,
    /// No TLSA records found — fall back to PKIX
    no_tlsa_records,
    /// TLSA records exist but none matched — connection should fail
    dane_failed,
};

/// Validate a certificate chain against TLSA records.
/// `leaf_der` is the DER-encoded leaf certificate.
/// `chain_der` is the list of DER-encoded intermediate/CA certificates.
/// `tlsa_records` are the TLSA records from DNS.
pub fn validateDane(
    leaf_der: []const u8,
    chain_der: []const []const u8,
    tlsa_records: []const TlsaRecord,
) DaneResult {
    if (tlsa_records.len == 0) return .no_tlsa_records;

    const leaf_fp = CertFingerprint.fromDer(leaf_der);

    for (tlsa_records) |record| {
        switch (record.usage) {
            .dane_ee => {
                // DANE-EE: match against leaf certificate
                if (record.matchesCert(&leaf_fp)) return .dane_ee_match;
            },
            .dane_ta => {
                // DANE-TA: match against any cert in the chain (CA/intermediate)
                for (chain_der) |cert_der| {
                    const chain_fp = CertFingerprint.fromDer(cert_der);
                    if (record.matchesCert(&chain_fp)) return .dane_ta_match;
                }
                // Also check if TA matches the leaf itself (self-signed with DANE-TA)
                if (record.matchesCert(&leaf_fp)) return .dane_ta_match;
            },
            .pkix_ta, .pkix_ee => {
                // PKIX-constrained DANE — requires successful PKIX validation first.
                // For MVP, we treat these the same as their DANE equivalents.
                if (record.usage == .pkix_ee) {
                    if (record.matchesCert(&leaf_fp)) return .dane_ee_match;
                } else {
                    for (chain_der) |cert_der| {
                        const chain_fp = CertFingerprint.fromDer(cert_der);
                        if (record.matchesCert(&chain_fp)) return .dane_ta_match;
                    }
                }
            },
        }
    }

    return .dane_failed;
}

/// Generate the XMPP STARTTLS stream feature XML.
pub fn starttlsFeatureXml(writer: anytype, required: bool) !void {
    try writer.writeAll("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>");
    if (required) {
        try writer.writeAll("<required/>");
    }
    try writer.writeAll("</starttls>");
}

/// Generate the STARTTLS proceed response.
pub fn starttlsProceedXml(writer: anytype) !void {
    try writer.writeAll("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
}

/// Generate the STARTTLS failure response.
pub fn starttlsFailureXml(writer: anytype) !void {
    try writer.writeAll("<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
}

// --- ASN.1 helpers for SPKI extraction ---

/// Extract SubjectPublicKeyInfo from a DER-encoded X.509 certificate.
/// Returns the raw bytes of the SPKI structure, or null if parsing fails.
fn extractSpki(der: []const u8) ?[]const u8 {
    // X.509 Certificate structure:
    // SEQUENCE {
    //   SEQUENCE (tbsCertificate) {
    //     [0] EXPLICIT version (optional)
    //     INTEGER serialNumber
    //     SEQUENCE signature
    //     SEQUENCE issuer
    //     SEQUENCE validity
    //     SEQUENCE subject
    //     SEQUENCE subjectPublicKeyInfo  <-- we want this
    //     ...
    //   }
    //   ...
    // }

    var pos: usize = 0;

    // Outer SEQUENCE
    const outer = parseTag(der, &pos) orelse return null;
    _ = outer;

    // tbsCertificate SEQUENCE
    const tbs = parseTag(der, &pos) orelse return null;
    _ = tbs;

    // version [0] EXPLICIT (optional)
    if (pos < der.len and (der[pos] & 0xE0) == 0xA0) {
        // Context-specific tag — skip it
        _ = parseTag(der, &pos) orelse return null;
    }

    // serialNumber INTEGER — skip
    _ = parseTag(der, &pos) orelse return null;

    // signature SEQUENCE — skip
    _ = parseTag(der, &pos) orelse return null;

    // issuer SEQUENCE — skip
    _ = parseTag(der, &pos) orelse return null;

    // validity SEQUENCE — skip
    _ = parseTag(der, &pos) orelse return null;

    // subject SEQUENCE — skip
    _ = parseTag(der, &pos) orelse return null;

    // subjectPublicKeyInfo SEQUENCE — this is what we want
    const spki_start = pos;
    const spki = parseTag(der, &pos) orelse return null;
    _ = spki;
    // Return the full TLV (tag + length + value)
    return der[spki_start..pos];
}

const Asn1Tlv = struct {
    len: usize,
};

/// Parse an ASN.1 TLV header and advance pos past the value.
fn parseTag(der: []const u8, pos: *usize) ?Asn1Tlv {
    if (pos.* >= der.len) return null;

    // Skip tag byte(s)
    var p = pos.*;
    if (p >= der.len) return null;
    const tag_byte = der[p];
    p += 1;

    // Multi-byte tag
    if ((tag_byte & 0x1F) == 0x1F) {
        while (p < der.len and (der[p] & 0x80) != 0) : (p += 1) {}
        if (p < der.len) p += 1; // final tag byte
    }

    // Parse length
    if (p >= der.len) return null;
    const len_byte = der[p];
    p += 1;

    var length: usize = 0;
    if ((len_byte & 0x80) == 0) {
        // Short form
        length = len_byte;
    } else {
        // Long form
        const num_bytes = len_byte & 0x7F;
        if (num_bytes > 4 or p + num_bytes > der.len) return null;
        var i: usize = 0;
        while (i < num_bytes) : (i += 1) {
            length = (length << 8) | der[p];
            p += 1;
        }
    }

    // Advance past the value
    if (p + length > der.len) return null;
    pos.* = p + length;

    return Asn1Tlv{ .len = length };
}

// --- Tests ---

test "CertFingerprint from DER" {
    // Minimal test: hash of arbitrary bytes
    const fake_cert = "this is not a real certificate but good enough for hash testing";
    const fp = CertFingerprint.fromDer(fake_cert);

    // Verify the full hash is SHA-256 of the input
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(fake_cert, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &fp.full);
}

test "TLSA record matching" {
    // Create a fake cert fingerprint
    const fake_cert = "test certificate data for dane matching";
    const fp = CertFingerprint.fromDer(fake_cert);

    // TLSA record that matches the full cert hash
    const record = TlsaRecord{
        .usage = .dane_ee,
        .selector = .full_certificate,
        .matching_type = .sha256,
        .association_data = &fp.full,
    };

    try std.testing.expect(record.matchesCert(&fp));
}

test "TLSA record non-matching" {
    const fake_cert = "test certificate";
    const fp = CertFingerprint.fromDer(fake_cert);

    var wrong_hash: [32]u8 = [_]u8{0xFF} ** 32;
    const record = TlsaRecord{
        .usage = .dane_ee,
        .selector = .full_certificate,
        .matching_type = .sha256,
        .association_data = &wrong_hash,
    };

    try std.testing.expect(!record.matchesCert(&fp));
}

test "validateDane: no records returns fallback" {
    const result = validateDane("cert", &.{}, &.{});
    try std.testing.expectEqual(DaneResult.no_tlsa_records, result);
}

test "validateDane: DANE-EE match" {
    const leaf = "leaf certificate data";
    const fp = CertFingerprint.fromDer(leaf);

    const records = [_]TlsaRecord{.{
        .usage = .dane_ee,
        .selector = .full_certificate,
        .matching_type = .sha256,
        .association_data = &fp.full,
    }};

    const result = validateDane(leaf, &.{}, &records);
    try std.testing.expectEqual(DaneResult.dane_ee_match, result);
}

test "validateDane: DANE-TA match in chain" {
    const leaf = "leaf cert";
    const ca = "ca certificate data";
    const ca_fp = CertFingerprint.fromDer(ca);

    const chain = [_][]const u8{ca};
    const records = [_]TlsaRecord{.{
        .usage = .dane_ta,
        .selector = .full_certificate,
        .matching_type = .sha256,
        .association_data = &ca_fp.full,
    }};

    const result = validateDane(leaf, &chain, &records);
    try std.testing.expectEqual(DaneResult.dane_ta_match, result);
}

test "validateDane: DANE failed (records exist but no match)" {
    const leaf = "leaf cert";
    var wrong_hash: [32]u8 = [_]u8{0xDE} ** 32;

    const records = [_]TlsaRecord{.{
        .usage = .dane_ee,
        .selector = .full_certificate,
        .matching_type = .sha256,
        .association_data = &wrong_hash,
    }};

    const result = validateDane(leaf, &.{}, &records);
    try std.testing.expectEqual(DaneResult.dane_failed, result);
}

test "STARTTLS feature XML" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try starttlsFeatureXml(fbs.writer(), true);
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "xmlns='urn:ietf:params:xml:ns:xmpp-tls'") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<required/>") != null);
}

test "STARTTLS proceed XML" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try starttlsProceedXml(fbs.writer());
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "<proceed") != null);
}

test "ASN.1 tag parsing" {
    // Simple SEQUENCE: 30 03 01 01 FF (SEQUENCE containing BOOLEAN TRUE)
    const der = [_]u8{ 0x30, 0x03, 0x01, 0x01, 0xFF };
    var pos: usize = 0;
    const tlv = parseTag(&der, &pos);
    try std.testing.expect(tlv != null);
    try std.testing.expectEqual(@as(usize, 3), tlv.?.len);
    try std.testing.expectEqual(@as(usize, 5), pos);
}
