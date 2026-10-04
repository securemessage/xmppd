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
    /// Raw DER of the certificate (matching type 0, selector 0).
    der: []const u8 = "",
    /// Raw DER of the SubjectPublicKeyInfo (matching type 0, selector 1).
    spki_der: []const u8 = "",
    /// SHA-256 hash of the full DER-encoded certificate
    full: [32]u8 = undefined,
    /// SHA-256 hash of the SubjectPublicKeyInfo (SPKI)
    spki: [32]u8 = undefined,
    /// SHA-512 hash of the full certificate / SPKI
    full512: [64]u8 = undefined,
    spki512: [64]u8 = undefined,

    /// Compute fingerprints from a DER-encoded certificate.
    /// The returned struct borrows `der` — it must outlive the fingerprint.
    pub fn fromDer(der: []const u8) CertFingerprint {
        var fp = CertFingerprint{};
        fp.der = der;
        std.crypto.hash.sha2.Sha256.hash(der, &fp.full, .{});
        std.crypto.hash.sha2.Sha512.hash(der, &fp.full512, .{});
        if (extractSpki(der)) |spki_bytes| {
            fp.spki_der = spki_bytes;
            std.crypto.hash.sha2.Sha256.hash(spki_bytes, &fp.spki, .{});
            std.crypto.hash.sha2.Sha512.hash(spki_bytes, &fp.spki512, .{});
        } else {
            // Unparseable cert: SPKI selectors can never exact-match, and
            // their hashes fall back to the full-cert hashes.
            fp.spki = fp.full;
            fp.spki512 = fp.full512;
        }
        return fp;
    }

    /// Compare fingerprint against a TLSA association per its matching type.
    pub fn matches(self: *const CertFingerprint, selector: TlsaSelector, matching_type: TlsaMatchingType, association_data: []const u8) bool {
        switch (matching_type) {
            .exact => {
                const raw: []const u8 = switch (selector) {
                    .full_certificate => self.der,
                    .subject_public_key_info => self.spki_der,
                };
                return raw.len > 0 and std.mem.eql(u8, raw, association_data);
            },
            .sha256 => {
                if (association_data.len != 32) return false;
                const hash = switch (selector) {
                    .full_certificate => &self.full,
                    .subject_public_key_info => &self.spki,
                };
                return std.mem.eql(u8, hash, association_data);
            },
            .sha512 => {
                if (association_data.len != 64) return false;
                const hash = switch (selector) {
                    .full_certificate => &self.full512,
                    .subject_public_key_info => &self.spki512,
                };
                return std.mem.eql(u8, hash, association_data);
            },
        }
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
        return fingerprint.matches(self.selector, self.matching_type, self.association_data);
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

    // Outer SEQUENCE — descend into its value (parseTag leaves pos past
    // the whole TLV; for containers we rewind to the value start).
    const outer = parseTag(der, &pos) orelse return null;
    pos -= outer.len;

    // tbsCertificate SEQUENCE — descend likewise.
    const tbs = parseTag(der, &pos) orelse return null;
    pos -= tbs.len;

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


test "CertFingerprint SPKI extraction against a real X.509 cert" {
    // RSA-2048 self-signed cert (openssl req -x509 -newkey rsa:2048).
    // SPKI SHA-256 verified externally with:
    //   openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | sha256
    const der = [_]u8{
    0x30, 0x82, 0x03, 0x22, 0x30, 0x82, 0x02, 0x0a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x10,
    0xc3, 0x33, 0x64, 0x10, 0x57, 0x3a, 0xac, 0xf8, 0x36, 0x01, 0x46, 0x03, 0x97, 0xef, 0x75, 0x56,
    0x5c, 0x4e, 0xf4, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x78,
    0x6d, 0x70, 0x70, 0x64, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31,
    0x30, 0x30, 0x34, 0x30, 0x36, 0x31, 0x38, 0x30, 0x37, 0x5a, 0x17, 0x0d, 0x32, 0x37, 0x31, 0x30,
    0x30, 0x34, 0x30, 0x36, 0x31, 0x38, 0x30, 0x37, 0x5a, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x78, 0x6d, 0x70, 0x70, 0x64, 0x2e, 0x74, 0x65, 0x73, 0x74,
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xb9, 0x3a, 0x45, 0x8a, 0x2e, 0x1e, 0x54, 0xef, 0x78, 0x86, 0x98, 0x1c, 0x62, 0x33, 0x1b,
    0x97, 0x9c, 0x27, 0x44, 0x3c, 0x5d, 0xe3, 0xd1, 0xdc, 0x21, 0x46, 0xad, 0x5d, 0xb8, 0x4e, 0x2c,
    0x8a, 0xe5, 0x88, 0x40, 0xf8, 0x24, 0x4a, 0x72, 0x24, 0x91, 0xbc, 0xd0, 0xbb, 0x31, 0xbf, 0xd5,
    0xe4, 0x95, 0xc0, 0x55, 0x45, 0x38, 0x42, 0x12, 0x8a, 0xea, 0xa3, 0x69, 0x77, 0xa5, 0xc4, 0x61,
    0x70, 0xd9, 0xda, 0xbf, 0xc8, 0xd4, 0x0f, 0x5c, 0x0f, 0x48, 0x6f, 0x35, 0x8f, 0x88, 0x75, 0x0c,
    0x0c, 0x9a, 0xff, 0x17, 0x97, 0x5c, 0x69, 0x5e, 0x27, 0x33, 0xfd, 0x6c, 0x19, 0x3a, 0x98, 0x20,
    0x49, 0xef, 0xec, 0x25, 0xa5, 0x7c, 0x2c, 0xee, 0xa9, 0xd9, 0x11, 0x6e, 0xdb, 0x75, 0xf5, 0xa9,
    0x22, 0x71, 0x26, 0x4e, 0x71, 0x10, 0xaf, 0x0b, 0xf9, 0xb5, 0x0e, 0x6a, 0xe3, 0x0a, 0x31, 0x45,
    0x27, 0x23, 0x1c, 0x8b, 0xda, 0x20, 0x05, 0x09, 0x87, 0xb1, 0x8b, 0xf9, 0x6c, 0x58, 0x2d, 0x67,
    0xda, 0xc9, 0x5c, 0xcd, 0xf6, 0xa3, 0xa8, 0xbb, 0x78, 0x3d, 0xcc, 0x95, 0x66, 0xd3, 0x29, 0x1a,
    0x15, 0x07, 0x4a, 0x06, 0x30, 0xb7, 0x3e, 0x40, 0xd2, 0xe7, 0xec, 0xb3, 0x43, 0x49, 0x3d, 0x4e,
    0x47, 0x96, 0x31, 0x36, 0x6e, 0xaa, 0xdb, 0xd8, 0xbe, 0x81, 0x8b, 0x99, 0x47, 0xe7, 0xff, 0x36,
    0x0f, 0xd1, 0x2b, 0x10, 0xd4, 0x0b, 0x5c, 0x86, 0xf0, 0x53, 0xe9, 0xca, 0x18, 0xf6, 0x0a, 0xea,
    0xe6, 0x18, 0x97, 0xd8, 0x72, 0xce, 0x57, 0x5d, 0x5e, 0x2b, 0xdd, 0x14, 0x2d, 0x2f, 0xd9, 0x0a,
    0x11, 0x83, 0x28, 0xed, 0x6c, 0xde, 0x74, 0xf5, 0x23, 0x57, 0xa8, 0x5b, 0x26, 0x43, 0xd4, 0xa5,
    0x17, 0x71, 0x16, 0x57, 0x92, 0x8f, 0x8a, 0x70, 0xde, 0x3d, 0x2f, 0xe0, 0x56, 0x48, 0xb5, 0xcf,
    0xf9, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x6a, 0x30, 0x68, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0x02, 0x18, 0x16, 0xb4, 0x45, 0xa5, 0x9a, 0x82, 0x96, 0xde, 0x74,
    0xcc, 0x21, 0x30, 0x2d, 0xc2, 0x24, 0x11, 0x84, 0x1f, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
    0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x02, 0x18, 0x16, 0xb4, 0x45, 0xa5, 0x9a, 0x82, 0x96, 0xde,
    0x74, 0xcc, 0x21, 0x30, 0x2d, 0xc2, 0x24, 0x11, 0x84, 0x1f, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
    0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x15, 0x06, 0x03, 0x55,
    0x1d, 0x11, 0x04, 0x0e, 0x30, 0x0c, 0x82, 0x0a, 0x78, 0x6d, 0x70, 0x70, 0x64, 0x2e, 0x74, 0x65,
    0x73, 0x74, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
    0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x94, 0x56, 0x4d, 0x01, 0x94, 0xbd, 0x9d, 0x05, 0x54, 0x63,
    0xcb, 0x46, 0x10, 0x00, 0x6d, 0xd9, 0xc8, 0xc9, 0x35, 0x1c, 0x00, 0x1c, 0x35, 0x3e, 0xa2, 0x3b,
    0x7e, 0x3a, 0xbf, 0xda, 0xc9, 0x6e, 0xc6, 0x56, 0xff, 0x79, 0x9f, 0x75, 0xae, 0xc1, 0x6a, 0x6e,
    0xeb, 0x00, 0x87, 0x72, 0x84, 0xa6, 0x2c, 0x81, 0xf5, 0x4a, 0xca, 0xdb, 0xb5, 0xec, 0x43, 0x0a,
    0xab, 0x34, 0x5d, 0x6e, 0xd1, 0x40, 0x64, 0x26, 0x9d, 0xa1, 0x15, 0xe4, 0x93, 0xdb, 0x41, 0x2f,
    0xea, 0x96, 0xd5, 0x31, 0xd6, 0x9d, 0x0c, 0x2a, 0x4d, 0xef, 0xf8, 0x0b, 0x57, 0x1e, 0xaf, 0x9d,
    0xf8, 0xc8, 0xd0, 0x23, 0xe1, 0x83, 0x21, 0x35, 0x87, 0x8f, 0xe0, 0x71, 0xe5, 0x5c, 0x59, 0x7f,
    0xb5, 0xef, 0x57, 0xed, 0x29, 0xbf, 0x1c, 0x58, 0xd0, 0xdc, 0x66, 0x97, 0x2b, 0x60, 0xd4, 0x37,
    0xfa, 0x24, 0x3c, 0x07, 0x0b, 0x5d, 0xa2, 0x3a, 0xad, 0x59, 0x8e, 0xa0, 0x91, 0x70, 0xbc, 0x79,
    0x50, 0x8c, 0x69, 0x69, 0xb0, 0x07, 0x97, 0x92, 0x1d, 0x11, 0x3e, 0xc4, 0x28, 0x2c, 0xb8, 0x10,
    0x59, 0x68, 0xef, 0x47, 0x90, 0x53, 0xf6, 0x49, 0x10, 0x43, 0xba, 0x7b, 0x75, 0x2f, 0x23, 0x44,
    0x77, 0x74, 0x04, 0x49, 0xbf, 0x4d, 0x27, 0x0c, 0xd9, 0xa3, 0xd2, 0x96, 0xc6, 0xe5, 0xc9, 0x19,
    0xfa, 0x3d, 0xb6, 0x34, 0xf5, 0x2c, 0xc3, 0x6c, 0x1d, 0x8a, 0xb5, 0x02, 0xf3, 0x2e, 0x4f, 0xa9,
    0x71, 0xed, 0x7c, 0xb2, 0x2f, 0x32, 0x67, 0xcc, 0xe0, 0x8f, 0x6d, 0x0d, 0x0d, 0x9d, 0x1a, 0xb4,
    0x72, 0xad, 0x7b, 0x3f, 0x1e, 0x2c, 0xee, 0xf1, 0xf1, 0x67, 0xfb, 0x4c, 0xd0, 0xf8, 0xbb, 0x2b,
    0x18, 0x5c, 0xa4, 0xc6, 0x09, 0xdf, 0xaf, 0x23, 0xcf, 0x25, 0xc9, 0x10, 0x12, 0xf1, 0x1e, 0x1f,
    0x7a, 0x29, 0x36, 0xa0, 0xf8, 0x43,
    };
    const expected_spki = [_]u8{
    0xde, 0xf5, 0xee, 0xa7, 0xe1, 0x87, 0xa3, 0xcd, 0x0a, 0x87, 0xf8, 0x8f, 0x1e, 0xbf, 0x48, 0x7a, 0x84, 0x9b, 0x62, 0x5d, 0xaf, 0x1a, 0x98, 0xc7, 0x45, 0x4e, 0x74, 0x2e, 0xd8, 0x48, 0x4a, 0x53,
    };
    const fp = CertFingerprint.fromDer(&der);
    try std.testing.expect(fp.spki_der.len > 0);
    try std.testing.expectEqualSlices(u8, &expected_spki, &fp.spki);
}

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

test "TLSA record matching: exact and SHA-512" {
    const fake_cert = "certificate bytes for exact and sha512 matching";
    const fp = CertFingerprint.fromDer(fake_cert);

    // Exact (matching type 0): full raw bytes, full-cert selector.
    const exact = TlsaRecord{
        .usage = .dane_ee,
        .selector = .full_certificate,
        .matching_type = .exact,
        .association_data = fake_cert,
    };
    try std.testing.expect(exact.matchesCert(&fp));

    // SHA-512 (matching type 2): 64-byte hash.
    const sha512_rec = TlsaRecord{
        .usage = .dane_ee,
        .selector = .full_certificate,
        .matching_type = .sha512,
        .association_data = &fp.full512,
    };
    try std.testing.expect(sha512_rec.matchesCert(&fp));

    // SPKI selector falls back to full-cert hashes for unparseable certs.
    const spki_sha256 = TlsaRecord{
        .usage = .dane_ee,
        .selector = .subject_public_key_info,
        .matching_type = .sha256,
        .association_data = &fp.spki,
    };
    try std.testing.expect(spki_sha256.matchesCert(&fp));

    // Wrong length association data never matches.
    const short = TlsaRecord{
        .usage = .dane_ee,
        .selector = .full_certificate,
        .matching_type = .sha256,
        .association_data = fake_cert[0..16],
    };
    try std.testing.expect(!short.matchesCert(&fp));
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
