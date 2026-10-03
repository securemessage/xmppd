//! RFC 8265 §4.2 OpaqueString preparation for SASL credentials, and the
//! RFC 5802 §5.1 SCRAM name escaping (=3D / =2C).
//!
//! OpaqueString is chosen over RFC 4013 SASLprep: it is Unicode-version
//! agnostic (no unassigned-codepoint table, the unstable part of
//! stringprep), and for printable ASCII input it is the identity, so
//! existing ASCII credentials are unaffected. Enforcement = map non-ASCII
//! spaces (Zs minus U+0020) to U+0020, normalize with NFC, then reject the
//! RFC 3454 C.2–C.9 prohibited classes.

const std = @import("std");
const tables = @import("nfc_tables.zig");

pub const PrepError = error{
    InvalidUtf8,
    ProhibitedCharacter,
    NoSpaceLeft,
};

/// Non-ASCII spaces (Zs category minus U+0020), mapped to U+0020.
fn isNonAsciiSpace(cp: u21) bool {
    return switch (cp) {
        0x00A0, 0x1680, 0x2000...0x200A, 0x202F, 0x205F, 0x3000 => true,
        else => false,
    };
}

/// RFC 3454 C.2–C.9 prohibited classes as referenced by RFC 8265 §4.2.
fn isProhibited(cp: u21) bool {
    return switch (cp) {
        // C.2 control characters (ASCII + non-ASCII)
        0x0000...0x001F, 0x007F...0x009F => true,
        0x06DD, 0x070F, 0x180E, 0x200C, 0x200D, 0x2028, 0x2029 => true,
        0x2060...0x2063, 0x206A...0x206F => true,
        0xFEFF, 0xFFF9...0xFFFB => true,
        0x1D173...0x1D17A, 0xE0001 => true,
        // C.3 private use
        0xE000...0xF8FF, 0xF0000...0xFFFFD, 0x100000...0x10FFFD => true,
        // C.4 non-character code points
        0xFDD0...0xFDEF => true,
        // C.5 surrogates (unreachable through valid UTF-8, kept for clarity)
        0xD800...0xDFFF => true,
        // C.6 inappropriate for plain text
        0xFFFC...0xFFFD => true,
        // C.7 inappropriate for canonical representation
        0x2FF0...0x2FFB => true,
        // C.8 change display properties / deprecated
        0x0340, 0x0341, 0x200E, 0x200F, 0x202A...0x202E => true,
        // C.9 tagging
        0xE0020...0xE007F => true,
        else => isPlaneNonCharacter(cp),
    };
}

/// C.4: U+nFFFE / U+nFFFF on every plane.
fn isPlaneNonCharacter(cp: u21) bool {
    const low = cp & 0xFFFF;
    return low == 0xFFFE or low == 0xFFFF;
}

fn decompFor(cp: u21) ?tables.Decomp {
    var lo: usize = 0;
    var hi: usize = tables.decomps.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        const d = tables.decomps[mid];
        if (cp < d.cp) hi = mid else if (cp > d.cp) lo = mid + 1 else return d;
    }
    return null;
}

fn cccOf(cp: u21) u8 {
    var lo: usize = 0;
    var hi: usize = tables.ccc_ranges.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        const r = tables.ccc_ranges[mid];
        if (cp < r.lo) hi = mid else if (cp > r.hi) lo = mid + 1 else return r.ccc;
    }
    return 0;
}

fn compFor(a: u21, b: u21) ?u21 {
    var lo: usize = 0;
    var hi: usize = tables.comps.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        const c = tables.comps[mid];
        if (a < c.a or (a == c.a and b < c.b)) {
            hi = mid;
        } else if (a == c.a and b == c.b) {
            return c.cp;
        } else {
            lo = mid + 1;
        }
    }
    return null;
}

const Seq = struct {
    cps: []u21,
    cccs: []u8,
    len: usize,

    fn push(self: *Seq, cp: u21) error{NoSpaceLeft}!void {
        if (self.len >= self.cps.len) return error.NoSpaceLeft;
        self.cps[self.len] = cp;
        self.cccs[self.len] = cccOf(cp);
        self.len += 1;
    }
};

fn decomposeInto(seq: *Seq, cp: u21) error{NoSpaceLeft}!void {
    if (decompFor(cp)) |d| {
        try decomposeInto(seq, d.a);
        if (d.b != 0) try decomposeInto(seq, d.b);
    } else {
        try seq.push(cp);
    }
}

/// NFC-normalize `input` into `buf`. Intermediate codepoint scratch uses
/// `scratch_cps`/`scratch_cccs` (parallel arrays, worst case 3x expansion).
pub fn nfc(
    input: []const u8,
    buf: []u8,
    scratch_cps: []u21,
    scratch_cccs: []u8,
) (PrepError)![]const u8 {
    if (!std.unicode.utf8ValidateSlice(input)) return error.InvalidUtf8;
    var seq = Seq{ .cps = scratch_cps, .cccs = scratch_cccs, .len = 0 };
    var it = std.unicode.Utf8Iterator{ .bytes = input, .i = 0 };
    while (it.nextCodepoint()) |cp| {
        decomposeInto(&seq, cp) catch return error.NoSpaceLeft;
    }
    // Canonical ordering: stable insertion sort by ccc per segment.
    if (seq.len > 1) {
        var i: usize = 1;
        while (i < seq.len) : (i += 1) {
            const cp = seq.cps[i];
            const c = seq.cccs[i];
            if (c == 0) continue;
            var j = i;
            while (j > 0 and seq.cccs[j - 1] > c) : (j -= 1) {
                seq.cps[j] = seq.cps[j - 1];
                seq.cccs[j] = seq.cccs[j - 1];
            }
            seq.cps[j] = cp;
            seq.cccs[j] = c;
        }
    }
    // Composition: each non-starter combines with the last starter unless
    // blocked by an intervening char of equal or higher ccc.
    var out_len: usize = 0;
    var starter_idx: ?usize = null;
    var prev_ccc: u8 = 0;
    var i: usize = 0;
    while (i < seq.len) : (i += 1) {
        const cp = seq.cps[i];
        const c = seq.cccs[i];
        if (starter_idx) |si| {
            if (c != 0 and prev_ccc < c) {
                if (compFor(seq.cps[si], cp)) |merged| {
                    seq.cps[si] = merged;
                    continue; // consumed; prev_ccc unchanged (blocking keeps it)
                }
            }
        }
        seq.cps[out_len] = cp;
        seq.cccs[out_len] = c;
        if (c == 0) {
            starter_idx = out_len;
            prev_ccc = 0;
        } else {
            prev_ccc = c;
        }
        out_len += 1;
    }
    // Encode.
    var pos: usize = 0;
    i = 0;
    while (i < out_len) : (i += 1) {
        const n = std.unicode.utf8CodepointSequenceLength(seq.cps[i]) catch return error.InvalidUtf8;
        if (pos + n > buf.len) return error.NoSpaceLeft;
        _ = std.unicode.utf8Encode(seq.cps[i], buf[pos..][0..n]) catch return error.InvalidUtf8;
        pos += n;
    }
    return buf[0..pos];
}

/// RFC 8265 §4.2 OpaqueString enforcement. Returns the prepared string in
/// `buf` (identity for printable ASCII). `buf` must be at least twice
/// `input.len`: the space-mapped form is staged at buf's tail before NFC.
/// Errors on invalid UTF-8 or any prohibited code point.
pub fn prepareOpaqueString(
    input: []const u8,
    buf: []u8,
    scratch_cps: []u21,
    scratch_cccs: []u8,
) PrepError![]const u8 {
    if (!std.unicode.utf8ValidateSlice(input)) return error.InvalidUtf8;
    if (buf.len < 2 * input.len) return error.NoSpaceLeft;
    // Width mapping: non-ASCII spaces -> U+0020 (shrinks, never grows).
    var mapped_len: usize = 0;
    {
        var it = std.unicode.Utf8Iterator{ .bytes = input, .i = 0 };
        while (it.nextCodepoint()) |cp| {
            const out_cp: u21 = if (isNonAsciiSpace(cp)) 0x20 else cp;
            const n = std.unicode.utf8CodepointSequenceLength(out_cp) catch unreachable;
            if (mapped_len + n > buf.len / 2) return error.NoSpaceLeft;
            _ = std.unicode.utf8Encode(out_cp, buf[mapped_len..][0..n]) catch unreachable;
            mapped_len += n;
        }
    }
    // NFC reads the whole input into scratch before writing anything, so a
    // tail-staged copy keeps input and output non-overlapping.
    const tail = buf.len - mapped_len;
    @memcpy(buf[tail..][0..mapped_len], buf[0..mapped_len]);
    const normed = try nfc(buf[tail..][0..mapped_len], buf, scratch_cps, scratch_cccs);
    // Prohibited check on the final form.
    var it = std.unicode.Utf8Iterator{ .bytes = normed, .i = 0 };
    while (it.nextCodepoint()) |cp| {
        if (isProhibited(cp)) return error.ProhibitedCharacter;
    }
    return normed;
}

/// RFC 5802 §5.1: '=' -> "=3D", ',' -> "=2C" in the SCRAM n= attribute.
pub fn escapeScramName(input: []const u8, buf: []u8) error{NoSpaceLeft}![]const u8 {
    var pos: usize = 0;
    for (input) |ch| {
        const rep: ?[]const u8 = switch (ch) {
            '=' => "=3D",
            ',' => "=2C",
            else => null,
        };
        if (rep) |r| {
            if (pos + r.len > buf.len) return error.NoSpaceLeft;
            @memcpy(buf[pos..][0..r.len], r);
            pos += r.len;
        } else {
            if (pos + 1 > buf.len) return error.NoSpaceLeft;
            buf[pos] = ch;
            pos += 1;
        }
    }
    return buf[0..pos];
}

/// Inverse of escapeScramName. Rejects stray or truncated '=' sequences.
pub fn unescapeScramName(input: []const u8, buf: []u8) error{ NoSpaceLeft, MalformedName }![]const u8 {
    var pos: usize = 0;
    var i: usize = 0;
    while (i < input.len) {
        const ch = input[i];
        if (ch != '=') {
            if (pos + 1 > buf.len) return error.NoSpaceLeft;
            buf[pos] = ch;
            pos += 1;
            i += 1;
            continue;
        }
        if (i + 3 > input.len) return error.MalformedName;
        const hi = input[i + 1];
        const lo = input[i + 2];
        const out: u8 = if (hi == '2' and lo == 'C')
            ','
        else if (hi == '3' and lo == 'D')
            '='
        else
            return error.MalformedName;
        if (pos + 1 > buf.len) return error.NoSpaceLeft;
        buf[pos] = out;
        pos += 1;
        i += 3;
    }
    return buf[0..pos];
}

// --- tests ---

const testing = std.testing;

fn prep(input: []const u8, buf: []u8, cps: []u21, cccs: []u8) PrepError![]const u8 {
    return prepareOpaqueString(input, buf, cps, cccs);
}

test "OpaqueString: printable ASCII is identity" {
    var buf: [64]u8 = undefined;
    var cps: [64]u21 = undefined;
    var cccs: [64]u8 = undefined;
    const out = try prep("alice-passw0rd!", &buf, &cps, &cccs);
    try testing.expectEqualStrings("alice-passw0rd!", out);
}

test "OpaqueString: non-ASCII space maps to U+0020" {
    var buf: [64]u8 = undefined;
    var cps: [64]u21 = undefined;
    var cccs: [64]u8 = undefined;
    const out = try prep("pass\xC2\xA0word", &buf, &cps, &cccs); // U+00A0 NO-BREAK SPACE
    try testing.expectEqualStrings("pass word", out);
}

test "OpaqueString: NFC composes decomposed input" {
    var buf: [64]u8 = undefined;
    var cps: [64]u21 = undefined;
    var cccs: [64]u8 = undefined;
    // "päss" in NFD: a + U+0308 COMBINING DIAERESIS
    const out = try prep("pa\xCC\x88ss", &buf, &cps, &cccs);
    try testing.expectEqualStrings("p\xC3\xA4ss", out); // U+00E4 precomposed
}

test "OpaqueString: combining-mark order normalizes (ccc reorder)" {
    var buf: [64]u8 = undefined;
    var cps: [64]u21 = undefined;
    var cccs: [64]u8 = undefined;
    // a + U+0315 (ccc 232) + U+0300 (ccc 230): reorder to a+0300+0315, then
    // a+0300 composes to U+00E0; U+00E0+0315 has no composition.
    const out = try prep("a\xCC\x95\xCC\x80", &buf, &cps, &cccs);
    try testing.expectEqualStrings("\xC3\xA0\xCC\x95", out);
}

test "OpaqueString: prohibited characters rejected" {
    var buf: [64]u8 = undefined;
    var cps: [64]u21 = undefined;
    var cccs: [64]u8 = undefined;
    try testing.expectError(error.ProhibitedCharacter, prep("pa\x07ss", &buf, &cps, &cccs)); // BEL control
    try testing.expectError(error.ProhibitedCharacter, prep("pa\xEE\x80\x80ss", &buf, &cps, &cccs)); // U+E000 private use
    try testing.expectError(error.ProhibitedCharacter, prep("pa\xEF\xB7\x90ss", &buf, &cps, &cccs)); // U+FDD0 non-character
}

test "OpaqueString: invalid UTF-8 rejected" {
    var buf: [64]u8 = undefined;
    var cps: [64]u21 = undefined;
    var cccs: [64]u8 = undefined;
    try testing.expectError(error.InvalidUtf8, prep("pa\xFFss", &buf, &cps, &cccs));
}

test "SCRAM name escape/unescape round trip" {
    var buf: [64]u8 = undefined;
    const esc = try escapeScramName("us,er=na=me", &buf);
    try testing.expectEqualStrings("us=2Cer=3Dna=3Dme", esc);
    var back: [64]u8 = undefined;
    const un = try unescapeScramName(esc, &back);
    try testing.expectEqualStrings("us,er=na=me", un);
    try testing.expectError(error.MalformedName, unescapeScramName("bad=2X", &back));
    try testing.expectError(error.MalformedName, unescapeScramName("bad=2", &back));
}
