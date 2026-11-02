//! Unicode NFC normalization engine and canonical combining class lookup,
//! shared by SASL OpaqueString (lib/sasl/stringprep.zig) and PRECIS
//! UsernameCaseMapped (lib/precis/username.zig). Single implementation of
//! NFC; the tables are generated (see nfc_tables.zig).
//!
//! The engine reads the whole input into codepoint scratch before writing
//! output, so the output buffer may overlap the input. Worst case expansion
//! is 3x the input codepoint count (a precomposed syllable decomposing to
//! three jamo).

const std = @import("std");
const tables = @import("nfc_tables.zig");

pub const NormalizeError = error{
    InvalidUtf8,
    NoSpaceLeft,
};

/// Canonical_Combining_Class of `cp` (0 for starters).
pub fn cccOf(cp: u21) u8 {
    var lo: usize = 0;
    var hi: usize = tables.ccc_ranges.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        const r = tables.ccc_ranges[mid];
        if (cp < r.lo) hi = mid else if (cp > r.hi) lo = mid + 1 else return r.ccc;
    }
    return 0;
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
/// `buf` may overlap `input`; it must hold at most 3x the input codepoint
/// count.
pub fn nfc(
    input: []const u8,
    buf: []u8,
    scratch_cps: []u21,
    scratch_cccs: []u8,
) NormalizeError![]const u8 {
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

// --- tests ---

const testing = std.testing;

fn nfcOf(input: []const u8) NormalizeError![]const u8 {
    var buf: [64]u8 = undefined;
    var cps: [64]u21 = undefined;
    var cccs: [64]u8 = undefined;
    return nfc(input, &buf, &cps, &cccs);
}

test "nfc: identity for already-normalized input" {
    const out = try nfcOf("alice");
    try testing.expectEqualStrings("alice", out);
}

test "nfc: composes decomposed input" {
    // a + U+0300 COMBINING GRAVE ACCENT -> U+00E0
    const out = try nfcOf("a\xCC\x80");
    try testing.expectEqualStrings("\xC3\xA0", out);
}

test "nfc: combining-mark order normalizes (ccc reorder)" {
    // a + U+0315 (ccc 232) + U+0300 (ccc 230): reorder to a+0300+0315, then
    // a+0300 composes to U+00E0; U+00E0+0315 has no composition.
    const out = try nfcOf("a\xCC\x95\xCC\x80");
    try testing.expectEqualStrings("\xC3\xA0\xCC\x95", out);
}

test "nfc: invalid UTF-8 rejected" {
    try testing.expectError(error.InvalidUtf8, nfcOf("pa\xFFss"));
}

test "nfc: undersized scratch returns NoSpaceLeft" {
    var buf: [64]u8 = undefined;
    var cps: [1]u21 = undefined;
    var cccs: [1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, nfc("abc", &buf, &cps, &cccs));
}

test "cccOf: starters and known combining marks" {
    try testing.expectEqual(@as(u8, 0), cccOf(0x0041));
    try testing.expectEqual(@as(u8, 230), cccOf(0x0300));
    try testing.expectEqual(@as(u8, 232), cccOf(0x0315));
    try testing.expectEqual(@as(u8, 9), cccOf(0x094D)); // Devanagari virama
}
