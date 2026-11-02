//! PRECIS UsernameCaseMapped profile (RFC 8265 Section 3.3) for account
//! names. `usernameCaseMapped` maps an input string to its canonical form
//! or rejects it: no allocation, all output in caller-provided buffers.
//!
//! RFC 8265 Section 3.3.1 rules, applied in the order of RFC 8264
//! Section 7 (width and case map the code points, NFC normalizes, then the
//! directionality and validity rules decide):
//!
//!   1. Width Mapping Rule: "Map fullwidth and halfwidth code points to
//!      their decomposition mappings (see Unicode Standard Annex #11
//!      [UAX11])."
//!   2. Additional Mapping Rule: "There is no additional mapping rule."
//!   3. Case Mapping Rule: "Map uppercase and titlecase code points to
//!      their lowercase equivalents, preferably using the Unicode
//!      toLowerCase() operation as defined in the Unicode Standard."
//!   4. Normalization Rule: "Apply Unicode Normalization Form C (NFC) to
//!      all strings."
//!   5. Directionality Rule: "Apply the 'Bidi Rule' defined in [RFC5893]
//!      to strings that contain right-to-left code points."
//!
//! Plus RFC 8265 Section 3.3.3: "the entity MUST ensure that the username
//! is not zero bytes in length", RFC 7622 Section 3.1's 1023-octet limit
//! on the prepared name, and RFC 8264 Section 7: "an implementation
//! SHOULD apply the rules repeatedly until the output string is stable; if
//! the output string does not stabilize after reapplying the rules three
//! (3) additional times after the first application, the implementation
//! SHOULD terminate application of the rules and reject the input string
//! as invalid."
//!
//! Case mapping decision (zed, 2026-11-02): full Unicode lowercase =
//! UnicodeData simple lowercase + UNCONDITIONAL SpecialCasing entries
//! only; every conditional entry is skipped (no Final_Sigma, no tr/az/lt
//! rules). U+03A3 always maps to U+03C3 and U+03C2 maps to itself. This
//! equals golang.org/x/text/secure/precis
//! cases.Lower(language.Und, cases.HandleFinalSigma(false)). Consequence:
//! the two sigmas are confusables; "οδος" (U+03C2) and "οδοσ" (U+03C3) are
//! different account names after preparation. Detecting that is out of
//! scope here.
//!
//! The IdentifierClass check runs after case mapping, not at RFC 8265
//! Section 3.3.2 preparation time, so the mapped code points are what is
//! validated: U+212A KELVIN SIGN (IdentifierClass DISALLOWED) prepares to
//! U+006B and is accepted, matching the account-key folding of PR #21
//! (src/auth/policy.zig, src/store/lock_store.zig).
//!
//! Tables come from lib/precis/precis_tables.zig, generated from the
//! pinned Unicode 15.0.0 UCD by tools/gen_precis_tables.py. NFC comes
//! from the shared engine in lib/unicode/normalize.zig.

const std = @import("std");
const testing = std.testing;
const unicode = @import("unicode");
const tables = @import("precis_tables.zig");

pub const PrecisError = error{
    /// Input is not valid UTF-8.
    InvalidUtf8,
    /// A caller-provided buffer is too small (see `usernameCaseMapped`).
    NoSpaceLeft,
    /// A code point is not allowed by the PRECIS IdentifierClass, or a
    /// CONTEXTJ/CONTEXTO code point fails its contextual rule.
    DisallowedCharacter,
    /// The string fails the RFC 5893 Bidi Rule.
    BidiViolation,
    /// The prepared username is zero bytes (RFC 8265 Section 3.3.3).
    Empty,
    /// The prepared username exceeds `max_username_octets` (RFC 7622
    /// Section 3.1).
    TooLong,
    /// The rules did not stabilize within `max_rule_applications`
    /// applications (RFC 8264 Section 7).
    NotStable,
};

/// RFC 7622 Section 3.1: an XMPP localpart must not exceed 1023 octets.
pub const max_username_octets = 1023;

/// Input longer than this cannot prepare to a conforming username:
/// canonical composition shrinks a string by at most a factor of 3 (three
/// jamo, or U+212A folding to one ASCII byte, per code point), so an
/// output of at most 1023 octets needs at most 3069 input octets.
pub const max_input_octets = 3 * max_username_octets;

/// RFC 8264 Section 7 allows the first application plus three
/// reapplications before the input must be rejected as invalid.
pub const max_rule_applications = 4;

/// Prepare `input` per RFC 8265 Section 3.3 or reject it. The returned
/// slice points into `buf` and is valid until `buf` is reused.
///
/// Buffer contracts (all checked; too small is `error.NoSpaceLeft`):
///   - `input` must not lie within `buf`.
///   - `buf.len >= 6 * input.len`: two slots of 3 * input.len that hold
///     consecutive stability-loop outputs (3x is the worst-case NFC
///     expansion; the rules are idempotent, so every pass after the first
///     re-fits the previous output).
///   - `scratch_cps.len >= 3 * input.len` and the same for `scratch_cccs`:
///     NFC decomposes into these; a fully decomposed form has at most one
///     code point per input byte of the string being normalized.
pub fn usernameCaseMapped(
    input: []const u8,
    buf: []u8,
    scratch_cps: []u21,
    scratch_cccs: []u8,
) PrecisError![]const u8 {
    return enforce(PrecisMapper, input, buf, scratch_cps, scratch_cccs);
}

/// The real width + case mapping (RFC 8265 Section 3.3.1 rules 1 and 3).
/// Returns up to two code points; the second is 0 when the mapping is a
/// single code point (code point 0 maps to itself, so the first element is
/// always written).
const PrecisMapper = struct {
    /// "Map fullwidth and halfwidth code points to their decomposition
    /// mappings (see Unicode Standard Annex #11 [UAX11])." then "Map
    /// uppercase and titlecase code points to their lowercase equivalents,
    /// preferably using the Unicode toLowerCase() operation as defined in
    /// the Unicode Standard."
    fn map(cp: u21) [2]u21 {
        const w = tables.widthOf(cp) orelse cp;
        if (tables.lowerOf(w)) |t| return .{ t.a, t.b };
        return .{ w, 0 };
    }
};

/// Stability loop around `applyRules` (RFC 8264 Section 7). `M` is the
/// mapper; tests inject a non-stabilizing one.
fn enforce(
    comptime M: type,
    input: []const u8,
    buf: []u8,
    scratch_cps: []u21,
    scratch_cccs: []u8,
) PrecisError![]const u8 {
    if (!std.unicode.utf8ValidateSlice(input)) return error.InvalidUtf8;
    if (input.len > max_input_octets) return error.TooLong;
    const slot_len = 3 * input.len;
    if (buf.len < 2 * slot_len) return error.NoSpaceLeft;
    if (scratch_cps.len < slot_len or scratch_cccs.len < slot_len) return error.NoSpaceLeft;

    // "apply the rules repeatedly until the output string is stable; if
    // the output string does not stabilize after reapplying the rules
    // three (3) additional times after the first application ... reject
    // the input string as invalid."
    var prev: []const u8 = input;
    var pass: usize = 0;
    while (pass < max_rule_applications) : (pass += 1) {
        const slot = if (pass % 2 == 0) buf[0..slot_len] else buf[slot_len..][0..slot_len];
        const out = try applyRules(M, prev, slot, scratch_cps, scratch_cccs);
        if (std.mem.eql(u8, out, prev)) return out;
        prev = out;
    }
    return error.NotStable;
}

/// One application of the rules: width + case mapping, NFC, the Bidi Rule,
/// the IdentifierClass with its contextual rules, then the empty and
/// length limits.
fn applyRules(
    comptime M: type,
    input: []const u8,
    out: []u8,
    scratch_cps: []u21,
    scratch_cccs: []u8,
) PrecisError![]const u8 {
    // Width + case mapping (RFC 8265 Section 3.3.1 rules 1 and 3).
    var len: usize = 0;
    {
        var it = std.unicode.Utf8Iterator{ .bytes = input, .i = 0 };
        while (it.nextCodepoint()) |cp| {
            const pair = M.map(cp);
            len += try writeCp(pair[0], out[len..]);
            if (pair[1] != 0) len += try writeCp(pair[1], out[len..]);
        }
    }
    // Normalization (RFC 8265 Section 3.3.1 rule 4): "Apply Unicode
    // Normalization Form C (NFC) to all strings." nfc() reads the whole
    // input before writing, so out may hold both.
    const normed = try unicode.nfc(out[0..len], out, scratch_cps, scratch_cccs);

    // Decode the prepared form; the NFC scratch is free again and now
    // holds the code points for the checks (at most one per input byte of
    // normed, which the buffer contract guarantees).
    var n: usize = 0;
    {
        var it = std.unicode.Utf8Iterator{ .bytes = normed, .i = 0 };
        while (it.nextCodepoint()) |cp| {
            scratch_cps[n] = cp;
            n += 1;
        }
    }
    const cps = scratch_cps[0..n];

    // Directionality (RFC 8265 Section 3.3.1 rule 5).
    if (!bidiOk(cps)) return error.BidiViolation;

    // Validity: the PRECIS IdentifierClass (RFC 8265 Section 3.3.2 step
    // 2) with its contextual rules (RFC 8264 Section 4.2.2).
    if (!classOk(cps)) return error.DisallowedCharacter;

    // RFC 8265 Section 3.3.3: "the entity MUST ensure that the username is
    // not zero bytes in length".
    if (normed.len == 0) return error.Empty;

    // RFC 7622 Section 3.1: 1023 octets on the prepared name.
    if (normed.len > max_username_octets) return error.TooLong;

    return normed;
}

fn writeCp(cp: u21, out: []u8) PrecisError!usize {
    const n = std.unicode.utf8CodepointSequenceLength(cp) catch unreachable;
    if (n > out.len) return error.NoSpaceLeft;
    _ = std.unicode.utf8Encode(cp, out[0..n]) catch unreachable;
    return n;
}

/// RFC 5893 Section 2's Bidi Rule (six conditions), applied only to
/// strings that contain right-to-left code points (RFC 8265 Section 3.3.1
/// rule 5: "for strings that do not contain right-to-left code points,
/// there is no special processing for directionality"). The generated
/// BidiGroup pools ES, CS, ET and BN (allowed in both label types) with
/// the remaining classes; every pooled code point is IdentifierClass
/// DISALLOWED and is rejected by the class check.
fn bidiOk(cps: []const u21) bool {
    var has_rtl = false;
    for (cps) |cp| {
        if (tables.bidiGroupOf(cp) == .r_al) {
            has_rtl = true;
            break;
        }
    }
    if (!has_rtl) return true;

    // Condition 1: "The first character must be a character with Bidi
    // property L, R, or AL." R and AL make it an RTL label, L an LTR
    // label.
    const first = tables.bidiGroupOf(cps[0]);
    if (first != .l and first != .r_al) return false;
    const rtl = first == .r_al;

    // Conditions 2/5 (allowed code points) and 4 (no EN with AN).
    var has_en = false;
    var has_an = false;
    for (cps) |cp| {
        const g = tables.bidiGroupOf(cp);
        if (rtl) {
            if (g == .l) return false;
            if (g == .en) has_en = true;
            if (g == .an) has_an = true;
        } else {
            if (g == .r_al or g == .an) return false;
        }
    }
    if (rtl and has_en and has_an) return false;

    // Conditions 3/6: "the end of the label must be a character with Bidi
    // property R, AL, EN, or AN" (RTL) or "L or EN" (LTR) "followed by
    // zero or more characters with Bidi property NSM".
    var end = cps.len;
    while (end > 0 and tables.bidiGroupOf(cps[end - 1]) == .nsm) end -= 1;
    if (end == 0) return false;
    const last = tables.bidiGroupOf(cps[end - 1]);
    return if (rtl)
        (last == .r_al or last == .en or last == .an)
    else
        (last == .l or last == .en);
}

/// PRECIS IdentifierClass validity: PVALID passes, CONTEXTJ needs Rule J,
/// CONTEXTO needs Rule O (RFC 8264 Section 4.2.2), everything else is
/// DISALLOWED. The contextual rules are applied at both registration and
/// lookup, so the lookup-time exemptions of RFC 5892 Appendix A do not
/// relax anything here.
fn classOk(cps: []const u21) bool {
    for (cps, 0..) |cp, i| {
        switch (tables.classOf(cp)) {
            .pvalid => {},
            .contextj => if (!contextJOk(cps, i)) return false,
            .contexto => if (!contextOOk(cps, i)) return false,
            .disallowed => return false,
        }
    }
    return true;
}

/// Rule J, RFC 5892 Appendix A.1 (U+200C) and A.2 (U+200D). Both allow a
/// preceding virama ("If Canonical_Combining_Class(Before(cp)) .eq.
/// Virama Then True"); U+200C additionally matches the joining regexp
/// "(Joining_Type:{L,D})(Joining_Type:T)*\u200C(Joining_Type:T)*
/// (Joining_Type:{R,D})".
fn contextJOk(cps: []const u21, i: usize) bool {
    const cp = cps[i];
    if (i > 0 and unicode.cccOf(cps[i - 1]) == 9) return true;
    if (cp == 0x200D) return false;
    // ZWNJ between joining characters, transparent characters allowed in
    // between (RFC 5892 Appendix A.1).
    var j = i;
    while (j > 0) {
        j -= 1;
        const jt = tables.joinTypeOf(cps[j]);
        if (jt == .l or jt == .d) break;
        if (jt != .t) return false;
    } else return false;
    var k = i + 1;
    while (k < cps.len) : (k += 1) {
        const jt = tables.joinTypeOf(cps[k]);
        if (jt == .r or jt == .d) return true;
        if (jt != .t) return false;
    }
    return false;
}

/// Rule O, RFC 5892 Appendix A.3 through A.9. The generated ScriptGroup
/// maps Greek, Hebrew and Hiragana/Katakana/Han (the A.7 set) apart from
/// everything else.
fn contextOOk(cps: []const u21, i: usize) bool {
    const cp = cps[i];
    switch (cp) {
        // A.3 MIDDLE DOT: "If Before(cp) .eq. U+006C And After(cp) .eq.
        // U+006C Then True" (Catalan ela geminada).
        0x00B7 => return i > 0 and i + 1 < cps.len and
            cps[i - 1] == 0x006C and cps[i + 1] == 0x006C,
        // A.4 GREEK LOWER NUMERAL SIGN: "If Script(After(cp)) .eq. Greek
        // Then True".
        0x0375 => return i + 1 < cps.len and
            tables.scriptGroupOf(cps[i + 1]) == .greek,
        // A.5/A.6 HEBREW PUNCTUATION: "If Script(Before(cp)) .eq. Hebrew
        // Then True".
        0x05F3, 0x05F4 => return i > 0 and
            tables.scriptGroupOf(cps[i - 1]) == .hebrew,
        // A.7 KATAKANA MIDDLE DOT: "For All Characters: If Script(cp)
        // .in. {Hiragana, Katakana, Han} Then True".
        0x30FB => {
            for (cps) |c| {
                if (tables.scriptGroupOf(c) == .cjk) return true;
            }
            return false;
        },
        // A.8/A.9 digits: "For All Characters: If cp .in. 06F0..06F9 Then
        // False" (and the mirror).
        0x0660...0x0669 => {
            for (cps) |c| {
                if (c >= 0x06F0 and c <= 0x06F9) return false;
            }
            return true;
        },
        0x06F0...0x06F9 => {
            for (cps) |c| {
                if (c >= 0x0660 and c <= 0x0669) return false;
            }
            return true;
        },
        // The generated table marks only the code points above CONTEXTO.
        else => unreachable,
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

fn expectUsername(expected: []const u8, input: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var cps: [2048]u21 = undefined;
    var cccs: [2048]u8 = undefined;
    const got = try usernameCaseMapped(input, &buf, &cps, &cccs);
    try testing.expectEqualStrings(expected, got);
}

fn expectUsernameError(expected: PrecisError, input: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var cps: [2048]u21 = undefined;
    var cccs: [2048]u8 = undefined;
    try testing.expectError(expected, usernameCaseMapped(input, &buf, &cps, &cccs));
}

test "usernameCaseMapped: sigma, no final-sigma rule" {
    // zed's expected values: U+03A3 always maps to U+03C3.
    try expectUsername("\u{03BF}\u{03B4}\u{03BF}\u{03C3}", "\u{039F}\u{0394}\u{039F}\u{03A3}");
    try expectUsername("\u{03B1}\u{03C3}", "\u{0391}\u{03A3}");
    try expectUsername("\u{03C3}\u{03B1}", "\u{03A3}\u{0391}");
    // U+03C2 maps to itself and stays distinct from U+03C3.
    try expectUsername("\u{03C2}", "\u{03C2}");
    try expectUsername("\u{03BF}\u{03B4}\u{03BF}\u{03C2}", "\u{03BF}\u{03B4}\u{03BF}\u{03C2}");
    try expectUsername("\u{03BF}\u{03B4}\u{03BF}\u{03C3}", "\u{03BF}\u{03B4}\u{03BF}\u{03C3}");
    // The two forms prepare to distinct names (separate buffers: each
    // result points into its buf).
    var buf_a: [64]u8 = undefined;
    var buf_b: [64]u8 = undefined;
    var cps: [32]u21 = undefined;
    var cccs: [32]u8 = undefined;
    const a = try usernameCaseMapped("\u{03BF}\u{03B4}\u{03BF}\u{03C2}", &buf_a, &cps, &cccs);
    const b = try usernameCaseMapped("\u{03BF}\u{03B4}\u{03BF}\u{03C3}", &buf_b, &cps, &cccs);
    try testing.expect(!std.mem.eql(u8, a, b));
}

test "usernameCaseMapped: KELVIN SIGN folds to k" {
    // U+212A is IdentifierClass DISALLOWED; case mapping runs first, so
    // the prepared name is the letter k (PR #21 account-key semantics).
    try expectUsername("k", "\u{212A}");
    try expectUsername("kk", "\u{212A}\u{212A}");
}

test "usernameCaseMapped: fullwidth and halfwidth map to decompositions" {
    try expectUsername("abc", "\u{FF21}\u{FF22}\u{FF23}");
    try expectUsername("12", "\u{FF11}\u{FF12}");
    // Halfwidth katakana letter a -> U+30A2 (its decomposition mapping).
    try expectUsername("\u{30A2}", "\u{FF71}");
}

test "usernameCaseMapped: I with dot above expands to two code points" {
    // U+0130 -> U+0069 U+0307 (the one unconditional multi-code-point
    // lowercase in Unicode 15.0.0); both are IdentifierClass PVALID.
    try expectUsername("i\u{0307}", "\u{0130}");
    try expectUsername("i\u{0307}x", "\u{0130}x");
}

test "usernameCaseMapped: NFC composes canonically equivalent input alike" {
    try expectUsername("\u{00E1}", "A\u{0301}");
    try expectUsername("\u{AC00}", "\u{1100}\u{1161}");
    try expectUsername("\u{AC01}", "\u{AC00}\u{11A8}");
    var buf: [64]u8 = undefined;
    var cps: [32]u21 = undefined;
    var cccs: [32]u8 = undefined;
    const a = try usernameCaseMapped("\u{00E1}", &buf, &cps, &cccs);
    const b = try usernameCaseMapped("A\u{0301}", &buf, &cps, &cccs);
    try testing.expectEqualStrings(a, b);
}

test "usernameCaseMapped: CONTEXTJ ZWNJ needs a joining context" {
    // Bare ZWNJ: not in any Rule J context.
    try expectUsernameError(error.DisallowedCharacter, "a\u{200C}b");
    // U+0628 (dual joining) ZWNJ U+062F (right joining) matches the
    // joining regexp of RFC 5892 Appendix A.1.
    try expectUsername("\u{0628}\u{200C}\u{062F}", "\u{0628}\u{200C}\u{062F}");
}

test "usernameCaseMapped: CONTEXTJ ZWJ follows a virama" {
    try expectUsername("\u{0915}\u{094D}\u{200D}", "\u{0915}\u{094D}\u{200D}");
    try expectUsernameError(error.DisallowedCharacter, "a\u{200D}");
    try expectUsernameError(error.DisallowedCharacter, "\u{200D}");
}

test "usernameCaseMapped: CONTEXTO middle dot and keraia" {
    // RFC 5892 Appendix A.3: between 'l' and 'l'.
    try expectUsername("l\u{00B7}l", "l\u{00B7}l");
    try expectUsernameError(error.DisallowedCharacter, "l\u{00B7}x");
    try expectUsernameError(error.DisallowedCharacter, "\u{00B7}");
    // A.4: the following character must be Greek script.
    try expectUsername("\u{0375}\u{03B1}", "\u{0375}\u{03B1}");
    try expectUsernameError(error.DisallowedCharacter, "\u{03B1}\u{0375}");
}

test "usernameCaseMapped: CONTEXTO Hebrew punctuation and katakana middle dot" {
    // A.5/A.6: the preceding character must be Hebrew script. (A Latin
    // letter before geresh fails the Bidi Rule first; Arabic before it
    // passes bidi and fails the contextual rule.)
    try expectUsername("\u{05D0}\u{05F3}", "\u{05D0}\u{05F3}");
    try expectUsername("\u{05D0}\u{05F4}", "\u{05D0}\u{05F4}");
    try expectUsernameError(error.DisallowedCharacter, "\u{0628}\u{05F3}");
    try expectUsernameError(error.DisallowedCharacter, "\u{0628}\u{05F4}");
    // A.7: at least one character must be Hiragana, Katakana or Han.
    try expectUsername("\u{30A2}\u{30FB}\u{30A2}", "\u{30A2}\u{30FB}\u{30A2}");
    try expectUsernameError(error.DisallowedCharacter, "a\u{30FB}b");
}

test "usernameCaseMapped: CONTEXTO digits must not mix" {
    try expectUsername("\u{0660}\u{0661}", "\u{0660}\u{0661}");
    try expectUsername("\u{06F0}\u{06F1}", "\u{06F0}\u{06F1}");
    try expectUsernameError(error.DisallowedCharacter, "\u{0660}\u{06F1}");
    try expectUsernameError(error.DisallowedCharacter, "\u{06F1}\u{0660}");
}

test "usernameCaseMapped: Bidi Rule failures" {
    // LTR label with a right-to-left character and the mirror (RFC 5893
    // conditions 5 and 2).
    try expectUsernameError(error.BidiViolation, "a\u{05D0}");
    try expectUsernameError(error.BidiViolation, "\u{05D0}a");
    // Condition 4: EN and AN in the same RTL label.
    try expectUsernameError(error.BidiViolation, "\u{0627}1\u{0662}");
    // Valid RTL label: first and last are right-to-left, digit EN at the
    // end is fine (condition 3).
    try expectUsername("\u{0627}1", "\u{0627}1");
    // Trailing nonspacing marks are fine after an RTL letter.
    try expectUsername("\u{05D0}\u{05B7}", "\u{05D0}\u{05B7}");
}

test "usernameCaseMapped: spaces and symbols are rejected" {
    try expectUsernameError(error.DisallowedCharacter, "a b");
    try expectUsernameError(error.DisallowedCharacter, " ");
    try expectUsernameError(error.DisallowedCharacter, "\u{00A0}");
    try expectUsernameError(error.DisallowedCharacter, "\u{20AC}");
    try expectUsernameError(error.DisallowedCharacter, "\u{2603}");
    // ASCII7 (K) is PVALID in the IdentifierClass (RFC 8264 Section 8.2:
    // "Else If .cp. .in. ASCII7 Then PVALID;"), so printable ASCII
    // punctuation is not a symbol here and prepares unchanged.
    try expectUsername("a!", "a!");
    try expectUsername("a,b.c-d_1", "a,b.c-d_1");
}

test "usernameCaseMapped: empty and RFC 7622 length limit" {
    try expectUsernameError(error.Empty, "");
    var buf: [8192]u8 = undefined;
    var cps: [4096]u21 = undefined;
    var cccs: [4096]u8 = undefined;
    var in1023: [max_username_octets]u8 = undefined;
    @memset(&in1023, 'a');
    const ok = try usernameCaseMapped(&in1023, &buf, &cps, &cccs);
    try testing.expectEqual(@as(usize, max_username_octets), ok.len);
    var in1024: [max_username_octets + 1]u8 = undefined;
    @memset(&in1024, 'a');
    try testing.expectError(error.TooLong, usernameCaseMapped(&in1024, &buf, &cps, &cccs));
    // Beyond max_input_octets the input cannot shrink below the limit.
    var big: [max_input_octets + 1]u8 = undefined;
    @memset(&big, 'a');
    try testing.expectError(error.TooLong, usernameCaseMapped(&big, &buf, &cps, &cccs));
}

test "usernameCaseMapped: buffer contracts" {
    const input = "abc";
    var buf: [6 * 3]u8 = undefined;
    var cps: [3 * 3]u21 = undefined;
    var cccs: [3 * 3]u8 = undefined;
    _ = try usernameCaseMapped(input, &buf, &cps, &cccs);
    try testing.expectError(error.NoSpaceLeft, usernameCaseMapped(input, buf[0 .. buf.len - 1], &cps, &cccs));
    try testing.expectError(error.NoSpaceLeft, usernameCaseMapped(input, &buf, cps[0 .. cps.len - 1], &cccs));
    try testing.expectError(error.NoSpaceLeft, usernameCaseMapped(input, &buf, &cps, cccs[0 .. cccs.len - 1]));
}

test "usernameCaseMapped: invalid UTF-8 is rejected" {
    try expectUsernameError(error.InvalidUtf8, "\xFF");
}

test "usernameCaseMapped: f(f(x)) == f(x) over the corpus" {
    const interesting = [_]u21{
        0x0041, 0x0061, 0x006C, 0x0020, 0x0021, 0x0031, 0x00B7, 0x00DF,
        0x0130, 0x0301, 0x0307, 0x0344, 0x0375, 0x0391, 0x03A3, 0x03B1,
        0x03C2, 0x03C3, 0x05B7, 0x05D0, 0x05F3, 0x05F4, 0x0628, 0x062F,
        0x0640, 0x0661, 0x06F1, 0x094D, 0x09BE, 0x09C7, 0x0F73, 0x1100,
        0x1161, 0x11A8, 0x200C, 0x200D, 0x212A, 0x2603, 0x30A2, 0x30FB,
        0xAC00, 0xFF21, 0xFF71, 0x1F82,
    };
    var buf_a: [4096]u8 = undefined;
    var cps_a: [2048]u21 = undefined;
    var cccs_a: [2048]u8 = undefined;
    var buf_b: [4096]u8 = undefined;
    var cps_b: [2048]u21 = undefined;
    var cccs_b: [2048]u8 = undefined;

    var checked: usize = 0;
    var seed: u64 = 0x9E3779B97F4A7C15;
    var round: usize = 0;
    while (round < interesting.len * interesting.len + 512) : (round += 1) {
        var raw: [32]u8 = undefined;
        var raw_len: usize = 0;
        if (round < interesting.len) {
            raw_len += try writeCp(interesting[round], raw[raw_len..]);
        } else if (round < interesting.len * interesting.len) {
            const a = interesting[round / interesting.len];
            const b = interesting[round % interesting.len];
            raw_len += try writeCp(a, raw[raw_len..]);
            raw_len += try writeCp(b, raw[raw_len..]);
        } else {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            const count = 1 + (seed >> 33) % 6;
            var k: usize = 0;
            while (k < count) : (k += 1) {
                seed = seed *% 6364136223846793005 +% 1442695040888963407;
                const cp = interesting[(seed >> 33) % interesting.len];
                raw_len += try writeCp(cp, raw[raw_len..]);
            }
        }
        const s = raw[0..raw_len];
        if (usernameCaseMapped(s, &buf_a, &cps_a, &cccs_a)) |y1| {
            // Copy y1 out of buf_a so the second call may reuse it.
            var stable: [128]u8 = undefined;
            @memcpy(stable[0..y1.len], y1);
            const y2 = try usernameCaseMapped(stable[0..y1.len], &buf_b, &cps_b, &cccs_b);
            try testing.expectEqualStrings(y1, y2);
            checked += 1;
        } else |e| {
            // Rejection is reproducible too.
            try testing.expectError(e, usernameCaseMapped(s, &buf_a, &cps_a, &cccs_a));
        }
    }
    try testing.expect(checked > 0);
}

/// Non-stabilizing rules: every ASCII letter advances, so no application
/// ever returns what it was given (RFC 8264 Section 7's rejection case).
const NonStabilizingMapper = struct {
    fn map(cp: u21) [2]u21 {
        if (cp >= 'a' and cp < 'z') return .{ cp + 1, 0 };
        if (cp == 'z') return .{ 'a', 0 };
        return .{ cp, 0 };
    }
};

test "usernameCaseMapped: RFC 8264 stability loop limit rejects" {
    var buf: [64]u8 = undefined;
    var cps: [32]u21 = undefined;
    var cccs: [32]u8 = undefined;
    // Four applications (first + three reapplications) never stabilize.
    try testing.expectError(error.NotStable, enforce(NonStabilizingMapper, "a", &buf, &cps, &cccs));
    // The real rules prepare the same input and are stable immediately.
    const got = try usernameCaseMapped("a", &buf, &cps, &cccs);
    try testing.expectEqualStrings("a", got);
}
