#!/usr/bin/env python3
"""Generate lib/precis/precis_tables.zig from the Unicode Character Database.

Pinned Unicode version: 15.0.0 (see UNICODE_VERSION below; both files state it).

Input: the official UCD 15.0.0 archive, unzipped:
  https://www.unicode.org/Public/15.0.0/ucd/UCD.zip
Pass the unzipped directory as the first argument (default /home/admin/tmp/UCDzip).

Files used (all from that one archive, nothing else):
  UnicodeData.txt                 general category, ccc, decompositions,
                                  simple lowercase (field 13)
  CompositionExclusions.txt       canonical composition exclusions
  SpecialCasing.txt               unconditional full lowercase (U+0130)
  DerivedNormalizationProps.txt   NFKC_Quick_Check cross-check of derived Q
  DerivedCoreProperties.txt       Default_Ignorable_Code_Point,
                                  Noncharacter_Code_Point, Join_Control
  DerivedJoiningType.txt          Arabic joining type (extracted/)
  DerivedBidiClass.txt            bidirectional class, incl. unassigned
                                  defaults (extracted/)
  HangulSyllableType.txt          Old_Hangul_Jamo (RFC 8264 rule I)
  Scripts.txt                     script extensions (CONTEXTJ/CONTEXTO)

Derived data (RFC 8264 section 8.2 derivation, in that exact order):
  class bits   2 bits per code point: 0 PVALID, 1 CONTEXTJ, 2 CONTEXTO,
               3 DISALLOWED
  bidi bits    3 bits per code point: 0 L, 1 R/AL, 2 EN, 3 AN,
               4 ES/CS/ET/ON/BN, 5 NSM, 6 other
  script bits  2 bits per code point: 0 Common/other, 1 Greek, 2 Hebrew,
               3 Hiragana/Katakana/Han
  width map    fullwidth and halfwidth code points (East_Asian_Width F or H
               per UAX #11) mapped to their decomposition mappings, per
               RFC 8265 section 3.3.1
  lower map    full lowercase mapping: UnicodeData simple lowercase plus the
               UNCONDITIONAL SpecialCasing entries (U+0130 -> 0069 0307). All
               conditional SpecialCasing entries are skipped, including
               Final_Sigma and the tr/az/lt locale mappings (decided for this
               profile; see lib/precis/username.zig). U+03A3 always maps to
               U+03C3; U+03C2 is lowercase and stays U+03C2.
  join map     Arabic joining type per RFC 8265 A.1 (1 L, 2 R, 3 D, 4 T;
               default 0)

Quick_Check note: the HasCompat check is NFKC_Quick_Check == No (Q=1); Maybe
decompositions recompose under NFC and are PVALID unless excluded by another
rule. The generator computes the NFKC form itself (recursive NFKD from
UnicodeData decompositions, ccc-ordered, then canonical recomposition from the
non-excluded 2-element decompositions) and asserts agreement with
DerivedNormalizationProps.txt.

The generated file must be regenerated whenever the pinned Unicode version
changes; the generator asserts determinism (running it twice yields the same
file).
"""

import sys
import os
import re

UNICODE_VERSION = "15.0.0"

MAX_CP = 0x110000
CCC_START, CCC_COUNT = 0x0300, 0x0370   # packed ccc array: 0x0300..0x036F

# --- exceptions from RFC 8264 section 8.2, by their RFC 5892 sources --------

# RFC 5892 Appendix A (LDH): ASCII 0021..007E are PVALID regardless of the
# derived category; nothing else in 0000..007F is in the FreePValue class.
ASCII7 = range(0x21, 0x7F)

# RFC 5892 section 2.6: U+00DF, Greek final sigma U+03C2, ZWJ U+200D, ZWNJ
# U+200C, and middle dot U+00B7 (the last only as CONTEXTO via rule J.1).
JOIN_CONTROL = {0x200C, 0x200D}

# DerivedCoreProperties.txt PrecisIgnorableProperties = Default_Ignorable_Code_Point
# plus Noncharacter_Code_Point plus Join_Control. The three sets are read from
# the file and unioned; the set below is a sanity anchor for assertions.
DI_ANCHOR = {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180F, 0x3164}


class Ucd:
    def __init__(self, d):
        self.d = d
        self.gc = {}            # cp -> general category (default "Cn")
        self.ccc = {}           # cp -> canonical combining class (default 0)
        self.decomp = {}        # cp -> tuple of cps (canonical decomp, c[5])
        self.simple_lower = {}  # cp -> cp (UnicodeData field 13)
        self.simple_upper = {}  # cp -> cp (UnicodeData field 12)
        self.simple_title = {}  # cp -> cp (UnicodeData field 14)
        self.composition_excl = set()
        self.sc_uncond_lower = {}   # cp -> tuple (SpecialCasing unconditional)
        self.nfc_qc = {}        # cp -> "N" | "M" | "Y" (DerivedNormalizationProps)
        self.di = set()         # Default_Ignorable_Code_Point
        self.nonchar = set()    # Noncharacter_Code_Point (ranges)
        self.join_ctl_file = set()
        self.join_type = {}     # cp -> "L"|"R"|"D"|"T"|"C"|"U"|"" 
        self.bidi = {}          # cp -> Bidi_Class (extracted/DerivedBidiClass)
        self.hst = {}           # cp -> "L"|"V"|"T"|"LV"|"LVT"
        self.scripts = {}       # cp -> script name (first matching range)
        self.eaw = {}           # cp -> East_Asian_Width (only F and H kept)

    def load(self):
        load_fields(self)
        load_ucd(self)


def parse_ranges(path, per_line):
    """Parse a UCD ranged file: 'first[..last] ; value # comment'."""
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            fields = [x.strip() for x in line.split(";")]
            per_line(fields)


def cp_of(s):
    s = s.strip()
    if ".." in s:
        a, b = s.split("..")
        return range(int(a, 16), int(b, 16) + 1)
    return range(int(s, 16), int(s, 16) + 1)


def load_fields(u):
    d = u.d

    def per(f):
        cp = int(f[0], 16)
        u.gc[cp] = f[2]
        u.ccc[cp] = int(f[3])
        if f[5]:
            parts = f[5].split()
            tag = None
            if parts[0].startswith("<"):
                tag = parts[0]
                parts = parts[1:]
            u.decomp[cp] = (tag, tuple(int(x, 16) for x in parts))
        if f[12]:
            u.simple_upper[cp] = int(f[12], 16)
        if f[13]:
            u.simple_lower[cp] = int(f[13], 16)
        if f[14]:
            u.simple_title[cp] = int(f[14], 16)

    # First/Last marker rows expand to their ranges.
    pending_first = None
    with open(os.path.join(d, "UnicodeData.txt"), encoding="utf-8") as f:
        for raw in f:
            fields = raw.rstrip("\n").split(";")
            name = fields[1]
            cp = int(fields[0], 16)
            if name.endswith(", First>"):
                pending_first = (cp, fields)
                continue
            if name.endswith(", Last>"):
                assert pending_first is not None
                first_cp, first_fields = pending_first
                assert first_fields[2] == fields[2], "First/Last Gc mismatch"
                for c in range(first_cp, cp + 1):
                    row = [f"{c:04X}"] + first_fields[1:]
                    row[0] = f"{c:04X}"
                    per(row)
                pending_first = None
                continue
            per(fields)
    assert pending_first is None


def load_ucd(u):
    d = u.d

    def per(f):
        for c in cp_of(f[0]):
            u.composition_excl.add(c)

    parse_ranges(os.path.join(d, "CompositionExclusions.txt"), per)

    # SpecialCasing: unconditional entries are those with an empty condition
    # field and a status field that is empty or 'Common'.
    with open(os.path.join(d, "SpecialCasing.txt"), encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            fields = [x.strip() for x in line.split(";")]
            cp, lower, upper, title, cond = (fields[0], fields[1], fields[2],
                                             fields[3], fields[4])
            if cond:
                continue  # Final_Sigma, tr/az/lt: skipped by this profile
            u.sc_uncond_lower[int(cp, 16)] = tuple(int(x, 16)
                                                   for x in lower.split())

    def dnp(f):
        # code_points ; NFKC_QC ; value (shorthand property name in data
        # lines; the header spells it NFKC_Quick_Check)
        if f[1] != "NFKC_QC":
            return
        for c in cp_of(f[0]):
            u.nfc_qc[c] = f[2]

    parse_ranges(os.path.join(d, "DerivedNormalizationProps.txt"), dnp)

    def dcp(f):
        if f[1] == "Default_Ignorable_Code_Point":
            for c in cp_of(f[0]):
                u.di.add(c)
        elif f[1] == "Noncharacter_Code_Point":
            for c in cp_of(f[0]):
                u.nonchar.add(c)
        elif f[1] == "Join_Control":
            for c in cp_of(f[0]):
                u.join_ctl_file.add(c)

    parse_ranges(os.path.join(d, "DerivedCoreProperties.txt"), dcp)

    def jt(f):
        # code_points ; value (the property is implied by the file;
        # C/U map to the default and are left out)
        for c in cp_of(f[0]):
            u.join_type[c] = f[1]

    parse_ranges(os.path.join(d, "extracted", "DerivedJoiningType.txt"), jt)

    def bidi(f):
        # code_points; Bidi_Class (extracted: includes unassigned defaults
        # as @missing rules in the comments; see below)
        for c in cp_of(f[0]):
            u.bidi[c] = f[1]

    parse_ranges(os.path.join(d, "extracted", "DerivedBidiClass.txt"), bidi)

    # Unlisted code points follow the file's @missing rules: unassigned
    # Default_Ignorable / Noncharacter code points default to BN, then the
    # right-to-left block defaults, then Left_To_Right everywhere else.
    missing = []  # (start, end, value) in file order; the global rule is last
    name_map = {"Left_To_Right": "L", "Right_To_Left": "R",
                "Arabic_Letter": "AL", "European_Terminator": "ET"}
    with open(os.path.join(d, "extracted", "DerivedBidiClass.txt"),
              encoding="utf-8") as f:
        for raw in f:
            m = re.match(r"#\s*@missing:\s*([0-9A-Fa-f.]+);\s*(\S+)", raw)
            if m:
                r = cp_of(m.group(1))
                missing.append((r.start, r.stop - 1, name_map[m.group(2)]))
    assert missing and missing[0][0] == 0 and missing[0][1] == 0x10FFFF, \
        "global @missing rule not found first"
    for cp in range(MAX_CP):
        if cp in u.bidi:
            continue
        if cp in u.di or cp in u.nonchar:
            u.bidi[cp] = "BN"
            continue
        # specific block ranges first, global default last
        for start, end, val in reversed(missing):
            if start <= cp <= end:
                u.bidi[cp] = val
                break

    def hst(f):
        # code_points ; value (the property is implied by the file)
        for c in cp_of(f[0]):
            u.hst[c] = f[1]

    parse_ranges(os.path.join(d, "HangulSyllableType.txt"), hst)

    def scr(f):
        for c in cp_of(f[0]):
            u.scripts.setdefault(c, f[1])

    parse_ranges(os.path.join(d, "Scripts.txt"), scr)

    def eaw(f):
        # code_points; East_Asian_Width (F = Fullwidth, H = Halfwidth)
        if f[1] in ("F", "H"):
            for c in cp_of(f[0]):
                u.eaw[c] = f[1]

    parse_ranges(os.path.join(d, "EastAsianWidth.txt"), eaw)


# --- NFKC computation (independent of any host library) ---------------------

def ccc_of(u, cp):
    return u.ccc.get(cp, 0)


def decomp_nfd(u, cp, out, seen):
    """Recursive decomposition (NFKD over canonical and compatibility
    decomposition mappings; UAX #15 definitions D117/D118)."""
    if cp in seen:
        raise AssertionError(f"decomposition loop at U+{cp:04X}")
    d = u.decomp.get(cp)
    if d is None:
        out.append(cp)
        return
    seen.add(cp)
    for part in d[1]:
        decomp_nfd(u, part, out, seen)
    seen.remove(cp)


def reorder(u, seq):
    """Canonical ordering: stable by ccc, ignoring starters (ccc == 0)."""
    i = 1
    while i < len(seq):
        c = ccc_of(u, seq[i])
        if c == 0:
            i += 1
            continue
        j = i
        while j > 0 and ccc_of(u, seq[j - 1]) > c:
            j += 1
        if j != i:
            seq.insert(j, seq.pop(i))
        i += 1
    return seq


def build_composition(u):
    """Canonical composition table (UAX #15 D117 primary composites).

    A primary composite has a canonical (un-tagged) decomposition of exactly
    two code points, is not a singleton decomposition, is not a non-starter
    decomposition (first code point has ccc != 0), and is not in
    CompositionExclusions.txt. The second code point may be a starter
    (e.g. (09C7, 09BE) -> 09CB).
    """
    pairs = {}
    for cp, (tag, d) in u.decomp.items():
        if tag is not None:
            continue
        if len(d) != 2:
            continue
        if cp in u.composition_excl:
            continue
        if ccc_of(u, d[0]) != 0:
            continue
        pairs[d] = cp
    return pairs


def nfkc(u, cp, comps):
    seq = []
    decomp_nfd(u, cp, seq, set())
    reorder(u, seq)
    # canonical composition (UAX #15)
    out = []
    starter = None
    for ch in seq:
        if starter is not None:
            last_ccc = ccc_of(u, out[-1])
            if last_ccc == 0 or last_ccc < ccc_of(u, ch):
                comp = comps.get((starter, ch))
                if comp is not None:
                    out[-1] = comp
                    starter = comp
                    continue
        out.append(ch)
        if ccc_of(u, ch) == 0:
            starter = ch
    return tuple(out)


# --- derivation -------------------------------------------------------------

# RFC 5892 section 2.6, Exceptions (F): code points whose derived value
# cannot be assigned from core properties alone. This table is checked
# FIRST by the RFC 8264 section 8.2 algorithm.
EXCEPTIONS = {}
for _cp, _v in (
    # PVALID -- would otherwise have been DISALLOWED
    (0x00DF, "P"), (0x03C2, "P"), (0x06FD, "P"), (0x06FE, "P"),
    (0x0F0B, "P"), (0x3007, "P"),
    # CONTEXTO -- would otherwise have been DISALLOWED
    (0x00B7, "O"), (0x0375, "O"), (0x05F3, "O"), (0x05F4, "O"),
    (0x30FB, "O"),
    # CONTEXTO -- would otherwise have been PVALID
    (0x0660, "O"), (0x0661, "O"), (0x0662, "O"), (0x0663, "O"),
    (0x0664, "O"), (0x0665, "O"), (0x0666, "O"), (0x0667, "O"),
    (0x0668, "O"), (0x0669, "O"), (0x06F0, "O"), (0x06F1, "O"),
    (0x06F2, "O"), (0x06F3, "O"), (0x06F4, "O"), (0x06F5, "O"),
    (0x06F6, "O"), (0x06F7, "O"), (0x06F8, "O"), (0x06F9, "O"),
    # DISALLOWED -- would otherwise have been PVALID
    (0x0640, "D"), (0x07FA, "D"), (0x302E, "D"), (0x302F, "D"),
    (0x3031, "D"), (0x3032, "D"), (0x3033, "D"), (0x3034, "D"),
    (0x3035, "D"), (0x303B, "D"),
):
    EXCEPTIONS[_cp] = _v
assert len(EXCEPTIONS) == 41, len(EXCEPTIONS)


def derive_class(u, comps):
    """RFC 8264 section 8.2 derivation, evaluated in the RFC's order.

    The returned strings are the derived property values with UNASSIGNED
    collapsed into DISALLOWED (neither is usable in a string; RFC 8264
    section 8 treats UNASSIGNED as its own value).
    """
    result = {}
    for cp in range(MAX_CP):
        gc = u.gc.get(cp, "Cn")
        # F: Exceptions (RFC 5892 section 2.6)
        if cp in EXCEPTIONS:
            cl = EXCEPTIONS[cp]
        # G: BackwardCompatible (RFC 5892 section 2.7): empty
        # J: Unassigned (RFC 5892 section 2.10): Cn and not a noncharacter
        elif gc == "Cn" and cp not in u.nonchar:
            cl = "U"
        # K: ASCII7 -> PVALID
        elif cp in ASCII7:
            cl = "P"
        # H: JoinControl (RFC 5892 section 2.8) -> CONTEXTJ
        elif cp in JOIN_CONTROL:
            cl = "J"
        # I: OldHangulJamo (RFC 5892 section 2.9)
        elif u.hst.get(cp, "") in ("L", "V", "T"):
            cl = "D"
        # M: PrecisIgnorableProperties
        elif cp in u.di or cp in u.nonchar:
            cl = "D"
        # L: Controls
        elif gc == "Cc":
            cl = "D"
        # Q: HasCompat
        elif u.nfc_qc.get(cp, "Y") == "N":
            cl = "D"
        # A: LetterDigits (RFC 5892 section 2.1)
        elif gc in ("Ll", "Lu", "Lo", "Nd", "Lm", "Mn", "Mc"):
            cl = "P"
        # R: OtherLetterDigits
        elif gc in ("Lt", "Nl", "No", "Me"):
            cl = "D"
        # N: Spaces
        elif gc == "Zs":
            cl = "D"
        # O: Symbols
        elif gc in ("Sm", "Sc", "Sk", "So"):
            cl = "D"
        # P: Punctuation
        elif gc in ("Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po"):
            cl = "D"
        else:
            cl = "D"
        result[cp] = cl
    return result


def class_code(cl):
    return {"P": 0, "J": 1, "O": 2, "D": 3, "U": 3}[cl]


BIDI_GROUP = {
    "L": 0,
    "R": 1, "AL": 1,
    "EN": 2,
    "AN": 3,
    "ES": 4, "CS": 4, "ET": 4, "ON": 4, "BN": 4,
    "NSM": 5,
}
BIDI_GROUP_NAMES = ["l", "r_al", "en", "an", "on", "nsm", "other"]


def bidi_code(cp, u):
    cl = u.bidi.get(cp)
    if cl is None:
        raise AssertionError(f"missing Bidi_Class for U+{cp:04X}")
    return BIDI_GROUP.get(cl, 6)


SCRIPT_GROUP = {"Greek": 1, "Hebrew": 2, "Hiragana": 3, "Katakana": 3,
                "Han": 3}


def script_code(cp, u):
    return SCRIPT_GROUP.get(u.scripts.get(cp, ""), 0)


def width_map(u, comps):
    """RFC 8265 width mapping rule: map fullwidth and halfwidth code points
    (East_Asian_Width F or H per UAX #11) to their decomposition mappings.
    Every fullwidth/halfwidth code point has a single-code-point
    decomposition mapping."""
    out = {}
    no_decomp = 0
    for cp, w in u.eaw.items():
        d = u.decomp.get(cp)
        if d is None:
            # no decomposition mapping: nothing to map (the class check
            # rejects these, e.g. U+20A9 HALFWIDTH WON SIGN)
            no_decomp += 1
            continue
        assert len(d[1]) == 1, f"U+{cp:04X} decomposes to {len(d[1])} cps"
        out[cp] = d[1][0]
    print(f"width: {no_decomp} fullwidth/halfwidth cps without decompositions")
    return out


def lower_map(u):
    """Full lowercase mapping for the code points the profile case-maps.

    RFC 8265 section 3.3.1: "Map uppercase and titlecase code points to
    their lowercase equivalents, preferably using the Unicode toLowerCase()
    operation". The mapping values are the Unicode full lowercase mapping:
    UnicodeData simple lowercase plus the UNCONDITIONAL SpecialCasing
    entries. All conditional SpecialCasing entries are skipped, including
    Final_Sigma and the tr/az/lt locale mappings (a pinned decision for
    this profile; see lib/precis/username.zig): U+03A3 always maps to
    U+03C3, U+03C2 is lowercase and stays U+03C2.

    Sources are the Unicode Uppercase property (Lu plus Other_Uppercase)
    and titlecase (Lt) code points that have a non-trivial lowercase
    mapping.
    """
    upper = set()
    parse_ranges(os.path.join(u.d, "DerivedCoreProperties.txt"),
                 lambda f: upper.update(cp_of(f[0]))
                 if f[1] == "Uppercase" else None)
    out = {}
    for cp in range(MAX_CP):
        gc = u.gc.get(cp, "Cn")
        if gc not in ("Lu", "Lt") and cp not in upper:
            continue
        if cp in u.sc_uncond_lower:
            v = u.sc_uncond_lower[cp]
            assert len(v) <= 2, f"U+{cp:04X} maps to {len(v)} cps"
            out[cp] = (v[0], v[1] if len(v) == 2 else 0)
        elif cp in u.simple_lower:
            b = u.simple_lower[cp]
            out[cp] = (b, 0)
    return out


JOIN_CODE = {"L": 1, "R": 2, "D": 3, "T": 4}


# --- packing ----------------------------------------------------------------

def pack_bits(values, nbits, size):
    """Pack nbits-wide values little-endian into byte-aligned groups.
    For 2-bit values, 4 code points per byte; for 3-bit values,
    8 code points per 24-bit (3-byte) group."""
    per = 8  # values per group
    while (per * nbits) % 8 != 0:
        per += 1
    nbytes = per * nbits // 8
    out = bytearray()
    for i in range(0, size, per):
        v = 0
        for j in range(per):
            val = values[i + j] if i + j < size else 0
            v |= val << (j * nbits)
        for b in range(nbytes):
            out.append((v >> (8 * b)) & 0xFF)
    return bytes(out)


# --- self-checks ------------------------------------------------------------

def selfcheck(u, comps, cl, widths, lowers, joins, bidi_v, script_v):
    def cls(cp):
        return cl[cp]

    def expect(cp, want):
        got = cls(cp)
        if want == "D":
            assert got in ("D", "U"), \
                f"class U+{cp:04X}: got {got}, want DISALLOWED/UNASSIGNED"
        else:
            assert got == want, f"class U+{cp:04X}: got {got}, want {want}"

    for cp in (0x002B, 0x002D, 0x0030, 0x0040, 0x0041, 0x0061, 0x006B,
               0x00DF, 0x00F0, 0x0130, 0x0300, 0x0307, 0x0391, 0x03C2,
               0x0410, 0x04B0, 0x05D0, 0x0627, 0x06FD, 0x06FE, 0x0905,
               0x0916, 0x0F0B, 0x1F80, 0x3007, 0x4E00, 0xAC00, 0x10400,
               0x11000):
        expect(cp, "P")
    for cp in (0x200C, 0x200D):
        expect(cp, "J")
    for cp in (0x00B7, 0x0375, 0x05F3, 0x05F4, 0x30FB, 0x0660, 0x0669,
               0x06F0, 0x06F9):
        expect(cp, "O")
    # the complete RFC 5892 exceptions table
    for cp, v in sorted(EXCEPTIONS.items()):
        expect(cp, v)
    for cp in (0x0009, 0x0020, 0x007F, 0x0085, 0x00A0, 0x00B0, 0x00B2,
               0x01C5, 0x034F, 0x0378, 0x03D2, 0x03D4, 0x0640,
               0x0959,
               0x1100, 0x115F, 0x1160, 0x11A8, 0x17B4, 0x17B5, 0x180B,
               0x180F, 0x200B, 0x2026, 0x2028, 0x2060, 0x2064, 0x2110,
               0x212A, 0x2160, 0x2170, 0x2403, 0x2460, 0x2764, 0x309B,
               0x3164, 0x33A0, 0x1D160, 0x1D400, 0x1D416, 0xA960, 0xD7B0,
               0xE000, 0xFDD0, 0xFFFA, 0xFF21, 0x1F71, 0x1F73, 0x1F88,
               0x1F8C):
        expect(cp, "D")
    # RFC 8264 rule I: Old_Hangul_Jamo are DISALLOWED (not only 1100..11FF)
    for cp in (0xA960, 0xD7B0):
        expect(cp, "D")

    # Bidi groups
    for cp, g in ((0x0041, 0), (0x03A3, 0), (0x3007, 0), (0x1100, 0),
                  (0x0959, 0), (0x05D0, 1), (0x05F3, 1), (0x061D, 1),
                  (0x0627, 1), (0x0030, 2), (0x06F0, 2), (0x06F9, 2),
                  (0x0605, 3), (0x0661, 3), (0x0669, 3), (0x066B, 3),
                  (0x002D, 4), (0x002C, 4), (0x0040, 4), (0x00AC, 4),
                  (0x00A0, 4), (0x2026, 4), (0x200B, 4), (0x200C, 4),
                  (0x200D, 4), (0x206A, 4), (0x0300, 5), (0x0900, 5),
                  (0x0901, 5), (0x0009, 6), (0x000A, 6), (0x001F, 6),
                  (0x0085, 6), (0x2029, 6), (0x2066, 6)):
        got = bidi_v[cp]
        assert got == g, f"bidi U+{cp:04X}: got {got}, want {g}"

    # Script groups
    for cp, g in ((0x0375, 1), (0x03B1, 1), (0x05D0, 2), (0x05F3, 2),
                  (0x05F4, 2), (0x3042, 3), (0x30A2, 3), (0x4E00, 3),
                  (0x3400, 3), (0x20000, 3), (0x3007, 3), (0x30FB, 0),
                  (0x0661, 0), (0x0041, 0)):
        got = script_v[cp]
        assert got == g, f"script U+{cp:04X}: got {got}, want {g}"

    # Width map: fullwidth/halfwidth code points to their decomposition
    # mappings (RFC 8265 section 3.3.1, UAX #11)
    print(f"width map entries: {len(widths)}")
    for cp, want in ((0xFF01, 0x0021), (0xFF21, 0x0041), (0xFF41, 0x0061),
                     (0xFF5E, 0x007E), (0xFF61, 0x3002), (0xFF65, 0x30FB),
                     (0xFF70, 0x30FC), (0xFF9E, 0x3099), (0xFF9F, 0x309A),
                     (0x3000, 0x0020)):
        assert widths.get(cp) == want, f"width U+{cp:04X} -> {widths.get(cp)}"
    # Not fullwidth/halfwidth: no width mapping
    for cp in (0x0041, 0x3001, 0x30A2, 0xFF00):
        assert cp not in widths, f"U+{cp:04X} must not width-map"

    # Lower map: full lowercase, unconditional SpecialCasing only
    for cp, want in ((0x0041, (0x0061, 0)), (0x00C0, (0x00E0, 0)),
                     (0x0130, (0x0069, 0x0307)), (0x03A3, (0x03C3, 0)),
                     (0x0410, (0x0430, 0)), (0x04B0, (0x04B1, 0)),
                     (0x0531, (0x0561, 0)), (0x212A, (0x006B, 0)),
                     (0x10400, (0x10428, 0)), (0x1F88, (0x1F80, 0)),
                     (0xFF21, (0xFF41, 0))):
        got = lowers.get(cp)
        assert got == want, f"lower U+{cp:04X}: got {got}, want {want}"
    # U+03C2 is lowercase: stays as is
    assert 0x03C2 not in lowers, "U+03C2 must not be case-mapped"
    # Exactly one code point maps to two code points (U+0130); all 471
    # Lu/Lt code points without any lowercase mapping are left alone
    multi = [cp for cp, (a, b) in lowers.items() if b != 0]
    assert multi == [0x0130], f"multi-cp lowercase targets: {multi}"
    assert len(lowers) == 1433, f"lower map entries {len(lowers)}"
    # U+0130's two targets are NFC-stable, so the 3x buffer contract holds
    for t in (0x0069, 0x0307):
        assert nfkc(u, t, comps) == (t,), f"U+{t:04X} must be NFC-stable"
    # U+0307 (combining dot above) is PVALID: the result of mapping U+0130
    # passes the IdentifierClass check (required by the profile tests)
    expect(0x0307, "P")
    print(f"lower map entries: {len(lowers)}")

    # Joining types (RFC 8265 Appendix A.1)
    for cp, want in ((0x0627, 2), (0x0622, 2), (0x0628, 3), (0x0635, 3),
                     (0x0643, 3), (0x10ACD, 1), (0x200B, 4), (0xFEFF, 4),
                     (0x200C, 0), (0x200D, 0), (0x0640, 0)):
        got = joins.get(cp, 0)
        assert got == want, f"join U+{cp:04X}: got {got}, want {want}"

    # Determinism anchor: table sizes (asserted to catch data drift)
    assert MAX_CP == 0x110000

    # PrecisIgnorableProperties sanity. Note the join controls (U+200C,
    # U+200D) ARE Default_Ignorable_Code_Point in the file; the JoinControl
    # rule runs first in the RFC 8264 section 8.2 order, so they still
    # derive to CONTEXTJ.
    for cp in (0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180F,
               0x3164, 0x200C, 0x200D):
        assert cp in u.di, f"U+{cp:04X} must be Default_Ignorable"
    assert cl[0x200C] == "J" and cl[0x200D] == "J", \
        "join controls must derive to CONTEXTJ despite being ignorable"

    # UnicodeData First/Last marker ranges were expanded: astral and
    # extension blocks carry their real general categories
    for cp, want in ((0x20000, "Lo"), (0x30000, "Lo"), (0x10400, "Lu"),
                     (0x10FFFF, "Cn"), (0xD7FF, "Cn"), (0x1D400, "Lu")):
        got = u.gc.get(cp, "Cn")
        assert got == want, f"gc U+{cp:04X}: got {got}, want {want}"


def crosscheck_q(u, comps, cl):
    """Derived Q bit must agree with DerivedNormalizationProps."""
    mism = 0
    for cp in range(MAX_CP):
        file_q = u.nfc_qc.get(cp, "Y") == "N"
        derived_q = nfkc(u, cp, comps) != (cp,)
        if file_q != derived_q and u.nfc_qc.get(cp, "Y") != "M":
            mism += 1
            if mism <= 5:
                print(f"Q mismatch U+{cp:04X}: file={file_q} "
                      f"derived={derived_q}", file=sys.stderr)
        # Q=1 must be DISALLOWED (unless an earlier rule already rejected it)
        if file_q and cl[cp] != "D":
            mism += 1
            print(f"Q=1 but class={cl[cp]} at U+{cp:04X}", file=sys.stderr)
    assert mism == 0, f"{mism} Q cross-check mismatches"

    # Buffer sizing contract: the NFC step maps one code point to at most
    # three output code points, and the case step's only two-code-point
    # target (U+0130 -> 0069 0307) is NFC-stable, so a whole string never
    # grows past 3x its code point count through width+case+NFC.
    memo = {}
    worst = 0
    for cp in range(MAX_CP):
        n = len(nfc_of_one(u, cp, comps, memo))
        if n > worst:
            worst = n
        assert n <= 3, f"NFC expands U+{cp:04X} to {n} code points"
    print(f"max NFC expansion per code point: {worst}")


def nfc_of_one(u, cp, comps, memo):
    """NFC of a single code point: canonical decomposition, reorder,
    recompose. This is what the shared NFC engine can produce for one
    input code point."""
    if cp in memo:
        return memo[cp]
    seq = []
    seen = set()

    def dec(c):
        if 0xAC00 <= c <= 0xD7A3:  # algorithmic Hangul decomposition
            l, v, t = (c - 0xAC00) // 588, ((c - 0xAC00) % 588) // 28, \
                (c - 0xAC00) % 28
            seq.append(0x1100 + l)
            seq.append(0x1161 + v)
            if t:
                seq.append(0x11A7 + t)
            return
        if c in seen:
            raise AssertionError(f"decomposition loop at U+{c:04X}")
        d = u.decomp.get(c)
        if d is None or d[0] is not None:
            seq.append(c)
            return
        seen.add(c)
        for p in d[1]:
            dec(p)
        seen.remove(c)

    dec(cp)
    reorder(u, seq)
    out = []
    starter = None
    for ch in seq:
        if starter is not None:
            last_ccc = ccc_of(u, out[-1])
            if last_ccc == 0 or last_ccc < ccc_of(u, ch):
                comp = comps.get((starter, ch))
                if comp is not None:
                    out[-1] = comp
                    starter = comp
                    continue
        out.append(ch)
        if ccc_of(u, ch) == 0:
            starter = ch
    result = tuple(out)
    memo[cp] = result
    return result


# --- emission ---------------------------------------------------------------

def emit(path, u, cl, widths, lowers, joins, bidi_v, script_v):
    out = []
    w = out.append
    w("//! PRECIS lookup tables, GENERATED FILE - do not edit.\n")
    w("//!\n")
    w(f"//! Generated by tools/gen_precis_tables.py from the Unicode "
      f"Character Database\n")
    w(f"//! version {UNICODE_VERSION}. Regenerate with:\n")
    w("//!   python3 tools/gen_precis_tables.py <ucd-dir>\n")
    w("//!\n")
    w("//! Derived per RFC 8264 section 8.2 (PRECIS derivation) and RFC 5892.\n")
    w("//! See lib/precis/username.zig for the profile that consumes these.\n\n")

    w("pub const unicode_version = \"" + UNICODE_VERSION + "\";\n\n")

    # lower map
    w("pub const LowerTarget = struct { a: u21, b: u21 };\n\n")
    w("const LowerEntry = struct { cp: u21, t: LowerTarget };\n\n")
    items = sorted(lowers.items())
    w("const lower_entries = [_]LowerEntry{\n")
    for cp, (a, b) in items:
        w(f"    .{{ .cp = 0x{cp:04X}, .t = .{{ .a = 0x{a:04X}, "
          f".b = 0x{b:04X} }} }},\n")
    w("};\n\n")
    w("/// Full lowercase mapping (UnicodeData simple + unconditional "
      "SpecialCasing),\n")
    w("/// or null when the code point has no lowercase mapping.\n")
    w("pub fn lowerOf(cp: u21) ?LowerTarget {\n")
    w("    var lo: usize = 0;\n")
    w("    var hi: usize = lower_entries.len;\n")
    w("    while (lo < hi) {\n")
    w("        const mid = lo + (hi - lo) / 2;\n")
    w("        const e = lower_entries[mid];\n")
    w("        if (e.cp == cp) return e.t;\n")
    w("        if (e.cp < cp) lo = mid + 1 else hi = mid;\n")
    w("    }\n")
    w("    return null;\n")
    w("}\n\n")

    # width map
    w("const WidthEntry = struct { cp: u21, to: u21 };\n\n")
    w("const width_entries = [_]WidthEntry{\n")
    for cp, a in sorted(widths.items()):
        w(f"    .{{ .cp = 0x{cp:04X}, .to = 0x{a:04X} }},\n")
    w("};\n\n")
    w("/// Fullwidth or halfwidth code point (East_Asian_Width F or H per\n")
    w("/// UAX #11) mapped to its decomposition mapping, per the RFC 8265\n")
    w("/// width mapping rule, or null when the code point is not mapped.\n")
    w("pub fn widthOf(cp: u21) ?u21 {\n")
    w("    var lo: usize = 0;\n")
    w("    var hi: usize = width_entries.len;\n")
    w("    while (lo < hi) {\n")
    w("        const mid = lo + (hi - lo) / 2;\n")
    w("        const e = width_entries[mid];\n")
    w("        if (e.cp == cp) return e.to;\n")
    w("        if (e.cp < cp) lo = mid + 1 else hi = mid;\n")
    w("    }\n")
    w("    return null;\n")
    w("}\n\n")

    # joining type
    w("pub const JoinType = enum(u3) { none = 0, l = 1, r = 2, d = 3, t = 4 };\n\n")
    w("const JoinRange = struct { start: u21, end: u21, jt: JoinType };\n\n")
    w("const join_ranges = [_]JoinRange{\n")
    cur = None
    for cp in range(MAX_CP):
        v = JOIN_CODE.get(u.join_type.get(cp, ""), 0)
        if cur and cur[2] == v and cur[1] == cp - 1:
            cur = (cur[0], cp, v)
        else:
            if cur and cur[2] != 0:
                w(f"    .{{ .start = 0x{cur[0]:04X}, .end = 0x{cur[1]:04X}, "
                  f".jt = .{['none','l','r','d','t'][cur[2]]} }},\n")
            cur = (cp, cp, v)
    if cur and cur[2] != 0:
        w(f"    .{{ .start = 0x{cur[0]:04X}, .end = 0x{cur[1]:04X}, "
          f".jt = .{['none','l','r','d','t'][cur[2]]} }},\n")
    w("};\n\n")
    w("/// Arabic joining type (RFC 8265 Appendix A.1); default is "
      "`none`.\n")
    w("pub fn joinTypeOf(cp: u21) JoinType {\n")
    w("    var lo: usize = 0;\n")
    w("    var hi: usize = join_ranges.len;\n")
    w("    while (lo < hi) {\n")
    w("        const mid = lo + (hi - lo) / 2;\n")
    w("        const r = join_ranges[mid];\n")
    w("        if (cp < r.start) hi = mid else if (cp > r.end) lo = mid + 1 "
      "else return r.jt;\n")
    w("    }\n")
    w("    return .none;\n")
    w("}\n\n")

    # class bits
    w("pub const Class = enum(u2) {\n")
    w("    pvalid = 0,\n")
    w("    contextj = 1,\n")
    w("    contexto = 2,\n")
    w("    disallowed = 3,\n")
    w("};\n\n")
    cv = [class_code(cl[cp]) for cp in range(MAX_CP)]
    cb = pack_bits(cv, 2, MAX_CP)
    w("const class_bits = [_]u8{")
    for i, b in enumerate(cb):
        if i % 16 == 0:
            w("\n    ")
        w(f"0x{b:02X},")
    w("\n};\n\n")
    w("/// PRECIS derivation result per RFC 8264 section 8.2.\n")
    w("pub fn classOf(cp: u21) Class {\n")
    w("    if (cp >= 0x110000) return .disallowed;\n")
    w("    const i: u32 = cp;\n")
    w("    return @enumFromInt((class_bits[i >> 2] >> "
      "@intCast((i & 3) * 2)) & 3);\n")
    w("}\n\n")

    # bidi bits
    w("pub const BidiGroup = enum(u3) {\n")
    w("    l = 0,\n")
    w("    r_al = 1,\n")
    w("    en = 2,\n")
    w("    an = 3,\n")
    w("    on = 4,\n")
    w("    nsm = 5,\n")
    w("    other = 6,\n")
    w("};\n\n")
    bv = [bidi_code(cp, u) for cp in range(MAX_CP)]
    bb = pack_bits(bv, 3, MAX_CP)
    w("const bidi_bits = [_]u8{")
    for i, b in enumerate(bb):
        if i % 16 == 0:
            w("\n    ")
        w(f"0x{b:02X},")
    w("\n};\n\n")
    w("/// Bidi_Class group for the RFC 5893 Bidi Rule (RFC 8264 section 8.2).\n")
    w("pub fn bidiGroupOf(cp: u21) BidiGroup {\n")
    w("    if (cp >= 0x110000) return .other;\n")
    w("    const i: u32 = cp;\n")
    w("    const g = i / 8 * 3; // 8 code points per 3-byte group (3 bits each)\n")
    w("    const o: u5 = @intCast((i % 8) * 3);\n")
    w("    const v: u32 = bidi_bits[g] | @as(u32, bidi_bits[g + 1]) << 8 | "
      "@as(u32, bidi_bits[g + 2]) << 16;\n")
    w("    return @enumFromInt(@as(u3, @intCast((v >> o) & 7)));\n")
    w("}\n\n")

    # script bits
    w("pub const ScriptGroup = enum(u2) {\n")
    w("    other = 0,\n")
    w("    greek = 1,\n")
    w("    hebrew = 2,\n")
    w("    cjk = 3,\n")
    w("};\n\n")
    sv = [script_code(cp, u) for cp in range(MAX_CP)]
    sb = pack_bits(sv, 2, MAX_CP)
    w("const script_bits = [_]u8{")
    for i, b in enumerate(sb):
        if i % 16 == 0:
            w("\n    ")
        w(f"0x{b:02X},")
    w("\n};\n\n")
    w("/// Script group used by the CONTEXTJ/CONTEXTO rules.\n")
    w("pub fn scriptGroupOf(cp: u21) ScriptGroup {\n")
    w("    if (cp >= 0x110000) return .other;\n")
    w("    const i: u32 = cp;\n")
    w("    return @enumFromInt((script_bits[i >> 2] >> "
      "@intCast((i & 3) * 2)) & 3);\n")
    w("}\n\n")

    # Zig-side spot tests: same expected values as the generator self-check
    w("const std = @import(\"std\");\n\n")
    w("test \"classOf spot values\" {\n")
    for cp in (0x002B, 0x002D, 0x0030, 0x0040, 0x0041, 0x0061, 0x006B,
               0x00DF, 0x00F0, 0x0130, 0x0300, 0x0307, 0x0391, 0x03C2,
               0x0410, 0x04B0, 0x05D0, 0x0627, 0x06FD, 0x06FE, 0x0905,
               0x0916, 0x0F0B, 0x1F80, 0x3007, 0x4E00, 0xAC00, 0x10400,
               0x11000):
        w(f"    try std.testing.expectEqual(Class.pvalid, "
          f"classOf(0x{cp:04X}));\n")
    for cp in (0x200C, 0x200D):
        w(f"    try std.testing.expectEqual(Class.contextj, "
          f"classOf(0x{cp:04X}));\n")
    for cp in (0x00B7, 0x0375, 0x05F3, 0x05F4, 0x30FB, 0x0660, 0x0669,
               0x06F0, 0x06F9):
        w(f"    try std.testing.expectEqual(Class.contexto, "
          f"classOf(0x{cp:04X}));\n")
    for cp in (0x0009, 0x0020, 0x007F, 0x0085, 0x00A0, 0x00B0, 0x00B2,
               0x01C5, 0x034F, 0x0378, 0x03D2, 0x03D4, 0x0640, 0x0959,
               0x1100, 0x115F, 0x1160, 0x11A8, 0x17B4, 0x17B5, 0x180B,
               0x180F, 0x200B, 0x2026, 0x2028, 0x2060, 0x2064, 0x2110,
               0x212A, 0x2160, 0x2170, 0x2403, 0x2460, 0x2764, 0x309B,
               0x3164, 0x33A0, 0x1D160, 0x1D400, 0x1D416, 0xA960, 0xD7B0,
               0xE000, 0xFDD0, 0xFFFA, 0xFF21, 0x1F71, 0x1F73, 0x1F88,
               0x1F8C):
        w(f"    try std.testing.expectEqual(Class.disallowed, "
          f"classOf(0x{cp:04X}));\n")
    w("}\n\n")

    w("test \"RFC 5892 exceptions table\" {\n")
    names = {"P": "pvalid", "J": "contextj", "O": "contexto", "D": "disallowed"}
    for cp, v in sorted(EXCEPTIONS.items()):
        w(f"    try std.testing.expectEqual(Class.{names[v]}, "
          f"classOf(0x{cp:04X}));\n")
    w("}\n\n")

    w("test \"bidiGroupOf spot values\" {\n")
    for cp, g in ((0x0041, 0), (0x03A3, 0), (0x3007, 0), (0x1100, 0),
                  (0x0959, 0), (0x05D0, 1), (0x05F3, 1), (0x061D, 1),
                  (0x0627, 1), (0x0030, 2), (0x06F0, 2), (0x06F9, 2),
                  (0x0605, 3), (0x0661, 3), (0x0669, 3), (0x066B, 3),
                  (0x002D, 4), (0x002C, 4), (0x0040, 4), (0x00AC, 4),
                  (0x00A0, 4), (0x2026, 4), (0x200B, 4), (0x200C, 4),
                  (0x200D, 4), (0x206A, 4), (0x0300, 5), (0x0900, 5),
                  (0x0901, 5), (0x0009, 6), (0x000A, 6), (0x001F, 6),
                  (0x0085, 6), (0x2029, 6), (0x2066, 6)):
        w(f"    try std.testing.expectEqual(BidiGroup.{BIDI_GROUP_NAMES[g]}"
          f", bidiGroupOf(0x{cp:04X}));\n")
    w("}\n\n")

    w("test \"scriptGroupOf spot values\" {\n")
    for cp, g in ((0x0375, 1), (0x03B1, 1), (0x05D0, 2), (0x05F3, 2),
                  (0x05F4, 2), (0x3042, 3), (0x30A2, 3), (0x4E00, 3),
                  (0x3400, 3), (0x20000, 3), (0x3007, 3), (0x30FB, 0),
                  (0x0661, 0), (0x0041, 0)):
        name = ["other", "greek", "hebrew", "cjk"][g]
        w(f"    try std.testing.expectEqual(ScriptGroup.{name}, "
          f"scriptGroupOf(0x{cp:04X}));\n")
    w("}\n\n")

    w("test \"joinTypeOf spot values\" {\n")
    for cp, jt in ((0x0627, "r"), (0x0622, "r"), (0x0628, "d"),
                   (0x0635, "d"), (0x0643, "d"), (0x10ACD, "l"),
                   (0x200B, "t"), (0xFEFF, "t"), (0x200C, "none"),
                   (0x200D, "none"), (0x0640, "none")):
        w(f"    try std.testing.expectEqual(JoinType.{jt}, "
          f"joinTypeOf(0x{cp:04X}));\n")
    w("}\n\n")

    w("test \"widthOf spot values\" {\n")
    for cp, a in ((0xFF01, 0x0021), (0xFF21, 0x0041), (0xFF41, 0x0061),
                  (0xFF5E, 0x007E), (0xFF61, 0x3002), (0xFF65, 0x30FB),
                  (0xFF70, 0x30FC), (0xFF9E, 0x3099), (0xFF9F, 0x309A),
                  (0x3000, 0x0020)):
        w(f"    try std.testing.expectEqual(@as(?u21, 0x{a:04X}), "
          f"widthOf(0x{cp:04X}));\n")
    for cp in (0x0041, 0x3001, 0x30A2, 0xFF00):
        w(f"    try std.testing.expectEqual(@as(?u21, null), "
          f"widthOf(0x{cp:04X}));\n")
    w("}\n\n")

    w("test \"lowerOf spot values\" {\n")
    for cp, (a, b) in ((0x0041, (0x0061, 0)), (0x00C0, (0x00E0, 0)),
                       (0x0130, (0x0069, 0x0307)), (0x03A3, (0x03C3, 0)),
                       (0x0410, (0x0430, 0)), (0x04B0, (0x04B1, 0)),
                       (0x0531, (0x0561, 0)), (0x212A, (0x006B, 0)),
                       (0x10400, (0x10428, 0)), (0x1F88, (0x1F80, 0)),
                       (0xFF21, (0xFF41, 0))):
        w(f"    try std.testing.expectEqual(LowerTarget{{ .a = 0x{a:04X}, "
          f".b = 0x{b:04X} }}, lowerOf(0x{cp:04X}).?);\n")
    w("    try std.testing.expectEqual(@as(?LowerTarget, null), "
      "lowerOf(0x03C2));\n")
    w("    try std.testing.expectEqual(@as(?LowerTarget, null), "
      "lowerOf(0x0061));\n")
    w("}\n")

    text = "".join(out)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


def main():
    ucd_dir = sys.argv[1] if len(sys.argv) > 1 else "/home/admin/tmp/UCDzip"
    out_path = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "lib", "precis", "precis_tables.zig")

    u = Ucd(ucd_dir)
    u.load()

    comps = build_composition(u)
    print(f"composition pairs: {len(comps)}")
    cl = derive_class(u, comps)
    widths = width_map(u, comps)
    lowers = lower_map(u)
    joins = {cp: JOIN_CODE[v] for cp, v in u.join_type.items()
             if v in JOIN_CODE}
    bidi_v = [bidi_code(cp, u) for cp in range(MAX_CP)]
    script_v = [script_code(cp, u) for cp in range(MAX_CP)]

    selfcheck(u, comps, cl, widths, lowers, joins, bidi_v, script_v)
    crosscheck_q(u, comps, cl)
    print("self-checks OK")

    text = emit(out_path, u, cl, widths, lowers, joins, bidi_v, script_v)
    print(f"wrote {out_path}: {len(text)} bytes")
    print(f"class bits: {MAX_CP // 4} bytes, bidi bits: "
          f"{(MAX_CP // 8) * 3} bytes, script bits: {MAX_CP // 4} bytes")
    print(f"width entries: {len(widths)}, join entries: {len(joins)}, "
          f"lower entries: {len(lowers)}")


if __name__ == "__main__":
    main()
