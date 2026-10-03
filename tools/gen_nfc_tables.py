#!/usr/bin/env python3
"""Regenerate lib/sasl/nfc_tables.zig from the host's unicodedata.

Emits canonical decomposition pairs, canonical combining class ranges and
canonical composition pairs (pairs validated against Python's own NFC so the
table is self-consistent by construction). NFC is stable for assigned code
points, so regenerating with a newer Unicode version only ever adds entries.
"""
import unicodedata

OUT = "lib/sasl/nfc_tables.zig"

decomp = {}
ccc = {}
for cp in range(0x110000):
    if 0xD800 <= cp <= 0xDFFF:
        continue
    ch = chr(cp)
    d = unicodedata.decomposition(ch)
    if d and not d.startswith("<"):
        decomp[cp] = [int(x, 16) for x in d.split()]
    c = unicodedata.combining(ch)
    if c:
        ccc[cp] = c

comp = {}
for cp, parts in decomp.items():
    if len(parts) == 2:
        a, b = parts
        if unicodedata.normalize("NFC", chr(a) + chr(b)) == chr(cp):
            comp[(a, b)] = cp

ccc_ranges = []
items = sorted(ccc.items())
start = prev = items[0][0]
cls = items[0][1]
for cp, c in items[1:]:
    if cp == prev + 1 and c == cls:
        prev = cp
        continue
    ccc_ranges.append((start, prev, cls))
    start = prev = cp
    cls = c
ccc_ranges.append((start, prev, cls))

with open(OUT, "w") as f:
    f.write("//! Generated NFC tables (canonical decomposition, canonical combining\n")
    f.write("//! class ranges, composition pairs). Source: Python unicodedata %s.\n" % unicodedata.unidata_version)
    f.write("//! Regenerate with tools/gen_nfc_tables.py. Do not edit by hand.\n\n")
    f.write("pub const Decomp = struct { cp: u21, a: u21, b: u21 };\n")
    f.write("pub const decomps = [_]Decomp{\n")
    for cp, parts in sorted(decomp.items()):
        a = parts[0]
        b = parts[1] if len(parts) > 1 else 0
        f.write("    .{ .cp = 0x%X, .a = 0x%X, .b = 0x%X },\n" % (cp, a, b))
    f.write("};\n\n")
    f.write("pub const CccRange = struct { lo: u21, hi: u21, ccc: u8 };\n")
    f.write("pub const ccc_ranges = [_]CccRange{\n")
    for lo, hi, c in ccc_ranges:
        f.write("    .{ .lo = 0x%X, .hi = 0x%X, .ccc = %d },\n" % (lo, hi, c))
    f.write("};\n\n")
    f.write("pub const Comp = struct { a: u21, b: u21, cp: u21 };\n")
    f.write("pub const comps = [_]Comp{\n")
    for (a, b), cp in sorted(comp.items()):
        f.write("    .{ .a = 0x%X, .b = 0x%X, .cp = 0x%X },\n" % (a, b, cp))
    f.write("};\n")

print("decomps", len(decomp), "ccc_ranges", len(ccc_ranges), "comps", len(comp), "unicode", unicodedata.unidata_version)
