#!/usr/bin/env python3
"""XEP feature-matrix consistency check.

Guards against the class of documentation/code drift that produced T163, T164,
T169: the server's advertised feature set is maintained by hand in three places
that must agree, but nothing enforced it.

The three sources of truth this checks:

  1. src/core/caps.zig  -> SERVER_FEATURES
        The feature list hashed into the XEP-0115 entity-caps `ver` string
        (computeServerCaps).

  2. src/core/iq_handler.zig  -> the server disco#info response
        The <feature var='...'/> elements actually sent to clients.

  3. README.md  -> the "Standards Compliance" XEP matrix
        The human-facing support claims.

Checks performed:

  [HARD]  caps.SERVER_FEATURES  ==  disco#info feature set
          The whole point of XEP-0115 is that a client can recompute the hash
          from disco#info and match the advertised `ver`. If the two lists
          differ, verification fails and caps caching is defeated. (This is
          exactly T163: jabber:iq:register was in disco#info but not in the
          hashed list.)

  [HARD]  caps.SERVER_FEATURES is sorted ascending
          computeServerCaps() relies on the list already being in the XEP-0115
          section 5.1 canonical order; an out-of-order entry silently produces
          a wrong hash. (Mirror of the existing Zig unit test, kept here so the
          check is self-contained.)

  [SOFT]  every advertised namespace is represented in the README matrix
          Advisory only: catches a feature shipped but never documented, or a
          README row whose namespace is no longer advertised (T169 shape).

Deliberately NOT checked: semantic completeness behind an advertised namespace
(a stub handler that answers but does nothing, e.g. T164/T165). A matrix check
sees advertisement, not behaviour. Those need their own targeted tests.

Exit status: 0 if all HARD checks pass (SOFT warnings do not fail CI), 1
otherwise. Pass --strict to also fail on SOFT warnings.

Runs on any Python 2.7 / 3.x (kept dependency- and syntax-light on purpose so
it works in a minimal CI image).
"""

from __future__ import print_function

import io
import os
import re
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CAPS_ZIG = os.path.join(REPO_ROOT, "src", "core", "caps.zig")
IQ_HANDLER_ZIG = os.path.join(REPO_ROOT, "src", "core", "iq_handler.zig")
README = os.path.join(REPO_ROOT, "README.md")

# Map advertised disco#info namespaces to the XEP number the README documents
# them under. Namespaces intentionally absent from the matrix (RFC-level
# features like jabber:iq:roster) map to None and are skipped by the advisory
# check.
NS_TO_XEP = {
    "jabber:iq:last": "XEP-0012",
    "http://jabber.org/protocol/disco#info": "XEP-0030",
    "http://jabber.org/protocol/disco#items": "XEP-0030",
    "vcard-temp": "XEP-0054",
    "jabber:iq:register": "XEP-0077",
    "urn:xmpp:avatar:metadata+notify": "XEP-0084",
    "http://jabber.org/protocol/chatstates": "XEP-0085",
    "jabber:iq:version": "XEP-0092",
    "http://jabber.org/protocol/caps": "XEP-0115",
    "msgoffline": "XEP-0160",
    "urn:xmpp:receipts": "XEP-0184",
    "urn:xmpp:blocking": "XEP-0191",
    "urn:xmpp:sm:3": "XEP-0198",
    "urn:xmpp:ping": "XEP-0199",
    "urn:xmpp:carbons:2": "XEP-0280",
    "urn:xmpp:message-correct:0": "XEP-0308",
    "urn:xmpp:mam:2": "XEP-0313",
    "urn:xmpp:chat-markers:0": "XEP-0333",
    "urn:xmpp:hints": "XEP-0334",
    "urn:xmpp:csi:0": "XEP-0352",
    "urn:xmpp:sid:0": "XEP-0359",
    "urn:xmpp:bookmarks:1#notify": "XEP-0402",
    # PEP/PubSub sub-features are all documented under the PEP row.
    "jabber:iq:roster": None,
    "http://jabber.org/protocol/pubsub#publish": "XEP-0163",
    "http://jabber.org/protocol/pubsub#subscribe": "XEP-0163",
    "http://jabber.org/protocol/pubsub#auto-subscribe": "XEP-0163",
    "http://jabber.org/protocol/pubsub#auto-create": "XEP-0163",
    "http://jabber.org/protocol/pubsub#persistent-items": "XEP-0163",
    "http://jabber.org/protocol/pubsub#retrieve-items": "XEP-0163",
}


class CheckError(Exception):
    pass


def read(path):
    if not os.path.isfile(path):
        raise CheckError("expected file not found: %s" % os.path.relpath(path, REPO_ROOT))
    with io.open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def parse_caps_features(src):
    """Ordered string literals from `const SERVER_FEATURES = [_][]const u8{ ... };`."""
    m = re.search(
        r"const\s+SERVER_FEATURES\s*=\s*\[_\]\[\]const u8\{(.*?)\};",
        src,
        re.DOTALL,
    )
    if not m:
        raise CheckError("could not locate SERVER_FEATURES array in caps.zig")
    return re.findall(r'"([^"]+)"', m.group(1))


def parse_disco_features(src):
    """<feature var='...'/> from the server disco#info block.

    Scoped to the block starting at the server identity element so MUC/room
    disco features elsewhere in the file are not swept in.
    """
    start = src.find("<identity category='server' type='im'")
    if start == -1:
        raise CheckError("could not locate server disco#info identity in iq_handler.zig")
    end = src.find("</query>", start)
    if end == -1:
        raise CheckError("could not locate end of server disco#info block")
    block = src[start:end]
    return re.findall(r"<feature var='([^']+)'/>", block)


def parse_readme_xeps(src):
    """Return {XEP-####: support} from the README standards-compliance table."""
    xeps = {}
    for row in re.finditer(r"^\|\s*(XEP-\d{4})\s*\|[^|]*\|\s*([^|]+?)\s*\|", src, re.MULTILINE):
        xeps[row.group(1)] = row.group(2).strip()
    return xeps


def main(argv):
    strict = "--strict" in argv[1:]

    try:
        caps_list = parse_caps_features(read(CAPS_ZIG))
        disco_list = parse_disco_features(read(IQ_HANDLER_ZIG))
        readme_xeps = parse_readme_xeps(read(README))
    except CheckError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2

    caps = set(caps_list)
    disco = set(disco_list)

    hard_failures = 0
    soft_warnings = 0

    print("caps.SERVER_FEATURES : %d features" % len(caps_list))
    print("disco#info response  : %d features" % len(disco_list))
    print("README XEP matrix     : %d XEP rows" % len(readme_xeps))
    print("")

    # ---- HARD 1: caps hash set == disco#info set --------------------------
    only_disco = sorted(disco - caps)
    only_caps = sorted(caps - disco)
    if only_disco or only_caps:
        hard_failures += 1
        print("FAIL  caps.SERVER_FEATURES does not match the disco#info response.")
        print("      The XEP-0115 `ver` hash is computed over SERVER_FEATURES, so any")
        print("      mismatch means the advertised caps hash will not verify.")
        for f in only_disco:
            print("        + advertised in disco#info but NOT hashed in caps.zig: %s" % f)
        for f in only_caps:
            print("        - hashed in caps.zig but NOT advertised in disco#info: %s" % f)
        print("")
    else:
        print("ok    caps.SERVER_FEATURES == disco#info feature set")

    # ---- HARD 2: caps list is sorted --------------------------------------
    if caps_list != sorted(caps_list):
        hard_failures += 1
        print("FAIL  SERVER_FEATURES is not sorted ascending; computeServerCaps()")
        print("      assumes XEP-0115 section 5.1 canonical order and will hash wrong.")
        for a, b in zip(caps_list, caps_list[1:]):
            if a > b:
                print("        out of order: %r precedes %r" % (a, b))
        print("")
    else:
        print("ok    SERVER_FEATURES is sorted ascending")

    # ---- SOFT: advertised namespaces represented in README ----------------
    unknown_ns = sorted(f for f in disco if f not in NS_TO_XEP)
    if unknown_ns:
        soft_warnings += 1
        print("warn  advertised namespace has no README mapping (update NS_TO_XEP or README):")
        for f in unknown_ns:
            print("        %s" % f)

    missing_in_readme = sorted(set(
        NS_TO_XEP[f]
        for f in disco
        if NS_TO_XEP.get(f) and NS_TO_XEP[f] not in readme_xeps
    ))
    if missing_in_readme:
        soft_warnings += 1
        print("warn  advertised feature whose XEP is absent from the README matrix:")
        for x in missing_in_readme:
            print("        %s" % x)

    if not unknown_ns and not missing_in_readme:
        print("ok    every advertised namespace maps to a documented README XEP row")

    print("")
    print("summary: %d hard failure(s), %d advisory warning(s)" % (hard_failures, soft_warnings))

    if hard_failures:
        return 1
    if strict and soft_warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
