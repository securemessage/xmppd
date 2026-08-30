# XEP feature-matrix consistency check (portable awk implementation).
#
# Guards the drift class behind T163/T164/T169: the server's advertised feature
# set is hand-maintained in three places that must agree, with nothing enforcing
# it. See test/consistency/README.md for rationale.
#
# Invoked as:  awk -f check_xep_matrix.awk caps.zig iq_handler.zig README.md
# (the wrapper check_xep_matrix.sh resolves those paths). Uses only base-system
# awk features so it runs under FreeBSD's one-true-awk as well as gawk — no
# python, no packages, so it works on a bare FreeBSD CI runner.
#
# Pass -v strict=1 to also fail on advisory (SOFT) warnings.

BEGIN {
    # Advertised namespace -> XEP number it is documented under in the README.
    # "known" lists every namespace we expect to see advertised; "xep" maps the
    # ones that correspond to a numbered XEP row (RFC-level features have none).
    known["http://jabber.org/protocol/disco#info"]=1; xep["http://jabber.org/protocol/disco#info"]="XEP-0030"
    known["http://jabber.org/protocol/disco#items"]=1; xep["http://jabber.org/protocol/disco#items"]="XEP-0030"
    known["urn:xmpp:ping"]=1;                          xep["urn:xmpp:ping"]="XEP-0199"
    known["jabber:iq:roster"]=1                        # RFC 6121, no XEP row
    known["vcard-temp"]=1;                             xep["vcard-temp"]="XEP-0054"
    known["jabber:iq:version"]=1;                      xep["jabber:iq:version"]="XEP-0092"
    known["msgoffline"]=1;                             xep["msgoffline"]="XEP-0160"
    known["urn:xmpp:mam:2"]=1;                         xep["urn:xmpp:mam:2"]="XEP-0313"
    known["urn:xmpp:sid:0"]=1;                         xep["urn:xmpp:sid:0"]="XEP-0359"
    known["urn:xmpp:carbons:2"]=1;                     xep["urn:xmpp:carbons:2"]="XEP-0280"
    known["http://jabber.org/protocol/chatstates"]=1;  xep["http://jabber.org/protocol/chatstates"]="XEP-0085"
    known["urn:xmpp:receipts"]=1;                      xep["urn:xmpp:receipts"]="XEP-0184"
    known["urn:xmpp:message-correct:0"]=1;             xep["urn:xmpp:message-correct:0"]="XEP-0308"
    known["urn:xmpp:blocking"]=1;                      xep["urn:xmpp:blocking"]="XEP-0191"
    known["urn:xmpp:sm:3"]=1;                          xep["urn:xmpp:sm:3"]="XEP-0198"
    known["http://jabber.org/protocol/pubsub#publish"]=1;         xep["http://jabber.org/protocol/pubsub#publish"]="XEP-0163"
    known["http://jabber.org/protocol/pubsub#subscribe"]=1;       xep["http://jabber.org/protocol/pubsub#subscribe"]="XEP-0163"
    known["http://jabber.org/protocol/pubsub#auto-subscribe"]=1;  xep["http://jabber.org/protocol/pubsub#auto-subscribe"]="XEP-0163"
    known["http://jabber.org/protocol/pubsub#auto-create"]=1;     xep["http://jabber.org/protocol/pubsub#auto-create"]="XEP-0163"
    known["http://jabber.org/protocol/pubsub#persistent-items"]=1; xep["http://jabber.org/protocol/pubsub#persistent-items"]="XEP-0163"
    known["http://jabber.org/protocol/pubsub#retrieve-items"]=1;  xep["http://jabber.org/protocol/pubsub#retrieve-items"]="XEP-0163"
    known["urn:xmpp:avatar:metadata+notify"]=1;        xep["urn:xmpp:avatar:metadata+notify"]="XEP-0084"
    known["urn:xmpp:bookmarks:1#notify"]=1;            xep["urn:xmpp:bookmarks:1#notify"]="XEP-0402"
    known["urn:xmpp:chat-markers:0"]=1;                xep["urn:xmpp:chat-markers:0"]="XEP-0333"
    known["urn:xmpp:hints"]=1;                         xep["urn:xmpp:hints"]="XEP-0334"
    known["jabber:iq:last"]=1;                         xep["jabber:iq:last"]="XEP-0012"
    known["urn:xmpp:csi:0"]=1;                         xep["urn:xmpp:csi:0"]="XEP-0352"
    known["http://jabber.org/protocol/caps"]=1;        xep["http://jabber.org/protocol/caps"]="XEP-0115"
    known["jabber:iq:register"]=1;                     xep["jabber:iq:register"]="XEP-0077"

    ncaps=0; ndisco=0
    in_caps=0; in_disco=0
}

# ---- caps.zig: the SERVER_FEATURES array (ordered) ----
index(FILENAME, "caps.zig") {
    if (index($0, "SERVER_FEATURES = [_][]const u8{")) { in_caps=1; next }
    if (in_caps && index($0, "};")) { in_caps=0; next }
    if (in_caps && match($0, /"[^"]+"/)) {
        f = substr($0, RSTART+1, RLENGTH-2)
        ncaps++; caps_ord[ncaps]=f; caps_set[f]=1
    }
    next
}

# ---- iq_handler.zig: the server disco#info feature block ----
index(FILENAME, "iq_handler.zig") {
    if (index($0, "<identity category='server' type='im'")) { in_disco=1 }
    if (in_disco && match($0, /var='[^']+'/)) {
        f = substr($0, RSTART+5, RLENGTH-6)
        disco_set[f]=1; ndisco++
    }
    if (in_disco && index($0, "</query>")) { in_disco=0 }
    next
}

# ---- README.md: the Standards Compliance table rows ----
$0 ~ /^\| *XEP-/ {
    if (match($0, /XEP-[0-9][0-9][0-9][0-9]/)) {
        readme_set[substr($0, RSTART, RLENGTH)]=1
    }
    next
}

END {
    printf "caps.SERVER_FEATURES : %d features\n", ncaps
    printf "disco#info response  : %d features\n", ndisco
    n=0; for (x in readme_set) n++
    printf "README XEP matrix     : %d XEP rows\n\n", n

    hard=0; soft=0

    # ---- HARD 1: caps hash set == disco#info set ----
    mismatch=0
    for (f in disco_set) if (!(f in caps_set)) mismatch=1
    for (f in caps_set)  if (!(f in disco_set)) mismatch=1
    if (mismatch) {
        hard++
        print "FAIL  caps.SERVER_FEATURES does not match the disco#info response."
        print "      The XEP-0115 `ver` hash is computed over SERVER_FEATURES, so any"
        print "      mismatch means the advertised caps hash will not verify."
        for (f in disco_set) if (!(f in caps_set))
            print "        + advertised in disco#info but NOT hashed in caps.zig: " f
        for (f in caps_set) if (!(f in disco_set))
            print "        - hashed in caps.zig but NOT advertised in disco#info: " f
        print ""
    } else {
        print "ok    caps.SERVER_FEATURES == disco#info feature set"
    }

    # ---- HARD 2: caps list sorted ascending ----
    unsorted=0
    for (i=2; i<=ncaps; i++)
        if ((caps_ord[i-1] "") > (caps_ord[i] "")) unsorted=1
    if (unsorted) {
        hard++
        print "FAIL  SERVER_FEATURES is not sorted ascending; computeServerCaps()"
        print "      assumes XEP-0115 section 5.1 canonical order and will hash wrong."
        for (i=2; i<=ncaps; i++)
            if ((caps_ord[i-1] "") > (caps_ord[i] ""))
                print "        out of order: " caps_ord[i-1] " precedes " caps_ord[i]
        print ""
    } else {
        print "ok    SERVER_FEATURES is sorted ascending"
    }

    # ---- SOFT: advertised namespaces represented in README ----
    softmsg=0
    for (f in disco_set) if (!(f in known)) {
        if (!softmsg) { print "warn  advertised namespace has no README mapping (update the map or README):"; softmsg=1; soft++ }
        print "        " f
    }
    missmsg=0
    for (f in disco_set) if ((f in xep) && !(xep[f] in readme_set)) {
        if (!missmsg) { print "warn  advertised feature whose XEP is absent from the README matrix:"; missmsg=1; soft++ }
        print "        " xep[f]
    }
    if (!softmsg && !missmsg)
        print "ok    every advertised namespace maps to a documented README XEP row"

    printf "\nsummary: %d hard failure(s), %d advisory warning(s)\n", hard, soft

    if (hard > 0) exit 1
    if (strict != "" && soft > 0) exit 1
    exit 0
}
