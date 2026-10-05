#!/bin/sh
# M4 silent-failure ratchet (T-4D163119, plan rule 5).
#
# Counts `catch {}`, `catch return`, `catch continue` and `catch false` in
# src/ and fails when any file's count per pattern exceeds the recorded
# baseline (test/quality/catch_baseline.tsv). Counts may only go down over
# time: lower the baseline by editing the TSV when a pattern is fixed.
#
# usage: catch_ratchet.sh
set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$SELF_DIR/../..
BASELINE=$SELF_DIR/catch_baseline.tsv
PATTERNS="catch \{\}|catch return|catch continue|catch false"

STATUS=0
echo "catch_ratchet: baseline $BASELINE"

# Current counts per file pattern, as lines "<file>|<pattern>|<count>".
CURRENT=$(
    cd "$ROOT" &&
    grep -rnoE "$PATTERNS" src --include=*.zig |
        sed 's/\.zig:[0-9]*:/.zig|/' |
        awk '{ c[$0]++ } END { for (k in c) print k "|" c[k] }' |
        sort
)

FRESH=$(echo "$CURRENT" | awk -F'|' -v bf="$BASELINE" '
BEGIN {
    while ((getline line < bf) > 0) {
        n = split(line, a, "\t")
        if (n >= 3) base[a[1] "|" a[2]] = a[3]
    }
    close(bf)
}
{
    key = $1 "|" $2
    b = (key in base) ? base[key] : 0
    if ($3 + 0 > b + 0) printf "catch_ratchet: INCREASED %s %s: %d > %d\n", $1, $2, $3, b
}')

if [ -n "$FRESH" ]; then
    echo "$FRESH"
    STATUS=1
fi

if [ "$STATUS" -eq 0 ]; then
    echo "catch_ratchet: OK (no pattern above baseline)"
    echo "catch_ratchet: remember to lower $BASELINE when fixing a pattern"
fi
exit $STATUS
