#!/bin/sh
# M4 stack-frame report (T-4D163119, plan rule 6).
#
# Disassembles the built xmppd-core binary and reports every src/core-module
# function whose maximal prolog frame exceeds the 16 KiB threshold. Two
# prolog shapes are recognised: a direct `subq $N, %rsp`, and a stack-probe
# sequence `movl $N, %eax; callq __zig_probe_stack; subq %rax, %rsp` where
# the frame size is the movl immediate. Frames already on the allow-list
# print as INFO; anything NEW fails the check (exit 1), which makes the
# ratchet one-directional (frames may shrink, never grow into).
#
# Symbols keep Zig module naming (<file>.<scope>.<fn>); the src/core match
# set is built from src/core/*.zig at run time so new core files are
# covered without a script edit.
#
# usage: stack_frames.sh [binary] [threshold_bytes]
set -u

BIN=${1:-zig-out/bin/xmppd-core}
THRESH=${2:-16384}
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ALLOW="$SELF_DIR/stack_frames_core.allow"
OBJDUMP=${OBJDUMP:-llvm-objdump}

if [ ! -x "$BIN" ]; then
    echo "stack_frames: $BIN not found (build first)" >&2
    exit 2
fi

CORE_MODS=$(ls "$SELF_DIR"/../../src/core/*.zig | xargs -n1 basename | sed 's/\.zig$//' | paste -sd '|' -)
CORE_RE="^(${CORE_MODS})\\."

CURRENT=$($OBJDUMP -d --no-show-raw-insn "$BIN" | awk -v t="$THRESH" -v modre="$CORE_RE" '
function hex2d(s,   n,i,c,d) {
    n = 0
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        d = index("0123456789abcdef", c) - 1
        if (d < 0) d = index("0123456789ABCDEF", c) - 1
        n = n * 16 + d
    }
    return n
}
function flush() {
    if (fname != "" && fmax > t) printf "%s %d\n", fname, fmax
}
/^[0-9a-f]+ </ {
    flush()
    fname = $0
    sub(/^[0-9a-f]+ </, "", fname)
    sub(/>:$/, "", fname)
    fmax = 0
    pending = 0
    next
}
/movl[ \t]+\$0x[0-9a-f]+,[ \t]+%eax/ {
    if (fname ~ modre) {
        h = $0
        sub(/.*\$0x/, "", h)
        sub(/,.*/, "", h)
        pending = hex2d(h)
    }
    next
}
/callq?[ \t]+.*__zig_probe_stack/ {
    if ((fname ~ modre) && pending > fmax) fmax = pending
    pending = 0
    next
}
/subq[ \t]+\$0x[0-9a-f]+,[ \t]+%rsp/ {
    if (fname ~ modre) {
        h = $0
        sub(/.*\$0x/, "", h)
        sub(/,.*/, "", h)
        n = hex2d(h)
        if (n > fmax) fmax = n
    }
    pending = 0
    next
}
END { flush() }' | sort)

echo "stack_frames: threshold $THRESH bytes, binary $BIN"
REPORT=$(echo "$CURRENT" | while read -r name frame; do
    [ -n "$name" ] || continue
    cap=$(awk -v n="$name" '$1 == n { print $2; exit }' "$ALLOW" 2>/dev/null)
    if [ -z "$cap" ]; then
        echo "stack_frames: NEW over-threshold frame: $name ($frame B)"
    elif [ "$frame" -gt "$cap" ]; then
        echo "stack_frames: GREW over-threshold frame: $name ($frame B > $cap B allowed)"
    else
        echo "stack_frames: allow-listed frame: $name ($frame B, cap $cap B)"
    fi
done)
echo "$REPORT"

if echo "$REPORT" | grep -qE "^stack_frames: (NEW|GREW)"; then
    echo "stack_frames: FAIL; shrink the frame or raise its intentional cap in $ALLOW"
    exit 1
fi
echo "stack_frames: OK (no new over-threshold src/core frames)"
exit 0
