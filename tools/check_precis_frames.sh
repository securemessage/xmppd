#!/bin/sh
# Fail when a PRECIS call site's stack frame exceeds the 16 KiB core budget.
set -eu

self_test=0
if [ "${1:-}" = "--self-test" ]; then
    self_test=1
    set -- /bin/true /bin/true
fi
if [ "$#" -ne 2 ]; then
    echo "usage: $0 AUTH_BINARY CORE_BINARY" >&2
    exit 2
fi

check_symbol() {
    binary=$1
    symbol=$2
    prologue=$(objdump -d --demangle "$binary" | sed -n "/<${symbol}>:/,+12p")
    if [ -z "$prologue" ]; then
        echo "missing required symbol: $symbol in $binary" >&2
        exit 1
    fi
    frame_hex=$(printf '%s\n' "$prologue" | sed -n 's/.*subq.*\$0x\([0-9a-f][0-9a-f]*\), %rsp.*/\1/p' | head -n 1)
    if [ -z "$frame_hex" ]; then
        # Large frames use __zig_probe_stack: movl $N,%eax; call probe; subq %rax,%rsp.
        frame_hex=$(printf '%s\n' "$prologue" | sed -n 's/.*movl.*\$0x\([0-9a-f][0-9a-f]*\), %eax.*/\1/p' | head -n 1)
    fi
    if [ -z "$frame_hex" ]; then
        echo "could not read stack adjustment for $symbol in $binary" >&2
        exit 1
    fi
    frame=$(printf '%d' "0x$frame_hex")
    if [ "$frame" -gt 16384 ]; then
        echo "$symbol has a $frame-byte stack frame (limit 16384)" >&2
        exit 1
    fi
    echo "$symbol: $frame bytes"
}

if [ "$self_test" -eq 1 ]; then
    if ( check_symbol /bin/true '__definitely_missing_precis_symbol__' >/dev/null 2>&1 ); then
        echo "self-test failed: a missing symbol was accepted" >&2
        exit 1
    fi
    echo "self-test: missing symbol rejected"
    exit 0
fi

# Production symbols only: ReleaseSafe legitimately inlines the specific
# mechanism handlers. The inlining parent carries their scratch and must stay
# within budget; a renamed/missing symbol is a hard failure.
check_symbol "$1" 'handler.AuthHandler(user_store.UserStore(lmdb.LmdbBackend)).handleMessage'
check_symbol "$2" 'iq_handler.handleRegisterSubmit'
