#!/bin/sh
# Fail when a PRECIS call site's stack frame exceeds the 16 KiB core budget.
set -eu

self_test=0
if [ "${1:-}" = "--self-test" ]; then
    self_test=1
    set -- /bin/true /bin/true /bin/true
fi
if [ "$#" -ne 3 ]; then
    echo "usage: $0 AUTH_BINARY AUTH_OIDC_BINARY CORE_BINARY" >&2
    exit 2
fi

check_symbol_impl() {
    binary=$1
    symbol=$2
    required=$3
    prologue=$(objdump -d --demangle "$binary" | sed -n "/<${symbol}>:/,+12p")
    if [ -z "$prologue" ]; then
        if [ "$required" -eq 1 ]; then
            echo "missing required symbol: $symbol in $binary" >&2
            exit 1
        fi
        return 0
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

check_symbol() {
    check_symbol_impl "$1" "$2" 1
}

check_optional_symbol() {
    check_symbol_impl "$1" "$2" 0
}

check_auth_binary() {
    binary=$1
    prefix=$2
    # ReleaseSafe inlines the mechanism handlers, so their symbols may be
    # absent; Debug keeps them out of line and they must pass on their own.
    # handleMessage is the inlining parent and is always required.
    check_symbol "$binary" "${prefix}.handleMessage"
    check_optional_symbol "$binary" "${prefix}.handlePlainAuth"
    check_optional_symbol "$binary" "${prefix}.handleScramInit"
    check_optional_symbol "$binary" "${prefix}.handleRegisterRequest"
}

if [ "$self_test" -eq 1 ]; then
    if ( check_symbol /bin/true '__definitely_missing_precis_symbol__' >/dev/null 2>&1 ); then
        echo "self-test failed: a missing symbol was accepted" >&2
        exit 1
    fi
    echo "self-test: missing symbol rejected"
    exit 0
fi

check_auth_binary "$1" 'handler.AuthHandler(user_store.UserStore(lmdb.LmdbBackend))'
check_auth_binary "$2" 'handler.AuthHandler(oidc.OidcStore)'
check_symbol "$3" 'iq_handler.handleRegisterSubmit'
