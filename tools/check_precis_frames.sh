#!/bin/sh
# Fail when a PRECIS call site's stack frame exceeds the 16 KiB core budget.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 AUTH_HANDLER_TEST_BINARY SERVER_TEST_BINARY" >&2
    exit 2
fi

check_symbol() {
    binary=$1
    symbol=$2
    prologue=$(objdump -d --demangle "$binary" | sed -n "/<${symbol}>:/,+12p")
    if [ -z "$prologue" ]; then
        # ReleaseSafe may inline a call site completely; there is then no
        # out-of-line frame to measure. Debug still checks every symbol.
        echo "$symbol: inlined or absent in $binary"
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

check_symbol "$1" 'handler.AuthHandler(user_store.UserStore(backend.MemoryBackend)).handlePlainAuth'
check_symbol "$1" 'handler.AuthHandler(user_store.UserStore(backend.MemoryBackend)).handleScramInit'
check_symbol "$1" 'handler.AuthHandler(user_store.UserStore(backend.MemoryBackend)).handleRegisterRequest'
check_symbol "$2" 'iq_handler.handleRegisterSubmit'
