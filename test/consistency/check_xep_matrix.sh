#!/bin/sh
# Wrapper for check_xep_matrix.awk: resolves repo-root-relative paths and runs
# the consistency check with base-system awk only (no python, no packages), so
# it works on a bare FreeBSD CI runner. Pass --strict to fail on advisory
# warnings too.
#
# Exit: 0 clean, 1 drift (or advisory under --strict), 2 usage/parse error.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)

strict=
for arg in "$@"; do
    case "$arg" in
        --strict) strict=1 ;;
        *) echo "usage: $0 [--strict]" >&2; exit 2 ;;
    esac
done

for f in src/core/caps.zig src/core/iq_handler.zig README.md; do
    if [ ! -f "$root/$f" ]; then
        echo "error: expected file not found: $f" >&2
        exit 2
    fi
done

exec awk -v strict="$strict" -f "$here/check_xep_matrix.awk" \
    "$root/src/core/caps.zig" \
    "$root/src/core/iq_handler.zig" \
    "$root/README.md"
