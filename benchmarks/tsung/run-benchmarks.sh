#!/bin/sh
# xmppd V1.0 pre-release load test runner
#
# Runs tsung benchmarks against the xmppd jail with different worker configs.
# Results stored in ~/tsung-results/xmppd-v1/<scenario>-<workers>/
#
# Usage: ./run-benchmarks.sh [chat-1to1|muc|combo|all]

set -e

JAIL_ROOT="/usr/local/jails/xmppd"
CONF="${JAIL_ROOT}/usr/local/etc/xmppd/xmppd.conf"
RESULTS_BASE="$HOME/tsung-results/xmppd-v1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

scenario="${1:-all}"

wait_for_port() {
    local retries=0
    while [ $retries -lt 30 ]; do
        if nc -z 127.0.0.1 5222 2>/dev/null; then
            return 0
        fi
        sleep 1
        retries=$((retries + 1))
    done
    echo "ERROR: port 5222 not ready after 30s"
    return 1
}

restart_xmppd() {
    local workers="$1"
    echo ">>> Configuring workers = ${workers}"
    doas sed -i '' "s/^workers = .*/workers = ${workers}/" "$CONF"
    doas jexec xmppd service xmppd stop 2>&1 | head -2
    sleep 2
    doas jexec xmppd service xmppd start 2>&1 | head -2
    wait_for_port
    echo ">>> xmppd restarted with workers=${workers}"
}

run_tsung() {
    local config="$1"
    local label="$2"
    local outdir="${RESULTS_BASE}/${label}"
    mkdir -p "$outdir"

    echo "=== Running: ${label} ==="
    tsung -f "${SCRIPT_DIR}/${config}" -l "$outdir" start 2>&1
    echo "=== Completed: ${label} ==="
    echo ""

    # Generate HTML report if tsung_stats.pl is available
    if [ -x /usr/local/lib/tsung/bin/tsung_stats.pl ]; then
        cd "$outdir"/$(ls -t "$outdir" | head -1) 2>/dev/null && \
            /usr/local/lib/tsung/bin/tsung_stats.pl 2>/dev/null && \
            echo "Report: $outdir/$(ls -t "$outdir" | head -1)/report.html"
        cd "$SCRIPT_DIR"
    fi
}

run_scenario() {
    local config="$1"
    local name="$2"

    for workers in 1 4 auto; do
        restart_xmppd "$workers"
        run_tsung "$config" "${name}-workers${workers}"
    done
}

mkdir -p "$RESULTS_BASE"

case "$scenario" in
    chat-1to1)
        run_scenario "chat-1to1.xml" "chat-1to1"
        ;;
    muc)
        run_scenario "muc.xml" "muc"
        ;;
    combo)
        run_scenario "combo.xml" "combo"
        ;;
    all)
        run_scenario "chat-1to1.xml" "chat-1to1"
        run_scenario "muc.xml" "muc"
        run_scenario "combo.xml" "combo"
        ;;
    *)
        echo "Usage: $0 [chat-1to1|muc|combo|all]"
        exit 1
        ;;
esac

echo ""
echo "============================================"
echo "All benchmarks complete. Results in:"
echo "  ${RESULTS_BASE}/"
echo "============================================"
