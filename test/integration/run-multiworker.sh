#!/bin/sh
# Multi-worker e2e regression lane (T173).
#
# Starts a throwaway xmppd instance with [core] workers = N (default 4) and
# runs the given slixmpp suites against it (default: muc-test.py). The whole
# cross-worker surface (MUC room sharding, actor messages, MPSC delivery with
# generation validation) is only exercised when workers > 1 — at workers = 1
# every route is local, which is how T173 (MUC admin IQ result dropped
# cross-worker) slipped through.
#
# Usage:
#   sh test/integration/run-multiworker.sh [workers] [suite.py ...]
#
# Requires: zig build products in zig-out/bin (run `zig build` first), a
# python with slixmpp (default: /tmp/slixvenv/bin/python, override with
# SLIXPYTHON), openssl. Everything else is created in a mktemp dir and
# removed on exit.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)

workers=4
if [ $# -gt 0 ] && [ "$1" -eq "$1" ] 2>/dev/null; then
    workers=$1
    shift
fi
if [ $# -gt 0 ]; then
    suites="$@"
else
    suites="muc-test.py"
fi

PYTHON=${SLIXPYTHON:-/tmp/slixvenv/bin/python}
PORT=${XMPP_PORT:-15333}

for f in zig-out/bin/xmppd zig-out/bin/xmppd-core zig-out/bin/xmppd-auth zig-out/bin/xmppctl; do
    if [ ! -x "$root/$f" ]; then
        echo "error: $f not built — run 'zig build' first" >&2
        exit 2
    fi
done
if [ ! -x "$PYTHON" ]; then
    echo "error: $PYTHON not found — set SLIXPYTHON to a python with slixmpp" >&2
    exit 2
fi

tmp=$(mktemp -d /tmp/xmppd-mw.XXXXXX)
# srvpid is set once the server starts; guard for early failures.
srvpid=
cleanup() {
    if [ -n "$srvpid" ]; then
        kill "$srvpid" 2>/dev/null
        wait "$srvpid" 2>/dev/null
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT
# Die-through to the EXIT trap on signals; SIGPIPE becomes a write error
# (caught by set -e) instead of an untrapped death when piping into head(1).
trap 'exit 1' INT TERM HUP
trap '' PIPE

openssl req -x509 -newkey rsa:2048 -keyout "$tmp/key.pem" \
    -out "$tmp/cert.pem" -days 1 -nodes -subj '/CN=localhost' 2>/dev/null

cat > "$tmp/xmppd.conf" <<EOF
[server]
hostname = localhost
bind_address = 127.0.0.1
c2s_port = $PORT
db_path = $tmp/db
[core]
workers = $workers
[muc]
host = conference.localhost
[tls]
cert = $tmp/cert.pem
key = $tmp/key.pem
[auth]
socket = $tmp/auth.sock
EOF

# NOTE: only one xmppd master can run per host (PID file is fixed at
# /var/run/xmppd/xmppd.pid). The auth socket is pointed into $tmp so xmppctl
# talks to THIS instance's daemon, never a neighbour's.
"$root/zig-out/bin/xmppctl" --db "$tmp/db" --auth-socket "$tmp/auth.sock" adduser alice@localhost   --password pass1 > /dev/null
"$root/zig-out/bin/xmppctl" --db "$tmp/db" --auth-socket "$tmp/auth.sock" adduser bob@localhost     --password pass2 > /dev/null
"$root/zig-out/bin/xmppctl" --db "$tmp/db" --auth-socket "$tmp/auth.sock" adduser charlie@localhost --password pass3 > /dev/null

"$root/zig-out/bin/xmppd" --config "$tmp/xmppd.conf" --no-s2s \
    --core-path "$root/zig-out/bin/xmppd-core" \
    --auth-path "$root/zig-out/bin/xmppd-auth" > "$tmp/server.log" 2>&1 &
srvpid=$!

# Wait for the C2S port to accept connections (up to ~15s)
ready=0
i=0
while [ $i -lt 75 ]; do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 0.2
done
if [ $ready -ne 1 ] || ! kill -0 "$srvpid" 2>/dev/null; then
    echo "error: server failed to start — log follows" >&2
    cat "$tmp/server.log" >&2
    exit 2
fi

echo "=== multi-worker lane: workers=$workers port=$PORT ==="
rc=0
for suite in $suites; do
    echo "--- $suite (workers=$workers) ---"
    XMPP_PORT=$PORT "$PYTHON" "$here/$suite" || rc=1
done

if [ $rc -ne 0 ]; then
    echo "--- server log tail ---" >&2
    tail -40 "$tmp/server.log" >&2
fi
exit $rc
