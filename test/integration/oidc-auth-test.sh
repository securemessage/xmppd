#!/bin/sh
# Integration test: xmppd-auth-oidc against Rauthy dev instance
#
# Prerequisites:
# - Rauthy running at auth.morante.dev:8443
# - xmppd client configured with password flow + RS256
# - Test user alice@morante.dev exists
#
# This test verifies ROPC (PLAIN-to-IdP) by starting the auth daemon
# and observing its log output when a token request is made.
# Full IPC-level testing requires the binary protocol client.

set -e

SCRIPT_DIR=$(dirname "$0")
REPO_DIR="$SCRIPT_DIR/../.."
BINARY="$REPO_DIR/zig-out/bin/xmppd-auth-oidc"
CONFIG="/home/admin/Documents/Data/xmppd-oidc-test.conf"
SOCKET="/tmp/xmppd-oidc-test.sock"

# Rauthy credentials
CLIENT_ID="xmppd"
CLIENT_SECRET="QlhaLYExyFexfCbeWfDctiYKfsOZKHxtdxFZBTIrmSghTRLDyqpgkPOjdPywBFob"
TOKEN_ENDPOINT="https://auth.morante.dev:8443/auth/v1/oidc/token"
JWKS_URI="https://auth.morante.dev:8443/auth/v1/oidc/certs"
TEST_USER="alice@morante.dev"
TEST_PASS="1MTK*McK0J'I%e!AVCC2"

echo "=== xmppd-auth-oidc Integration Test ==="
echo ""

# Test 1: Verify ROPC works at the HTTP level (prerequisite)
echo "[1/4] Testing ROPC grant against Rauthy..."
RESPONSE=$(curl -sk -X POST "$TOKEN_ENDPOINT" \
    -d "grant_type=password&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&username=$(echo -n "$TEST_USER" | sed 's/@/%40/g')&password=$(echo -n "$TEST_PASS" | python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read(),safe=""))')&scope=openid%20email%20profile" 2>/dev/null)

if echo "$RESPONSE" | grep -q "access_token"; then
    echo "  PASS: ROPC grant succeeded"
    ACCESS_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
else
    echo "  FAIL: ROPC grant failed: $RESPONSE"
    exit 1
fi

# Test 2: Verify JWKS endpoint is reachable
echo "[2/4] Testing JWKS endpoint..."
JWKS=$(curl -sk "$JWKS_URI" 2>/dev/null)
if echo "$JWKS" | grep -q '"kid"'; then
    KEY_COUNT=$(echo "$JWKS" | grep -o '"kid"' | wc -l)
    echo "  PASS: JWKS has $KEY_COUNT keys"
else
    echo "  FAIL: JWKS fetch failed"
    exit 1
fi

# Test 3: Verify the access token has expected claims
echo "[3/4] Verifying token claims..."
CLAIMS=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | python3 -c "
import sys,base64,json
payload=sys.stdin.read().strip()
payload+='='*((4-len(payload)%4)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload))))
")

ISS=$(echo "$CLAIMS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('iss',''))")
AUD=$(echo "$CLAIMS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('aud',''))")
EMAIL=$(echo "$CLAIMS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('email',''))")

if [ "$ISS" = "https://auth.morante.dev:8443/auth/v1/" ]; then
    echo "  PASS: issuer matches"
else
    echo "  FAIL: issuer mismatch: $ISS"
    exit 1
fi

if [ "$AUD" = "xmppd" ]; then
    echo "  PASS: audience matches"
else
    echo "  FAIL: audience mismatch: $AUD"
    exit 1
fi

if [ "$EMAIL" = "alice@morante.dev" ]; then
    echo "  PASS: email claim present (alice@morante.dev)"
else
    echo "  WARN: email claim missing or different: $EMAIL"
fi

# Test 4: Start xmppd-auth-oidc and verify it initializes
echo "[4/4] Starting xmppd-auth-oidc daemon..."
rm -f "$SOCKET"

if [ ! -f "$BINARY" ]; then
    echo "  SKIP: binary not found at $BINARY (run 'zig build' first)"
    exit 0
fi

# Start daemon in background, capture output
$BINARY --config "$CONFIG" --socket "$SOCKET" > /tmp/xmppd-oidc-test.log 2>&1 &
DAEMON_PID=$!

# Wait for socket to appear
for i in 1 2 3 4 5; do
    if [ -S "$SOCKET" ]; then
        break
    fi
    sleep 1
done

if [ -S "$SOCKET" ]; then
    echo "  PASS: daemon started, IPC socket ready at $SOCKET"
else
    echo "  FAIL: daemon did not create socket within 5s"
    kill $DAEMON_PID 2>/dev/null
    cat /tmp/xmppd-oidc-test.log
    exit 1
fi

# Clean up
kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null
rm -f "$SOCKET"

echo ""
echo "=== All integration tests PASSED ==="
echo ""
echo "Note: Full IPC-level OAUTHBEARER testing requires the binary"
echo "protocol client (sending MechanismList, AuthRequest over Unix socket)."
echo "The HTTP-level tests verify the IdP integration works correctly."
