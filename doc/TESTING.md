# Testing xmppd

## Unit tests

```sh
zig build test
```

Runs every module's test step (105 steps). Expected: all pass.

## Integration suites (slixmpp)

The Python suites in `test/integration/` require slixmpp (1.17 verified). They
target a **local throwaway instance** by default — never the shared test jail.

### Throwaway instance setup

```sh
zig build

# config: /tmp/xmppd-test.conf
#   [server]
#   hostname = localhost
#   bind_address = 127.0.0.1
#   c2s_port = 15222
#   user = <your-user>
#   db_path = /tmp/xmppd-test-db
#   [core]
#   workers = 1          # IMPORTANT: single worker; 'auto' puts you on
#                        # cross-worker paths (T154 still open)
#   [muc]
#   host = conference.localhost
#   [tls]                # REQUIRED for e2e-sm-resume.py (it does STARTTLS)
#   cert = /tmp/xmppd-test-cert.pem
#   key = /tmp/xmppd-test-key.pem

# self-signed cert (suites use CERT_NONE contexts):
openssl req -x509 -newkey rsa:2048 -keyout /tmp/xmppd-test-key.pem \
    -out /tmp/xmppd-test-cert.pem -days 2 -nodes -subj '/CN=localhost'

# accounts BEFORE starting (xmppctl falls back to direct DB access when no
# auth daemon is running):
./zig-out/bin/xmppctl --db /tmp/xmppd-test-db adduser alice@localhost   --password pass1
./zig-out/bin/xmppctl --db /tmp/xmppd-test-db adduser bob@localhost     --password pass2
./zig-out/bin/xmppctl --db /tmp/xmppd-test-db adduser charlie@localhost --password pass3

# run in foreground (child paths must be absolute):
./zig-out/bin/xmppd --config /tmp/xmppd-test.conf --no-s2s \
    --core-path "$PWD/zig-out/bin/xmppd-core" \
    --auth-path "$PWD/zig-out/bin/xmppd-auth"
```

`--no-s2s` avoids colliding with any real instance on port 5269.

### Environment overrides

All slixmpp suites honour:

| Variable | Default |
|----------|---------|
| `XMPP_HOST` | `127.0.0.1` |
| `XMPP_PORT` | `15222` |
| `XMPP_DOMAIN` | `localhost` |
| `XMPP_MUC_SERVICE` | `conference.$XMPP_DOMAIN` |
| `XMPP_ALICE_PASS` / `XMPP_BOB_PASS` / `XMPP_CHARLIE_PASS` | `pass1` / `pass2` / `pass3` |

`s2s-federation.py` and `client-interop.py` target different topologies and use
their own variables (`XMPPD_HOST`, `XMPPD_C2S_PORT`, `PROSODY_HOST`,
`PROSODY_C2S_PORT`).

### Suites and known-good results

| Suite | Result |
|-------|--------|
| `e2e-sm-resume.py` | 29/29 (XEP-0198 enable/resume/replay) |
| `e2e-chat.py` | all pass (routing, stanza forwarding) |
| `muc-test.py` | 12/12 |
| `e2e-quick-wins.py` | 12/12 |
| `e2e-mam.py` | 7/7 |
| `e2e-subscription.py` | 29/29 |

Notes:

- The C2S port speaks STARTTLS, not direct TLS. Suites set
  `client.enable_direct_tls = False`; without that slixmpp sends a TLS
  ClientHello first, which the server logs as `error.InvalidEntityReference`
  (T160) and drops — the reconnect then intermittently overruns test timeouts.
- slixmpp `connect()` takes `(host, port)` as two arguments. Passing a tuple
  silently leaves `custom_address` unset and the client falls back to DNS SRV,
  connecting to whatever is on port 5222.

## Interop (SINT)

`smack-sint-server-extensions` follows DNS SRV records (`dnsResolver=javax`).
`/var/unbound/conf.d/s2s-test.conf` on freebsd-dev1 maps
`_xmpp-client._tcp.xmppd.test` to port 15222, so SINT can run against a
throwaway instance. SINT skips stream-management tests when
`accountRegistration` is disabled — run the auth daemon with
`--enable-registration --no-require-invite` (or the `[auth]` equivalents) for
the full XEP-0198 suite.
