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
| `e2e-register-invite.py` | 6/6 (XEP-0077 invite-gated registration, T165) |

`e2e-register-invite.py` needs a *separate* instance: registration enabled
with invites **required** (do not pass `--no-require-invite` / set
`[auth] registration = true` and leave `require_invite` unset), plus an
invite created up front and passed via `XMPP_INVITE_CODE`:

```sh
./zig-out/bin/xmppctl --db /tmp/xmppd-test-db invite create --max-uses 5
# -> prints e.g. INV-XXXXXXXXXXXX
XMPP_INVITE_CODE=INV-XXXXXXXXXXXX python3 test/integration/e2e-register-invite.py
```

It uses a raw socket (STARTTLS via `ssl` module), not slixmpp — slixmpp's
xep_0077 client flow only fires when the server advertises `<register/>`
instead of SASL mechanisms, which xmppd does not do.

Notes:

- The C2S port speaks STARTTLS, not direct TLS. Suites set
  `client.enable_direct_tls = False`; without that slixmpp sends a TLS
  ClientHello first, which the server logs as `error.InvalidEntityReference`
  (T160) and drops — the reconnect then intermittently overruns test timeouts.
- slixmpp `connect()` takes `(host, port)` as two arguments. Passing a tuple
  silently leaves `custom_address` unset and the client falls back to DNS SRV,
  connecting to whatever is on port 5222.

### Multi-worker lane

`workers = 1` makes every route local — the whole cross-worker surface (room
sharding, actor messages, MPSC delivery with ABA generation validation) goes
untested, which is how T173 slipped through. `test/integration/run-multiworker.sh`
spins up a self-contained throwaway instance at N workers (default 4, port
15333) and runs the given suites (default: `muc-test.py`):

```sh
zig build
sh test/integration/run-multiworker.sh            # muc-test at workers=4
sh test/integration/run-multiworker.sh 4 muc-test.py e2e-subscription.py ...
```

Notes:

- The lane uses its own run dir (`--run-dir`), auth socket, db and cert in a
  mktemp dir, so it can coexist with other throwaway instances as long as
  ports differ (default 15333).
- `e2e-sm-resume.py` is excluded on purpose: SM resume state is per-worker,
  and a reconnect lands on a random worker via SO_REUSEPORT, so resume fails
  with `item-not-found` at workers>1 by design (cross-worker resume is not
  implemented).

Known-good at workers=4 (post-T173): muc-test 12/12, e2e-quick-wins 12/12,
e2e-chat all pass, e2e-mam 7/7, e2e-subscription 29/29.

## Interop (SINT)

`smack-sint-server-extensions` follows DNS SRV records (`dnsResolver=javax`).
`/var/unbound/conf.d/s2s-test.conf` on freebsd-dev1 maps
`_xmpp-client._tcp.xmppd.test` to port 15222, so SINT can run against a
throwaway instance. SINT skips stream-management tests when
`accountRegistration` is disabled — run the auth daemon with
`--enable-registration --no-require-invite` (or the `[auth]` equivalents) for
the full XEP-0198 suite.
