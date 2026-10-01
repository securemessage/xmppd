#!/usr/bin/env python3
"""End-to-end test: cross-worker resource takeover eviction (T154 + T152).

Two live connections bind the SAME full JID (alice@localhost/shared). The
second bind must succeed and the first connection must die with a conflict
stream error. Same-worker this is T152's local eviction; cross-worker it now
goes through the session_kick actor round-trip (T154).

At workers>1, SO_REUSEPORT scatters the two connections; repeated rounds make
a cross-worker kick near-certain, and XMPP_SERVER_LOG evidence asserts at
least one actually happened.

Environment: XMPP_HOST/XMPP_PORT/XMPP_DOMAIN, XMPP_SERVER_LOG (optional),
             XMPP_WORKERS (optional, default 1), XMPP_ROUNDS (default 6)
"""

import socket, ssl, time, base64, sys, os, re

HOST = os.environ.get('XMPP_HOST', '127.0.0.1')
PORT = int(os.environ.get('XMPP_PORT', '15222'))
DOMAIN = os.environ.get('XMPP_DOMAIN', 'localhost')
SERVER_LOG = os.environ.get('XMPP_SERVER_LOG', '')
WORKERS = int(os.environ.get('XMPP_WORKERS', '1'))
ROUNDS = int(os.environ.get('XMPP_ROUNDS', '6'))

passed = 0
failed = 0


def check(label, condition, detail=''):
    global passed, failed
    if condition:
        print(f"  PASS {label}")
        passed += 1
    else:
        print(f"  FAIL {label}" + (f" - {detail}" if detail else ""))
        failed += 1


def connect_and_bind(user, password, resource):
    """Full TLS+SASL+bind; returns (wrapped_sock, bind_response)."""
    sock = socket.create_connection((HOST, PORT), timeout=5)

    def send(x):
        sock.sendall(x.encode())

    send("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
         "xmlns:stream='http://etherx.jabber.org/streams' "
         f"to='{DOMAIN}' version='1.0'>")
    sock.recv(8192)

    send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    resp = sock.recv(8192).decode('utf-8', 'replace')
    if '<proceed' not in resp:
        raise RuntimeError('STARTTLS refused')

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(sock, server_hostname='localhost')
    tls.settimeout(8)

    tls.sendall(("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                 "xmlns:stream='http://etherx.jabber.org/streams' "
                 f"to='{DOMAIN}' version='1.0'>").encode())
    tls.recv(8192)

    pw = base64.b64encode(f'\x00{user}\x00{password}'.encode()).decode()
    tls.sendall(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{pw}</auth>".encode())
    resp = tls.recv(8192).decode('utf-8', 'replace')
    if '<success' not in resp:
        raise RuntimeError(f'SASL failed: {resp}')

    tls.sendall(("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                 "xmlns:stream='http://etherx.jabber.org/streams' "
                 f"to='{DOMAIN}' version='1.0'>").encode())
    tls.recv(8192)

    tls.sendall(("<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                 f"<resource>{resource}</resource></bind></iq>").encode())
    return tls, tls.recv(8192).decode('utf-8', 'replace')


if __name__ == '__main__':
    print('=' * 60)
    print('xmppd E2E Test: resource takeover eviction (T154/T152)')
    print('=' * 60)

    for rnd in range(1, ROUNDS + 1):
        # Incumbent: connect and bind the shared resource
        old = connect_and_bind('alice', 'pass1', 'shared')
        check(f'round {rnd}: incumbent bound', f'alice@{DOMAIN}/shared' in old[1], old[1][:200])

        # Taker: second connection binds the same resource
        start = time.time()
        new = connect_and_bind('alice', 'pass1', 'shared')
        elapsed = time.time() - start
        ok = f'alice@{DOMAIN}/shared' in new[1]
        check(f'round {rnd}: taker bound (evicting incumbent)', ok, new[1][:200])
        check(f'round {rnd}: takeover completed quickly', elapsed < 5, f'{elapsed:.1f}s')

        # Incumbent must see a conflict stream error and get closed
        old_sock = old[0]
        old_sock.settimeout(5)
        buf = ''
        try:
            while 'conflict' not in buf and '</stream:stream>' not in buf:
                chunk = old_sock.recv(8192)
                if not chunk:
                    break
                buf += chunk.decode('utf-8', 'replace')
        except (socket.timeout, ssl.SSLError, ConnectionResetError):
            pass
        check(f'round {rnd}: evicted connection got stream conflict', 'conflict' in buf, buf[:200])

        old_sock.close()
        new[0].close()  # released so next round's incumbent starts clean

    # wait... next round's incumbent connects AFTER previous taker closed
    if SERVER_LOG:
        try:
            with open(SERVER_LOG, 'r', errors='replace') as f:
                log_text = f.read()
            kicks = len(re.findall(r'bind parked: kicking', log_text))
            if WORKERS > 1:
                check('cross-worker session_kick observed at least once', kicks >= 1,
                      f'parks in log: {kicks}')
        except OSError as e:
            check('server log readable', False, str(e))

    print()
    print('=' * 60)
    print(f'Results: {passed} passed, {failed} failed')
    print('=' * 60)
    sys.exit(1 if failed > 0 else 0)
