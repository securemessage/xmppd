#!/usr/bin/env python3
"""End-to-end test: XEP-0012 Last Activity (T164).

Covers the full semantic matrix:
  1. Server-directed query (no `to` / `to` = domain): uptime in seconds,
     monotonically increasing.
  2. Self query (own bare and full JID): seconds='0'.
  3. Subscribed contact online: seconds='0'.
  4. Subscribed contact offline: seconds since its last teardown (>= 1 after
     a 2s window), then back to 0 on reconnect.
  5. Privacy gate: non-subscribed requester gets 'forbidden' for online,
     offline, and nonexistent targets alike.
  6. Full-JID queries forward to the resource per RFC 6121 §8.5.3; the
     resource's client answers its own idle time (XEP-0012 §2.1). Unbound
     full JIDs get a server-side error bounce.

Pre-T164 every one of these answered seconds='0' — this suite fails on the
stub.

Environment: XMPP_HOST, XMPP_PORT, XMPP_DOMAIN, XMPP_WORKERS
"""

import socket, ssl, time, base64, sys, re, os

HOST = os.environ.get('XMPP_HOST', '127.0.0.1')
PORT = int(os.environ.get('XMPP_PORT', '15222'))
DOMAIN = os.environ.get('XMPP_DOMAIN', 'localhost')
SERVER_LOG = os.environ.get('XMPP_SERVER_LOG', '')
WORKERS = int(os.environ.get('XMPP_WORKERS', '1'))

CREDS = {'alice': 'pass1', 'bob': 'pass2', 'charlie': 'pass3'}

passed = 0
failed = 0


class XmppClient:
    def __init__(self, user):
        self.user = user
        self.password = CREDS[user]
        self.sock = None
        self.tls = None
        # Client-side idle clock (XEP-0012 §2.1): last interaction in either
        # direction — the client answers its own idle time.
        self.idle_since = time.time()

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        self.sock.settimeout(5)

    def send(self, data):
        self.idle_since = time.time()
        target = self.tls or self.sock
        if isinstance(data, str):
            data = data.encode()
        target.sendall(data)

    def recv(self, timeout=3):
        target = self.tls or self.sock
        target.settimeout(timeout)
        try:
            return target.recv(8192).decode('utf-8', errors='replace')
        except socket.timeout:
            return ''

    def recv_until(self, marker, timeout=5):
        target = self.tls or self.sock
        target.settimeout(0.5)
        buf = ''
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                buf += target.recv(8192).decode('utf-8', errors='replace')
                if marker in buf:
                    return buf
            except socket.timeout:
                continue
        return buf

    def drain(self, seconds=0.4):
        return self.recv_until('\x00never\x00', timeout=seconds)

    def full_connect(self, resource):
        self.connect()
        self.send("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                  "xmlns:stream='http://etherx.jabber.org/streams' "
                  f"to='{DOMAIN}' version='1.0'>")
        self.recv()
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        if '<proceed' not in self.recv():
            raise RuntimeError(f'{self.user}: STARTTLS failed')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.tls = ctx.wrap_socket(self.sock, server_hostname='localhost')
        self.send("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                  "xmlns:stream='http://etherx.jabber.org/streams' "
                  f"to='{DOMAIN}' version='1.0'>")
        self.recv()
        b64 = base64.b64encode(f'\x00{self.user}\x00{self.password}'.encode()).decode()
        self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
        if '<success' not in self.recv():
            raise RuntimeError(f'{self.user}: SASL PLAIN failed')
        self.send("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                  "xmlns:stream='http://etherx.jabber.org/streams' "
                  f"to='{DOMAIN}' version='1.0'>")
        self.recv()
        self.send(f"<iq type='set' id='bind1'>"
                  f"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                  f"<resource>{resource}</resource></bind></iq>")
        resp = self.recv()
        # Announce presence: without it the server holds subscription requests
        # as pending and routes bare-JID traffic to the offline store.
        self.send('<presence/>')
        self.drain(0.3)
        return resp

    def ask_last_activity(self, target, iq_id):
        """Send a last-activity query WITHOUT waiting (used when the answer
        must be produced by the peer before we read it)."""
        to = f" to='{target}'" if target else ''
        self.send(f"<iq type='get' id='{iq_id}'{to}><query xmlns='jabber:iq:last'/></iq>")

    def answer_last_activity(self, iq_id, from_full, to_full):
        """Answer a forwarded full-JID last-activity query client-side
        (XEP-0012 §2.1: the resource answers its own idle time)."""
        idle = max(0, int(time.time() - self.idle_since))
        self.send(f"<iq type='result' from='{from_full}' to='{to_full}' id='{iq_id}'>"
                  f"<query xmlns='jabber:iq:last' seconds='{idle}'/></iq>")

    def last_activity(self, target, iq_id):
        to = f" to='{target}'" if target else ''
        self.send(f"<iq type='get' id='{iq_id}'{to}><query xmlns='jabber:iq:last'/></iq>")
        return self.recv_until(f"id='{iq_id}'", timeout=6)

    def close(self):
        try:
            self.send('</stream:stream>')
            time.sleep(0.2)
        except Exception:
            pass
        try:
            (self.tls or self.sock).close()
        except Exception:
            pass


def check(label, condition, detail=''):
    global passed, failed
    if condition:
        print(f'  PASS {label}')
        passed += 1
    else:
        print(f'  FAIL {label}' + (f' - {detail}' if detail else ""))
        failed += 1


def last_seconds(resp, iq_id):
    # Attribute order is not stable across server-written vs forwarded
    # answers — match id anywhere in the IQ tag, then read seconds.
    m = re.search(r"<iq[^>]*id='" + re.escape(iq_id) + r"'[^>]*>", resp)
    if not m:
        return None
    s = re.search(r"<query xmlns='jabber:iq:last' seconds='(\d+)'", resp[m.start():])
    return int(s.group(1)) if s else None


def mutual_subscribe(a, b):
    """Drive alice<->bob to subscription='both' with raw presence stanzas."""
    a_bare = f'{a.user}@{DOMAIN}'
    b_bare = f'{b.user}@{DOMAIN}'
    a.send(f"<presence to='{b_bare}' type='subscribe'/>")
    b.recv_until("type='subscribe'", timeout=5)
    b.send(f"<presence to='{a_bare}' type='subscribed'/>")
    # inbound subscribed goes to alice; her contact-side entry becomes 'to'
    a.recv_until("type='subscribed'", timeout=5)
    b.send(f"<presence to='{a_bare}' type='subscribe'/>")
    a.recv_until("type='subscribe'", timeout=5)
    a.send(f"<presence to='{b_bare}' type='subscribed'/>")
    b.recv_until("type='subscribed'", timeout=5)
    a.drain(0.4)
    b.drain(0.4)


if __name__ == '__main__':
    print('=' * 60)
    print('xmppd E2E Test: XEP-0012 Last Activity (T164)')
    print('=' * 60)

    alice = XmppClient('alice')
    bob = XmppClient('bob')
    charlie = XmppClient('charlie')

    try:
        print('\n[Setup] connect alice, bob, charlie')
        alice.full_connect('phone')
        bob.full_connect('laptop')
        charlie.full_connect('desk')
        alice.drain(0.3)
        bob.drain(0.3)
        charlie.drain(0.3)

        # ---- 1+2: server uptime, monotonic -------------------------------
        print('\n[1] Server uptime')
        r1 = alice.last_activity('', 'la-uptime-1')
        s1 = last_seconds(r1, 'la-uptime-1')
        check('uptime answer parses', s1 is not None, r1[-200:])
        time.sleep(2.1)
        r2 = alice.last_activity(DOMAIN, 'la-uptime-2')
        s2 = last_seconds(r2, 'la-uptime-2')
        if s1 is not None and s2 is not None:
            check('uptime increases with real time', s2 >= s1 + 1, f'{s1} -> {s2}')
        check('to=domain gives same shape', s2 is not None, r2[-200:])

        # ---- 2: self (bare + full) ----------------------------------------
        print('\n[2] Self')
        r = alice.last_activity(f'alice@{DOMAIN}', 'la-self-bare')
        check('self bare JID is 0', last_seconds(r, 'la-self-bare') == 0, r[-200:])
        r = alice.last_activity(f'alice@{DOMAIN}/phone', 'la-self-full')
        check('self full JID is 0', last_seconds(r, 'la-self-full') == 0, r[-200:])

        # ---- 3: subscribed contact online ---------------------------------
        print('\n[3] Subscribe alice<->bob; bob online')
        mutual_subscribe(alice, bob)
        r = alice.last_activity(f'bob@{DOMAIN}', 'la-bob-online')
        check('online subscribed contact is 0', last_seconds(r, 'la-bob-online') == 0, r[-200:])

        # ---- 3b: full-JID forwarding + client-side idle (XEP-0012 §2.1) ---
        print('\n[3b] Full-JID query forwarded; bob answers his own idle time')
        # bob stays silent 2.2s, then alice asks his full JID for idle time.
        # (ask = send only; bob's client must answer before alice reads.)
        time.sleep(2.2)
        alice.ask_last_activity(f'bob@{DOMAIN}/laptop', 'la-bob-idle-1')
        fwd = bob.recv_until("jabber:iq:last", timeout=5)
        check('full-JID query forwarded to bob resource', "id='la-bob-idle-1'" in fwd,
              fwd[-200:])
        if "id='la-bob-idle-1'" in fwd:
            bob.answer_last_activity('la-bob-idle-1', f'bob@{DOMAIN}/laptop', f'alice@{DOMAIN}/phone')
            r = alice.recv_until("id='la-bob-idle-1'", timeout=5)
            s = last_seconds(r, 'la-bob-idle-1')
            check('client idle answer routed back (>= 1 after silence)',
                  s is not None and 1 <= s <= 60,
                  f'seconds={s}' if s is not None else r[-200:])

        # Activity resets bob's clock (send side)
        bob.send(f"<message to='alice@{DOMAIN}/phone'><body>activity-marker</body></message>")
        alice.recv_until('activity-marker', timeout=5)
        alice.ask_last_activity(f'bob@{DOMAIN}/laptop', 'la-bob-idle-2')
        fwd = bob.recv_until("id='la-bob-idle-2'", timeout=5)
        check('second full-JID query forwarded', "jabber:iq:last" in fwd, fwd[-200:])
        if 'jabber:iq:last' in fwd:
            bob.answer_last_activity('la-bob-idle-2', f'bob@{DOMAIN}/laptop', f'alice@{DOMAIN}/phone')
            r = alice.recv_until("id='la-bob-idle-2'", timeout=5)
            s = last_seconds(r, 'la-bob-idle-2')
            check('client idle resets to 0 after activity', s == 0,
                  f'seconds={s}' if s is not None else r[-200:])

        # Unbound full JID: server answers the bounce itself (RFC 6121 §8.5.4)
        r = alice.last_activity(f'bob@{DOMAIN}/nonexistent', 'la-bob-badres')
        check('unbound resource -> error bounce',
              "type='error'" in r and ('<service-unavailable' in r or '<recipient-unavailable' in r),
              r[-200:])

        # Full-JID queries follow RFC 6121 §8.5.3 forwarding (not the server
        # answering on behalf), so worker placement is irrelevant — no
        # server-side probe path exists to hunt for.

        # ---- 4: contact goes offline --------------------------------------
        print('\n[4] bob disconnects; elapsed seconds accrue')
        bob.close()
        time.sleep(2.3)
        r = alice.last_activity(f'bob@{DOMAIN}', 'la-bob-offline')
        s = last_seconds(r, 'la-bob-offline')
        check('offline contact reports elapsed >= 1', s is not None and 1 <= s <= 60,
              f'seconds={s}' if s is not None else r[-200:])

        # ---- 4b: contact comes back ----------------------------------------
        print('\n[4b] bob reconnects')
        bob = XmppClient('bob')
        bob.full_connect('laptop')
        bob.drain(0.3)
        r = alice.last_activity(f'bob@{DOMAIN}', 'la-bob-back')
        check('reconnected contact is 0 again', last_seconds(r, 'la-bob-back') == 0, r[-200:])

        # ---- 5: privacy gate -----------------------------------------------
        print('\n[5] charlie (never subscribed) is forbidden everywhere')
        r = charlie.last_activity(f'alice@{DOMAIN}', 'la-c-alice')
        check('online but unsubscribed -> forbidden',
              "type='error'" in r and '<forbidden' in r, r[-200:])
        bob.close()
        time.sleep(0.8)
        r = charlie.last_activity(f'bob@{DOMAIN}', 'la-c-bob')
        check('offline and unsubscribed -> forbidden',
              "type='error'" in r and '<forbidden' in r, r[-200:])
        r = charlie.last_activity(f'nobody@{DOMAIN}', 'la-c-nobody')
        check('nonexistent account -> forbidden (indistinguishable)',
              "type='error'" in r and '<forbidden' in r, r[-200:])

        alice.close()
        charlie.close()

    except Exception as e:
        print(f'  FAIL Exception: {e}')
        failed += 1
        for c in (alice, bob, charlie):
            c.close()

    print('\n' + '=' * 60)
    print(f'Results: {passed} passed, {failed} failed')
    print('=' * 60)
    sys.exit(1 if failed > 0 else 0)
