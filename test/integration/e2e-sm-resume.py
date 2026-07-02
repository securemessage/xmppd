#!/usr/bin/env python3
"""End-to-end test: XEP-0198 Stream Management resume.

Tests the SM resume flow that was broken by a dispatch ordering bug
where the pre-bind IQ catch-all silently dropped <resume/> elements.

Test cases:
  1. SM enable — verify server returns <enabled/> with resume='true' and an SM-ID
  2. SM resume after disconnect — verify <resumed/> or <failed/> (not silence)
  3. SM resume fallback to bind — after <failed/>, verify <iq><bind> still works
  4. Unique stream IDs — verify each stream restart produces a new ID (RFC 6120 §4.7.3)
  5. SM stanza ack — verify <r/> produces <a/> with correct h value
  6. SM resume with stanza replay — verify unacked stanzas are replayed after resume
"""

import socket, ssl, time, base64, sys, re

import os
HOST = os.environ.get('XMPP_HOST', '127.0.0.1')
PORT = int(os.environ.get('XMPP_PORT', '15222'))
DOMAIN = os.environ.get('XMPP_DOMAIN', 'localhost')

passed = 0
failed = 0

def make_sasl_plain(user, password):
    payload = f'\x00{user}\x00{password}'.encode()
    return base64.b64encode(payload).decode()

class XmppClient:
    def __init__(self, name, user, password):
        self.name = name
        self.user = user
        self.password = password
        self.sock = None
        self.tls = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        self.sock.settimeout(5)

    def send(self, data):
        target = self.tls or self.sock
        if isinstance(data, str):
            data = data.encode()
        target.sendall(data)

    def recv(self, timeout=3):
        target = self.tls or self.sock
        target.settimeout(timeout)
        try:
            data = target.recv(8192)
            return data.decode('utf-8', errors='replace')
        except socket.timeout:
            return ''

    def recv_until(self, marker, timeout=5):
        target = self.tls or self.sock
        target.settimeout(0.5)
        buf = ''
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = target.recv(8192).decode('utf-8', errors='replace')
                buf += chunk
                if marker in buf:
                    return buf
            except socket.timeout:
                continue
        return buf

    def stream_open(self):
        self.send("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                  "xmlns:stream='http://etherx.jabber.org/streams' "
                  f"to='{DOMAIN}' version='1.0'>")
        return self.recv()

    def starttls(self):
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        resp = self.recv()
        if '<proceed' not in resp:
            raise RuntimeError(f'{self.name}: STARTTLS failed: {resp}')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.tls = ctx.wrap_socket(self.sock, server_hostname='localhost')

    def auth_plain(self):
        b64 = make_sasl_plain(self.user, self.password)
        self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
                  f"mechanism='PLAIN'>{b64}</auth>")
        resp = self.recv()
        if '<success' not in resp:
            raise RuntimeError(f'{self.name}: SASL PLAIN failed: {resp}')

    def bind(self, resource):
        self.send(f"<iq type='set' id='bind1'>"
                  f"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                  f"<resource>{resource}</resource></bind></iq>")
        return self.recv()

    def full_connect(self, resource):
        """Connect through to bound session (STARTTLS + SASL + bind)."""
        self.connect()
        self.stream_open()
        self.starttls()
        self.stream_open()
        self.auth_plain()
        resp = self.stream_open()
        bind_resp = self.bind(resource)
        return resp, bind_resp

    def close_tcp(self):
        """Abruptly close the TCP connection without </stream:stream>."""
        try:
            if self.tls:
                self.tls.close()
            elif self.sock:
                self.sock.close()
        except:
            pass
        self.tls = None
        self.sock = None

    def close(self):
        try:
            self.send("</stream:stream>")
            time.sleep(0.2)
        except:
            pass
        self.close_tcp()


def extract_stream_id(resp):
    """Extract the id attribute from <stream:stream ... id='...'/>."""
    m = re.search(r"id='([^']+)'", resp)
    if not m:
        m = re.search(r'id="([^"]+)"', resp)
    return m.group(1) if m else None


def extract_sm_id(resp):
    """Extract the SM-ID from <enabled ... id='...'/>."""
    m = re.search(r"<enabled[^>]*id='([^']+)'", resp)
    if not m:
        m = re.search(r'<enabled[^>]*id="([^"]+)"', resp)
    return m.group(1) if m else None


def check(label, condition, detail=''):
    global passed, failed
    if condition:
        print(f"  ✓ {label}")
        passed += 1
    else:
        print(f"  ✗ {label}" + (f" — {detail}" if detail else ""))
        failed += 1


# ========================================================================
# Test 1: SM enable with resume
# ========================================================================
def test_sm_enable():
    print("\n[Test 1] SM enable with resume")
    c = XmppClient('alice', 'alice', 'pass1')
    try:
        features, _ = c.full_connect('sm-test')

        c.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
        resp = c.recv_until('/>',  timeout=3)

        check("Server responds to <enable/>", '<enabled' in resp, resp[:200])
        check("<enabled/> has resume='true'", "resume='true'" in resp or 'resume="true"' in resp, resp[:200])

        sm_id = extract_sm_id(resp)
        check("<enabled/> has SM-ID", sm_id is not None and len(sm_id) > 0, f"id={sm_id}")
        check("SM-ID is 32 hex chars", sm_id is not None and len(sm_id) == 32, f"len={len(sm_id) if sm_id else 0}")

        return sm_id
    finally:
        c.close()


# ========================================================================
# Test 2: SM resume after disconnect (session still alive)
# ========================================================================
def test_sm_resume_active():
    print("\n[Test 2] SM resume after TCP disconnect (session still detached)")
    c = XmppClient('alice', 'alice', 'pass1')
    try:
        features, _ = c.full_connect('sm-resume')

        # Enable SM
        c.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
        resp = c.recv_until('/>', timeout=3)
        sm_id = extract_sm_id(resp)
        check("SM enabled", sm_id is not None, resp[:200])

        # Send presence so the server has something to track
        c.send("<presence/>")
        time.sleep(0.3)
        c.recv(timeout=0.5)  # drain

        # Abruptly close TCP (simulates network drop)
        c.close_tcp()
        time.sleep(1)  # Give server time to detect disconnect and detach

        # Reconnect and attempt resume
        c2 = XmppClient('alice', 'alice', 'pass1')
        c2.connect()
        c2.stream_open()
        c2.starttls()
        c2.stream_open()
        c2.auth_plain()
        features = c2.stream_open()

        check("Post-auth features contain <sm/>", '<sm' in features, features[:300])

        # Send resume
        c2.send(f"<resume xmlns='urn:xmpp:sm:3' h='0' previd='{sm_id}'/>")
        resp = c2.recv_until('/', timeout=5)

        got_resumed = '<resumed' in resp
        got_failed = '<failed' in resp
        check("Server responds to <resume/> (not silence)", got_resumed or got_failed, resp[:300])
        check("Session resumed successfully", got_resumed, resp[:300])

        if got_resumed:
            check("<resumed/> contains previd", sm_id in resp, resp[:300])

        c2.close()
        return True
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        failed += 1
        return False


# ========================================================================
# Test 3: SM resume with expired/unknown ID → fallback to bind
# ========================================================================
def test_sm_resume_fallback():
    print("\n[Test 3] SM resume with unknown ID → <failed/> → fallback to bind")
    c = XmppClient('alice', 'alice', 'pass1')
    try:
        c.connect()
        c.stream_open()
        c.starttls()
        c.stream_open()
        c.auth_plain()
        features = c.stream_open()

        check("Post-auth features contain <bind/>", '<bind' in features, features[:300])
        check("Post-auth features contain <sm/>", '<sm' in features, features[:300])

        # Try resume with a fake SM-ID
        fake_id = '00' * 16  # 32 hex chars, won't match any real session
        c.send(f"<resume xmlns='urn:xmpp:sm:3' h='0' previd='{fake_id}'/>")
        resp = c.recv_until('/', timeout=5)

        check("Server responds <failed/> for unknown SM-ID", '<failed' in resp, resp[:300])
        check("<failed/> contains item-not-found", 'item-not-found' in resp, resp[:300])

        # Now try bind (should still work on the same stream)
        bind_resp = c.bind('fallback-test')
        check("Bind succeeds after <failed/>", 'result' in bind_resp, bind_resp[:300])
        check("Bound JID is correct", f'alice@{DOMAIN}/fallback-test' in bind_resp, bind_resp[:300])

    finally:
        c.close()


# ========================================================================
# Test 4: Unique stream IDs per stream restart (RFC 6120 §4.7.3)
# ========================================================================
def test_unique_stream_ids():
    print("\n[Test 4] Unique stream IDs per restart (RFC 6120 §4.7.3)")
    c = XmppClient('alice', 'alice', 'pass1')
    try:
        c.connect()

        # Stream open #1 (pre-TLS)
        resp1 = c.stream_open()
        id1 = extract_stream_id(resp1)
        check("Pre-TLS stream has ID", id1 is not None, resp1[:200])

        c.starttls()

        # Stream open #2 (post-TLS)
        resp2 = c.stream_open()
        id2 = extract_stream_id(resp2)
        check("Post-TLS stream has ID", id2 is not None, resp2[:200])
        check("Post-TLS ID differs from pre-TLS", id1 != id2, f"{id1} vs {id2}")

        c.auth_plain()

        # Stream open #3 (post-auth)
        resp3 = c.stream_open()
        id3 = extract_stream_id(resp3)
        check("Post-auth stream has ID", id3 is not None, resp3[:200])
        check("Post-auth ID differs from post-TLS", id2 != id3, f"{id2} vs {id3}")
        check("All three IDs are unique", len({id1, id2, id3}) == 3,
              f"{id1}, {id2}, {id3}")

    finally:
        c.close()


# ========================================================================
# Test 5: SM stanza ack (<r/> → <a/>)
# ========================================================================
def test_sm_ack():
    print("\n[Test 5] SM stanza ack: <r/> → <a/>")
    c = XmppClient('alice', 'alice', 'pass1')
    try:
        c.full_connect('sm-ack')

        c.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
        resp = c.recv_until('/>', timeout=3)
        check("SM enabled", '<enabled' in resp, resp[:200])

        # Request ack
        c.send("<r xmlns='urn:xmpp:sm:3'/>")
        resp = c.recv_until('/>', timeout=3)
        check("Server responds <a/> to <r/>", '<a ' in resp or '<a/' in resp, resp[:200])

        # Verify h attribute
        m = re.search(r"<a[^>]*h='(\d+)'", resp) or re.search(r'<a[^>]*h="(\d+)"', resp)
        check("<a/> has h attribute", m is not None, resp[:200])
        if m:
            check("h value is 0 (no stanzas sent yet)", m.group(1) == '0', f"h={m.group(1)}")

    finally:
        c.close()


# ========================================================================
# Test 6: SM resume with stanza replay
# ========================================================================
def test_sm_resume_replay():
    print("\n[Test 6] SM resume with stanza replay")
    alice = XmppClient('alice', 'alice', 'pass1')
    bob = XmppClient('bob', 'bob', 'pass2')
    try:
        # Alice connects with SM
        alice.full_connect('replay-a')
        alice.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
        resp = alice.recv_until('/>', timeout=3)
        sm_id = extract_sm_id(resp)
        check("Alice SM enabled", sm_id is not None, resp[:200])
        alice.send("<presence/>")
        time.sleep(0.3)
        alice.recv(timeout=0.5)  # drain

        # Bob connects
        bob.full_connect('replay-b')
        bob.send("<presence/>")
        time.sleep(0.5)
        bob.recv(timeout=0.5)  # drain

        # Bob sends a message to Alice (Alice will receive it)
        bob.send(f"<message to='alice@{DOMAIN}' type='chat' id='replay-msg-1'>"
                 "<body>Message before disconnect</body></message>")
        time.sleep(0.5)

        # Alice receives but does NOT ack (h stays at 0 from server's perspective)
        msg = alice.recv_until('</message>', timeout=3)
        check("Alice receives message before disconnect", 'replay-msg-1' in msg, msg[:200])

        # Alice disconnects abruptly (server should keep the unacked message)
        alice.close_tcp()
        time.sleep(1)

        # Bob sends another message while Alice is disconnected
        bob.send(f"<message to='alice@{DOMAIN}' type='chat' id='replay-msg-2'>"
                 "<body>Message during disconnect</body></message>")
        time.sleep(0.5)

        # Alice reconnects and resumes
        alice2 = XmppClient('alice', 'alice', 'pass1')
        alice2.connect()
        alice2.stream_open()
        alice2.starttls()
        alice2.stream_open()
        alice2.auth_plain()
        alice2.stream_open()

        alice2.send(f"<resume xmlns='urn:xmpp:sm:3' h='0' previd='{sm_id}'/>")
        resp = alice2.recv_until('</message>', timeout=5)

        got_resumed = '<resumed' in resp
        check("Session resumed after message", got_resumed, resp[:300])

        # The server should replay the unacked message(s)
        if got_resumed:
            check("Replayed stanzas contain message", '<message' in resp or '<body>' in resp, resp[:500])

        alice2.close()
    finally:
        bob.close()


# ========================================================================
# Main
# ========================================================================
if __name__ == '__main__':
    print("=" * 60)
    print("xmppd E2E Test: XEP-0198 Stream Management Resume")
    print("=" * 60)

    test_sm_enable()
    test_sm_resume_fallback()  # Run before active resume (doesn't need prior session)
    test_unique_stream_ids()
    test_sm_ack()
    test_sm_resume_active()
    test_sm_resume_replay()

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    sys.exit(1 if failed > 0 else 0)
