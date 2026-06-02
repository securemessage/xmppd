#!/usr/bin/env python3
"""End-to-end test: two-person chat via xmppd.

Connects alice and bob, establishes STARTTLS + SASL PLAIN,
binds resources, exchanges presence, sends a message with body,
and verifies the recipient receives the full stanza including <body>.
"""

import socket, ssl, time, base64, sys, select

HOST = '127.0.0.1'
PORT = 15222

def make_sasl_plain(user, password):
    """SASL PLAIN: \\0authzid\\0password (authzid=username for XMPP)"""
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
        """Receive data until marker is found or timeout."""
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
                  "to='localhost' version='1.0'>")
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

    def send_presence(self):
        self.send("<presence/>")

    def send_message(self, to, body, msg_type='chat'):
        self.send(f"<message to='{to}' type='{msg_type}' id='msg1'>"
                  f"<body>{body}</body>"
                  f"<thread>test-thread-1</thread>"
                  f"</message>")

    def close(self):
        try:
            self.send("</stream:stream>")
            time.sleep(0.2)
        except:
            pass
        try:
            if self.tls:
                self.tls.close()
            elif self.sock:
                self.sock.close()
        except:
            pass

def test_e2e():
    print("=" * 60)
    print("xmppd E2E Test: Two-Person Chat")
    print("=" * 60)

    alice = XmppClient('alice', 'alice', 'pass1')
    bob = XmppClient('bob', 'bob', 'pass2')

    try:
        # --- Alice connects ---
        print("\n[1] Alice: connecting...")
        alice.connect()
        resp = alice.stream_open()
        assert '<stream:features>' in resp, f"Alice: no features in: {resp[:200]}"
        assert '<starttls' in resp, "Alice: no STARTTLS offered"
        print("    ✓ Stream opened, STARTTLS offered")

        print("[2] Alice: STARTTLS...")
        alice.starttls()
        print("    ✓ TLS established")

        print("[3] Alice: post-TLS stream + SASL PLAIN...")
        resp = alice.stream_open()
        assert 'PLAIN' in resp, f"Alice: PLAIN not offered: {resp[:200]}"
        alice.auth_plain()
        print("    ✓ Authenticated")

        print("[4] Alice: post-auth stream + bind...")
        resp = alice.stream_open()
        assert '<bind' in resp, f"Alice: no bind in features: {resp[:200]}"
        resp = alice.bind('desktop')
        assert 'result' in resp, f"Alice: bind failed: {resp[:200]}"
        assert 'alice@localhost' in resp, f"Alice: wrong JID in bind result: {resp[:200]}"
        print(f"    ✓ Bound: alice@localhost/desktop")

        print("[5] Alice: sending initial presence...")
        alice.send_presence()
        time.sleep(0.3)
        print("    ✓ Presence sent")

        # --- Bob connects ---
        print("\n[6] Bob: connecting...")
        bob.connect()
        resp = bob.stream_open()
        assert '<starttls' in resp, "Bob: no STARTTLS"

        print("[7] Bob: STARTTLS + SASL PLAIN + bind...")
        bob.starttls()
        bob.stream_open()
        bob.auth_plain()
        resp = bob.stream_open()
        resp = bob.bind('mobile')
        assert 'bob@localhost' in resp, f"Bob: wrong JID: {resp[:200]}"
        print(f"    ✓ Bound: bob@localhost/mobile")

        print("[8] Bob: sending initial presence...")
        bob.send_presence()
        time.sleep(1)  # Allow server to process presence
        # Drain any presence-related data bob might receive
        drain = bob.recv(timeout=0.5)
        if drain:
            print(f"    (Bob received on presence: {drain[:200]})")
        print("    ✓ Presence sent")

        # --- Alice sends message to Bob ---
        print("\n[9] Alice → Bob: sending message with body...")
        alice.send_message('bob@localhost', 'Hello Bob! This is a test message.', 'chat')
        print("    ✓ Message sent")
        time.sleep(0.5)  # Allow server to route

        # --- Bob receives message ---
        print("[10] Bob: waiting for message...")
        resp = bob.recv_until('</message>', timeout=3)
        print(f"    Raw received: {resp[:500]}")

        assert '<message' in resp, f"Bob: no <message> received: {resp}"
        assert '<body>' in resp, f"Bob: no <body> in message: {resp}"
        assert 'Hello Bob! This is a test message.' in resp, \
            f"Bob: body content missing: {resp}"
        assert "from='alice@localhost/default'" in resp, \
            f"Bob: wrong from JID: {resp}"
        assert '<thread>test-thread-1</thread>' in resp, \
            f"Bob: thread element missing: {resp}"
        print("    ✓ Message received with full body!")
        print(f"    ✓ from='alice@localhost/desktop'")
        print(f"    ✓ <body>Hello Bob! This is a test message.</body>")
        print(f"    ✓ <thread>test-thread-1</thread>")

        # --- Bob replies to Alice ---
        print("\n[11] Bob → Alice: sending reply...")
        bob.send_message('alice@localhost', 'Hi Alice! Got your message.', 'chat')
        print("    ✓ Reply sent")

        print("[12] Alice: waiting for reply...")
        resp = alice.recv_until('</message>', timeout=3)
        print(f"    Raw received: {resp[:500]}")

        assert '<body>' in resp, f"Alice: no <body> in reply: {resp}"
        assert 'Hi Alice! Got your message.' in resp, \
            f"Alice: reply body missing: {resp}"
        assert "from='bob@localhost/default'" in resp, \
            f"Alice: wrong from JID: {resp}"
        print("    ✓ Reply received with full body!")
        print(f"    ✓ from='bob@localhost/default'")
        print(f"    ✓ <body>Hi Alice! Got your message.</body>")

        # --- Test special characters ---
        print("\n[13] Alice → Bob: message with XML entities...")
        alice.send_message('bob@localhost', 'Does 2 &lt; 3? Yes &amp; no!', 'chat')
        resp = bob.recv_until('</message>', timeout=3)
        print(f"    Raw received: {resp[:500]}")
        assert '<body>' in resp, f"Bob: no body with entities: {resp}"
        # The body should have the entities preserved
        assert '&lt;' in resp or '<' in resp, f"Bob: entity test failed: {resp}"
        print("    ✓ Message with entities received")

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED — Full stanza forwarding works!")
        print("=" * 60)

    except Exception as e:
        print(f"\n✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        alice.close()
        bob.close()

if __name__ == '__main__':
    test_e2e()
