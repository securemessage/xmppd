#!/usr/bin/env python3
"""End-to-end regression: MUC same-nick resource takeover (XEP-0045 §7.2.14).

When a second resource of the same bare JID joins a room with a nick already
in use by that user, xmppd collapses the two resources onto one occupant
record (latest resource wins). The collapse used to overwrite the occupant's
real-JID buffer in place without repairing the room's jid_map index, whose
keys alias that same buffer: every later findByRealJid missed, so the
takeover resource could not send (not-acceptable), and disconnect could not
remove the occupant (ghost).

Asserts the full user-visible flow for the takeover resource:
  1. join completes (occupant roster + self-presence 110 + history replay)
  2. groupchat send is reflected and fanned out (no not-acceptable)
  3. unclean disconnect removes the occupant (unavailable broadcast)
  4. a later resource can then join normally

Stdlib only. Environment: XMPP_HOST, XMPP_PORT, XMPP_DOMAIN (defaults match
test/integration/run-multiworker.sh).
"""

import socket, ssl, time, base64, sys, os

HOST = os.environ.get('XMPP_HOST', '127.0.0.1')
PORT = int(os.environ.get('XMPP_PORT', '15222'))
DOMAIN = os.environ.get('XMPP_DOMAIN', 'localhost')
ROOM = os.environ.get('XMPP_ROOM', f'firstroom@conference.{DOMAIN}')

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


class Xmpp:
    def __init__(self, user, password, resource):
        sock = socket.create_connection((HOST, PORT), timeout=5)
        self.buf = ''

        def send(x):
            sock.sendall(x.encode())

        send("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
             "xmlns:stream='http://etherx.jabber.org/streams' "
             f"to='{DOMAIN}' version='1.0'>")
        sock.recv(8192)

        send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        if '<proceed' not in sock.recv(8192).decode('utf-8', 'replace'):
            raise RuntimeError('STARTTLS refused')

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(sock, server_hostname='localhost')
        self.sock.settimeout(8)

        self.send("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                  "xmlns:stream='http://etherx.jabber.org/streams' "
                  f"to='{DOMAIN}' version='1.0'>")
        self.drain(2)

        pw = base64.b64encode(f'\x00{user}\x00{password}'.encode()).decode()
        self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{pw}</auth>")
        if '<success' not in self.drain(2):
            raise RuntimeError(f'SASL failed: {self.buf}')

        self.send("<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                  "xmlns:stream='http://etherx.jabber.org/streams' "
                  f"to='{DOMAIN}' version='1.0'>")
        self.drain(2)

        self.resource = resource
        self.send(("<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                   f"<resource>{resource}</resource></bind></iq>"))
        resp = self.drain(2)
        if f'{user}@{DOMAIN}/{resource}' not in resp:
            raise RuntimeError(f'bind failed: {resp}')
        self.send('<presence><priority>0</priority></presence>')
        self.drain(1)

    def send(self, xml):
        self.sock.sendall(xml.encode())

    def drain(self, seconds):
        """Read everything the server sends for `seconds`, appending to buf."""
        from_buf_at = len(self.buf)
        deadline = time.time() + seconds
        self.sock.settimeout(0.3)
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(8192)
                if not chunk:
                    break
                self.buf += chunk.decode('utf-8', 'replace')
            except (socket.timeout, ssl.SSLError):
                continue
            except (ConnectionResetError, BrokenPipeError):
                break
        self.sock.settimeout(8)
        return self.buf[from_buf_at:]

    def join(self, nick):
        self.send(f"<presence to='{ROOM}/{nick}'><x xmlns='http://jabber.org/protocol/muc'/></presence>")

    def groupchat(self, text):
        self.send(f"<message to='{ROOM}' type='groupchat'><body>{text}</body></message>")


if __name__ == '__main__':
    print('=' * 60)
    print('xmppd E2E Test: MUC same-nick resource takeover (collapse)')
    print('=' * 60)

    # Incumbent resource joins and posts history
    a1 = Xmpp('alice', 'pass1', 'resA')
    a1.join('alice')
    join1 = a1.drain(3)
    check('incumbent: joined with status 110', "code='110'" in join1 or 'code="110"' in join1, join1[:200])

    bob = Xmpp('bob', 'pass2', 'resB')
    bob.join('bob')
    bob.drain(3)
    a1.drain(2)

    a1.groupchat('takeover-history-probe-1')
    a1.drain(2)
    bob_rx = bob.drain(3)
    check('incumbent message fanned out to bob', 'takeover-history-probe-1' in bob_rx, bob_rx[:200])

    # Takeover: same bare JID, new resource, same nick
    a2 = Xmpp('alice', 'pass1', 'resC')
    a2.join('alice')
    rx = a2.drain(4)
    check('takeover to completed', "code='110'" in rx or 'code="110"' in rx, rx[:250])
    check('takeover resource received occupant roster', f"{ROOM}/bob'" in rx or f'{ROOM}/bob"' in rx, rx[:250])
    check('takeover resource received history replay', 'takeover-history-probe-1' in rx, rx[-400:])
    check('takeover join was not a presence error', 'type=\'error\'' not in rx, rx[:250])

    # Takeover resource must be able to send: reflection + fan-out
    a2_rx_start = len(a2.buf)
    a2.groupchat('takeover-send-probe-2')
    a2_rx = a2.drain(3)
    bob_rx = bob.drain(3)
    check('takeover resource message reflected (no not-acceptable)',
          'takeover-send-probe-2' in a2_rx and 'not-acceptable' not in a2_rx, a2_rx[:250])
    check('takeover resource message fanned out to bob',
          'takeover-send-probe-2' in bob_rx, bob_rx[:250])

    # Unclean disconnect must remove the occupant (no ghost)
    a2.sock.close()
    time.sleep(1.0)
    bob_rx = bob.drain(3)
    check('ghost removal: bob saw unavailable for the takeover nick',
          "type='unavailable'" in bob_rx and f'{ROOM}/alice' in bob_rx, bob_rx[:250])

    # Room state is clean: a fresh resource joins normally
    a3 = Xmpp('alice', 'pass1', 'resD')
    a3.join('alice')
    rx = a3.drain(4)
    check('post-takeover fresh join completes', "code='110'" in rx or 'code="110"' in rx, rx[:250])

    a3.sock.close()
    bob.sock.close()
    a1.sock.close()

    print()
    print('=' * 60)
    print(f'Results: {passed} passed, {failed} failed')
    print('=' * 60)
    sys.exit(1 if failed > 0 else 0)
