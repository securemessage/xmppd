#!/usr/bin/env python3
"""End-to-end test: MUC MAM query routing to the room-owning worker (T112).

Every MAM query in this suite sets a MAM queryid deliberately DIFFERENT from
the IQ stanza id. A query routed to the owning worker must behave identically
to a local one:

  - the fin <iq> result carries the IQ stanza id (not the queryid)
  - RSM <max> is honored (2 results for max=2 out of 3 archived messages)
  - RSM <after> paging continues from the first page's <last> anchor
  - each <result> echoes the query's queryid (XEP-0313)

At workers>1, SO_REUSEPORT pins alice's connection to one worker while room
ownership hashes N rooms across all workers (~3/4 of queries route cross-
worker at workers=4). Suite-level log evidence asserts at least one query
actually routed ('routing MAM query for room' in the server log), so a green
run cannot be a false pass through the local path only.

Environment: XMPP_HOST, XMPP_PORT, XMPP_DOMAIN, XMPP_MUC_HOST,
             XMPP_SERVER_LOG (optional: xmppd log for routing evidence),
             XMPP_WORKERS, XMPP_ROUNDS (default 8)
"""

import socket, ssl, time, base64, sys, re, os

HOST = os.environ.get('XMPP_HOST', '127.0.0.1')
PORT = int(os.environ.get('XMPP_PORT', '15222'))
DOMAIN = os.environ.get('XMPP_DOMAIN', 'localhost')
MUC_HOST = os.environ.get('XMPP_MUC_HOST', 'conference.localhost')
SERVER_LOG = os.environ.get('XMPP_SERVER_LOG', '')
WORKERS = int(os.environ.get('XMPP_WORKERS', '1'))
ROUNDS = int(os.environ.get('XMPP_ROUNDS', '8'))

PASS1 = 'pass1'
PASS2 = 'pass2'

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

    def full_connect(self, resource):
        self.connect()
        self.stream_open()
        self.starttls()
        self.stream_open()
        b64 = make_sasl_plain(self.user, self.password)
        self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
                  f"mechanism='PLAIN'>{b64}</auth>")
        if '<success' not in self.recv():
            raise RuntimeError(f'{self.name}: SASL PLAIN failed')
        self.stream_open()
        self.send(f"<iq type='set' id='bind1'>"
                  f"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                  f"<resource>{resource}</resource></bind></iq>")
        return self.recv()

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


def muc_join(c, room, nick):
    c.send(f"<presence to='{room}/{nick}'/>")
    resp = c.recv_until("status code='110'", timeout=8)
    return "code='110'" in resp or 'code="110"' in resp


def groupchat(c, room, text):
    c.send(f"<message to='{room}' type='groupchat' id='msg-{text}'>"
           f"<body>{text}</body></message>")


def mam_query(c, room, iq_id, query_id, rsm):
    c.send(f"<iq type='set' id='{iq_id}' to='{room}'>"
           f"<query xmlns='urn:xmpp:mam:2' queryid='{query_id}'>"
           f"<set xmlns='http://jabber.org/protocol/rsm'>{rsm}</set>"
           f"</query></iq>")


def collect_mam(c, iq_id, timeout=6):
    """Read until the fin IQ for iq_id arrives (results may precede it)."""
    return c.recv_until(f"id='{iq_id}'><fin", timeout=timeout)


if __name__ == '__main__':
    print('=' * 60)
    print('xmppd E2E Test: MUC MAM routing to owning worker (T112)')
    print(f'  rooms={ROUNDS} workers={WORKERS}')
    print('=' * 60)

    alice = XmppClient('alice', 'alice', PASS1)
    bob = XmppClient('bob', 'bob', PASS2)
    routed_queries = 0  # local estimate (log evidence is authoritative)

    try:
        print('\n[Setup] connect alice + bob')
        alice.full_connect('phone')
        bob.full_connect('laptop')
        alice.drain(0.3)
        bob.drain(0.3)

        for rnd in range(ROUNDS):
            room = f'mam-r{rnd}-{os.getpid()}@{MUC_HOST}'
            bodies = [f'r{rnd}-m{k}' for k in range(3)]
            print(f'\n[Room {rnd}] {room}')

            check(f'room {rnd}: alice joins', muc_join(alice, room, 'al'))
            check(f'room {rnd}: bob joins', muc_join(bob, room, 'bo'))
            bob.drain(0.3)

            # 3 groupchat messages: alice, bob, alice — async archive writer
            # (T87) preserves enqueue order, so archive order matches.
            groupchat(alice, room, bodies[0])
            bob.recv_until(bodies[0], timeout=5)
            groupchat(bob, room, bodies[1])
            alice.recv_until(bodies[1], timeout=5)
            groupchat(alice, room, bodies[2])
            bob.recv_until(bodies[2], timeout=5)
            bob.drain(0.2)

            # Wait for the async archive writer to flush all 3 messages
            # (probe with an unbounded query; MAM queryid != IQ id always).
            archived = False
            for attempt in range(20):
                mam_query(alice, room, f'probe-{rnd}-{attempt}', f'qp{rnd}a{attempt}', '<max>50</max>')
                resp = collect_mam(alice, f'probe-{rnd}-{attempt}', timeout=3)
                m = re.search(r"<count>(\d+)</count>", resp)
                if m and int(m.group(1)) >= 3:
                    archived = True
                    break
                time.sleep(0.3)
            check(f'room {rnd}: 3 messages archived', archived)
            if not archived:
                continue
            alice.drain(0.2)

            # Page 1: max=2 — the remote path must honor RSM, id, queryid.
            mam_query(alice, room, f'mam-{rnd}', f'qid-{rnd}', '<max>2</max>')
            page1 = collect_mam(alice, f'mam-{rnd}')
            check(f'room {rnd}: fin id is the IQ stanza id (not queryid)',
                  f"type='result' id='mam-{rnd}'><fin" in page1,
                  page1[-400:] if len(page1) > 0 else 'no fin received')
            results1 = re.findall(r"<result xmlns='urn:xmpp:mam:2'", page1)
            check(f'room {rnd}: RSM max=2 honored', len(results1) == 2,
                  f'got {len(results1)} results')
            check(f'room {rnd}: results echo queryid',
                  page1.count(f"queryid='qid-{rnd}'") == 2)
            m_first = re.search(r'<first>([^<]+)</first>', page1)
            m_last = re.search(r'<last>([^<]+)</last>', page1)
            check(f'room {rnd}: RSM first/last anchors present',
                  m_first is not None and m_last is not None)

            # Page 2: after=<page1 last> — the remaining single message.
            if m_last:
                last_id = m_last.group(1)
                mam_query(alice, room, f'mam2-{rnd}', f'qid2-{rnd}', f'<max>2</max><after>{last_id}</after>')
                page2 = collect_mam(alice, f'mam2-{rnd}')
                check(f'room {rnd}: page2 fin id is the IQ stanza id',
                      f"type='result' id='mam2-{rnd}'><fin" in page2)
                results2 = re.findall(r"<result xmlns='urn:xmpp:mam:2'", page2)
                check(f'room {rnd}: after-paging returns the 1 remaining message',
                      len(results2) == 1, f'got {len(results2)}')
                check(f'room {rnd}: page2 body is the third message',
                      bodies[2] in page2)
            bob.drain(0.2)

        print('\n[Teardown]')
        alice.close()
        bob.close()

        # ---- Server-log evidence (multi-worker lane) ----------------------
        if SERVER_LOG:
            try:
                with open(SERVER_LOG, 'r', errors='replace') as f:
                    log_text = f.read()
                routed = len(re.findall(r'routing MAM query for room', log_text))
                if WORKERS > 1:
                    check('cross-worker MAM routing observed at least once',
                          routed >= 1, f'routed queries in log: {routed}')
                drops = len(re.findall(r'room mailbox full', log_text))
                check('no room mailbox drops in server log', drops == 0,
                      f'drops={drops}')
            except OSError as e:
                check('server log readable', False, str(e))

    except Exception as e:
        print(f'  FAIL Exception: {e}')
        failed += 1
        alice.close()
        bob.close()

    print('\n' + '=' * 60)
    print(f'Results: {passed} passed, {failed} failed')
    print('=' * 60)
    sys.exit(1 if failed > 0 else 0)
