#!/usr/bin/env python3
"""End-to-end test: XEP-0198 SM resume with MUC occupancy (T177 occupant migration).

alice joins a MUC room with SM resume enabled, disconnects abruptly, and
resumes - repeatedly. At workers>1, SO_REUSEPORT lands the reconnect on a
different worker ~75% of the time, so repeated rounds exercise the
cross-worker occupant migration (bundle room list + room_occupant_move actor
message + shadow sync). Same-worker rounds exercise the in-place variant.

Assertions per round:
  - <resume/> returns <resumed/> (never <failed/>) even though alice is in a room
  - the groupchat sent while detached is replayed from the unacked queue
  - alice receives post-resume groupchat WITHOUT rejoining (fan-in migrated)
  - alice can send groupchat post-resume (canonical sender record migrated)
  - bob NEVER sees a second join presence for alice's nick (move, not rejoin)

Suite-level, when XMPP_SERVER_LOG is set (multi-worker lane):
  - at least one cross-worker handoff actually occurred (log evidence)
  - no 'occupant moves skipped' or 'occupancy exceeds migration cap' warnings

Environment: XMPP_HOST, XMPP_PORT, XMPP_DOMAIN, XMPP_MUC_HOST,
             XMPP_SERVER_LOG (optional: xmppd log for handoff evidence),
             XMPP_ROUNDS (default 6)
"""

import socket, ssl, time, base64, sys, re, os

HOST = os.environ.get('XMPP_HOST', '127.0.0.1')
PORT = int(os.environ.get('XMPP_PORT', '15222'))
DOMAIN = os.environ.get('XMPP_DOMAIN', 'localhost')
MUC_HOST = os.environ.get('XMPP_MUC_HOST', 'conference.localhost')
SERVER_LOG = os.environ.get('XMPP_SERVER_LOG', '')
WORKERS = int(os.environ.get('XMPP_WORKERS', '1'))
ROUNDS = int(os.environ.get('XMPP_ROUNDS', '6'))

ROOM = f"resume-room-{os.getpid()}@{MUC_HOST}"
NICK_ALICE = 'al'
NICK_BOB = 'bo'

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
        self.log = []  # everything received, for presence auditing

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
            text = data.decode('utf-8', errors='replace')
            self.log.append(text)
            return text
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
                self.log.append(chunk)
                if marker in buf:
                    return buf
            except socket.timeout:
                continue
        return buf

    def drain(self, seconds=0.5):
        """Read whatever is pending; returns collected text."""
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

    def auth_plain(self):
        b64 = make_sasl_plain(self.user, self.password)
        self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
                  f"mechanism='PLAIN'>{b64}</auth>")
        resp = self.recv()
        if '<success' not in resp:
            raise RuntimeError(f'{self.name}: SASL PLAIN failed: {resp}')

    def full_connect(self, resource):
        self.connect()
        self.stream_open()
        self.starttls()
        self.stream_open()
        self.auth_plain()
        self.stream_open()
        self.send(f"<iq type='set' id='bind1'>"
                  f"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                  f"<resource>{resource}</resource></bind></iq>")
        return self.recv()

    def resume_connect(self, sm_id):
        """Reconnect and attempt SM resume; returns the response buffer."""
        self.connect()
        self.stream_open()
        self.starttls()
        self.stream_open()
        self.auth_plain()
        self.stream_open()
        self.send(f"<resume xmlns='urn:xmpp:sm:3' h='0' previd='{sm_id}'/>")
        return self.recv_until('urn:xmpp:sm:3', timeout=8)

    def close(self):
        try:
            self.send("</stream:stream>")
            time.sleep(0.2)
        except Exception:
            pass
        self.close_tcp()

    def close_tcp(self):
        try:
            if self.tls:
                self.tls.close()
            elif self.sock:
                self.sock.close()
        except Exception:
            pass
        self.tls = None
        self.sock = None


def extract_sm_id(resp):
    m = re.search(r"<enabled[^>]*id='([^']+)'", resp) or re.search(r'<enabled[^>]*id="([^"]+)"', resp)
    return m.group(1) if m else None


def muc_join(c, nick):
    c.send(f"<presence to='{ROOM}/{nick}'/>")
    resp = c.recv_until("status code='110'", timeout=8)
    return "code='110'" in resp or 'code="110"' in resp


def groupchat(c, text):
    c.send(f"<message to='{ROOM}' type='groupchat' id='msg-{text}'>"
           f"<body>{text}</body></message>")


def check(label, condition, detail=''):
    global passed, failed
    if condition:
        print(f"  PASS {label}")
        passed += 1
    else:
        print(f"  FAIL {label}" + (f" - {detail}" if detail else ""))
        failed += 1


def count_alice_join_presences(bob):
    """Count available-presence stanzas bob received from ROOM/al."""
    transcript = ''.join(bob.log)
    # join presence = <presence from='ROOM/al' ...> WITHOUT type='unavailable'
    count = 0
    for m in re.finditer(r"<presence[^>]*from='%s/%s'[^>]*>" % (re.escape(ROOM), NICK_ALICE), transcript):
        if "type='unavailable'" not in m.group(0):
            count += 1
    return count


def wait_for_detach(sm_id, timeout=4):
    """Wait until the server has detached alice's session (log evidence).

    Sending the 'while away' groupchat before the detach is processed would
    queue it onto the dead socket instead of the SM unacked queue. Without a
    server log (standalone runs), fall back to a plain sleep.
    """
    if not SERVER_LOG:
        time.sleep(1.5)
        return
    marker = f'detached for SM resume (id={sm_id}'
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(SERVER_LOG, 'r', errors='replace') as f:
                if marker in f.read():
                    return
        except OSError:
            pass
        time.sleep(0.1)
    time.sleep(0.5)  # log missing: proceed anyway, replay check will catch it


if __name__ == '__main__':
    print('=' * 60)
    print('xmppd E2E Test: SM resume with MUC occupancy (T177)')
    print(f'  room={ROOM} rounds={ROUNDS}')
    print('=' * 60)

    alice = XmppClient('alice', 'alice', 'pass1')
    bob = XmppClient('bob', 'bob', 'pass2')

    try:
        # ---- Setup: both clients in the room ------------------------------
        print('\n[Setup] connect, SM enable, join room')
        alice.full_connect('phone')
        alice.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
        resp = alice.recv_until('/>', timeout=3)
        sm_id = extract_sm_id(resp)
        check('alice SM enabled with resume', sm_id is not None, resp[:200])

        bob.full_connect('laptop')
        bob.send('<presence/>')
        alice.send('<presence/>')

        check('alice joins room', muc_join(alice, NICK_ALICE))
        check('bob joins room', muc_join(bob, NICK_BOB))

        baseline = count_alice_join_presences(bob)  # includes alice1's join (1)
        bob.drain(0.5)
        alice.drain(0.5)

        # Sanity: groupchat works pre-disconnect
        groupchat(bob, 'baseline-from-bob')
        resp = alice.recv_until('baseline-from-bob', timeout=5)
        check('baseline groupchat delivers', 'baseline-from-bob' in resp)
        alice.drain(0.3)

        # ---- Rounds: disconnect + resume ---------------------------------
        for rnd in range(1, ROUNDS + 1):
            print(f'\n[Round {rnd}] abrupt disconnect + resume')

            alice.close_tcp()
            wait_for_detach(sm_id)

            # Groupchat while detached: must land in the SM unacked queue
            away_msg = f'while-away-{rnd}'
            groupchat(bob, away_msg)
            time.sleep(0.4)
            bob.drain(0.2)

            resp = alice.resume_connect(sm_id)
            check(f'round {rnd}: <resumed/> (not <failed/>)', "<resumed" in resp,
                  resp[:300])

            # Read on until the detached-era message shows up in the replay
            if away_msg not in resp:
                resp += alice.recv_until(away_msg, timeout=5)
            check(f'round {rnd}: detached-era groupchat replayed', away_msg in resp)

            # Fan-in: post-resume message from bob must reach alice (no rejoin)
            post_msg = f'post-resume-{rnd}'
            groupchat(bob, post_msg)
            resp = alice.recv_until(post_msg, timeout=5)
            check(f'round {rnd}: post-resume groupchat received without rejoin',
                  post_msg in resp)

            # Fan-out: alice sends; bob must receive (canonical sender record ok)
            from_msg = f'from-alice-{rnd}'
            groupchat(alice, from_msg)
            resp = bob.recv_until(from_msg, timeout=5)
            check(f'round {rnd}: alice groupchat echoes to bob', from_msg in resp)
            bob.drain(0.3)

            # Move, not rejoin: bob must never see another join presence for al
            joins = count_alice_join_presences(bob) - baseline
            check(f'round {rnd}: no rejoin presence broadcast to occupants', joins == 0,
                  f'extra join presences seen: {joins}')

        # ---- Cleanup ------------------------------------------------------
        print('\n[Teardown]')
        alice.close_tcp()
        bob.close()

        # ---- Server-log evidence (multi-worker lane) ----------------------
        if SERVER_LOG:
            try:
                with open(SERVER_LOG, 'r', errors='replace') as f:
                    log_text = f.read()
                handoffs = len(re.findall(r'cross-worker session resumed', log_text))
                skipped = len(re.findall(r'occupant moves skipped', log_text))
                capped = len(re.findall(r'occupancy exceeds migration cap', log_text))
                if WORKERS > 1:
                    check('cross-worker handoff observed at least once', handoffs >= 1,
                          f'cross-worker resumes in log: {handoffs}')
                check('no skipped occupant moves in server log', skipped == 0,
                      f'skipped={skipped}')
                check('no migration-cap fallbacks in server log', capped == 0,
                      f'capped={capped}')
            except OSError as e:
                check('server log readable', False, str(e))

    except Exception as e:
        print(f'  FAIL Exception: {e}')
        failed += 1

    print('\n' + '=' * 60)
    print(f'Results: {passed} passed, {failed} failed')
    print('=' * 60)
    sys.exit(1 if failed > 0 else 0)
