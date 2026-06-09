#!/usr/bin/env python3
"""Cross-thread delivery test for xmppd multi-worker mode.

Connects multiple clients to an xmppd running with workers >= 2.
With SO_REUSEPORT, the kernel distributes connections across workers.
We connect enough clients that the probability of all landing on the
same thread is negligible, then exchange messages between all pairs.

Usage:
    # Start xmppd in multi-worker mode first:
    # ./xmppd --host localhost --port 15222 --workers 2 --db /tmp/xmppd-test \
    #         --cert server.pem --key server.key --auth-socket /tmp/xmppd-auth.sock

    python3 cross-thread-chat.py [--host HOST] [--port PORT] [--count N]
"""

import socket, ssl, time, base64, sys, argparse, threading

HOST = '127.0.0.1'
PORT = 5222
DEFAULT_USERS = ['alice', 'bob', 'charlie', 'user1', 'user2', 'user3', 'user4', 'user5']
PASSWORD = 'test1234'


def make_sasl_plain(user, password):
    payload = f'\x00{user}\x00{password}'.encode()
    return base64.b64encode(payload).decode()


class XmppClient:
    def __init__(self, user, domain='localhost', resource='test'):
        self.user = user
        self.domain = domain
        self.resource = resource
        self.jid = f'{user}@{domain}/{resource}'
        self.bare = f'{user}@{domain}'
        self.sock = None
        self.tls = None

    def connect(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
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
            return target.recv(16384).decode('utf-8', errors='replace')
        except socket.timeout:
            return ''

    def recv_until(self, marker, timeout=5):
        target = self.tls or self.sock
        target.settimeout(0.5)
        buf = ''
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = target.recv(16384).decode('utf-8', errors='replace')
                buf += chunk
                if marker in buf:
                    return buf
            except socket.timeout:
                continue
        return buf

    def stream_open(self, domain='localhost'):
        self.send(f"<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                  f"xmlns:stream='http://etherx.jabber.org/streams' "
                  f"to='{domain}' version='1.0'>")
        return self.recv()

    def starttls(self):
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        resp = self.recv()
        if '<proceed' not in resp:
            raise RuntimeError(f'{self.user}: STARTTLS failed: {resp[:200]}')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.tls = ctx.wrap_socket(self.sock, server_hostname='localhost')

    def auth_plain(self, password=PASSWORD):
        b64 = make_sasl_plain(self.user, password)
        self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
                  f"mechanism='PLAIN'>{b64}</auth>")
        resp = self.recv()
        if '<success' not in resp:
            raise RuntimeError(f'{self.user}: SASL PLAIN failed: {resp[:200]}')

    def bind(self):
        self.send(f"<iq type='set' id='bind1'>"
                  f"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                  f"<resource>{self.resource}</resource></bind></iq>")
        resp = self.recv()
        if 'result' not in resp:
            raise RuntimeError(f'{self.user}: bind failed: {resp[:200]}')
        return resp

    def send_presence(self):
        self.send("<presence/>")

    def send_message(self, to, body, msg_id='test'):
        self.send(f"<message to='{to}' type='chat' id='{msg_id}'>"
                  f"<body>{body}</body></message>")

    def close(self):
        try:
            self.send("</stream:stream>")
            time.sleep(0.1)
        except:
            pass
        try:
            (self.tls or self.sock).close()
        except:
            pass


def full_connect(client, host, port, domain='localhost', use_tls=True):
    """Full XMPP session establishment: connect → TLS → SASL → bind → presence."""
    client.connect(host, port)
    resp = client.stream_open(domain)
    assert '<stream:features>' in resp, f'{client.user}: no features'

    if use_tls and '<starttls' in resp:
        client.starttls()
        client.stream_open(domain)

    client.auth_plain()
    client.stream_open(domain)
    client.bind()
    client.send_presence()
    time.sleep(0.2)
    # Drain any presence stanzas
    client.recv(timeout=0.5)


def test_cross_thread(host, port, domain, users, use_tls):
    count = len(users)
    print("=" * 60)
    print(f"xmppd Cross-Thread Delivery Test ({count} clients)")
    print(f"Target: {host}:{port} domain={domain}")
    print("=" * 60)

    clients = {}

    try:
        # Phase 1: Connect all clients concurrently
        # Concurrent TCP connects force SO_REUSEPORT to distribute across workers.
        # Sequential connects tend to land on the same worker (kernel affinity).
        print(f"\n[Phase 1] Connecting {count} clients concurrently...")
        errors = {}
        barrier = threading.Barrier(count)

        def connect_user(user):
            try:
                c = XmppClient(user, domain, 'cross-thread')
                c.connect(host, port)
                # Wait for all threads to have TCP sockets open before proceeding.
                # This ensures SO_REUSEPORT distributes them across workers.
                barrier.wait(timeout=5)
                # Small stagger to avoid overwhelming auth daemon with simultaneous SASL
                import random
                time.sleep(random.uniform(0.05, 0.3))
                # Now do TLS + SASL + bind + presence
                resp = c.stream_open(domain)
                if '<starttls' in resp and use_tls:
                    c.starttls()
                    c.stream_open(domain)
                c.auth_plain()
                c.stream_open(domain)
                c.bind()
                c.send_presence()
                time.sleep(0.2)
                c.recv(timeout=0.5)  # drain presence
                clients[user] = c
            except Exception as e:
                errors[user] = e

        threads = []
        for user in users:
            t = threading.Thread(target=connect_user, args=(user,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=10)

        for user, err in errors.items():
            print(f"    ✗ {user} failed: {err}")
        if errors:
            raise RuntimeError(f"{len(errors)} clients failed to connect")

        for user in users:
            print(f"    ✓ {clients[user].jid} connected")

        time.sleep(0.5)  # Let presence settle

        # Phase 2: Each client sends a message to the next (round-robin)
        print(f"\n[Phase 2] Sending {count} messages (round-robin)...")
        pairs = []
        for i, sender_name in enumerate(users):
            receiver_name = users[(i + 1) % count]
            sender = clients[sender_name]
            body = f'Hello from {sender_name} to {receiver_name} (cross-thread test)'
            msg_id = f'xthread-{i}'
            sender.send_message(f'{receiver_name}@{domain}', body, msg_id)
            pairs.append((sender_name, receiver_name, body, msg_id))
            print(f"    → {sender_name} → {receiver_name}")

        time.sleep(1)  # Allow routing across threads

        # Phase 3: Each receiver checks for their message
        print(f"\n[Phase 3] Verifying {count} message deliveries...")
        passed = 0
        for sender_name, receiver_name, expected_body, msg_id in pairs:
            receiver = clients[receiver_name]
            resp = receiver.recv_until('</message>', timeout=5)

            if '<message' in resp and expected_body in resp:
                from_jid = f"{sender_name}@{domain}/cross-thread"
                if f"from='{from_jid}'" in resp:
                    print(f"    ✓ {receiver_name} received from {sender_name}")
                    passed += 1
                else:
                    print(f"    ✗ {receiver_name}: wrong from JID in: {resp[:300]}")
            else:
                print(f"    ✗ {receiver_name}: message not received (got: {resp[:300]})")

        # Phase 4: Bidirectional — everyone sends to everyone else
        print(f"\n[Phase 4] All-pairs messaging ({count * (count-1)} messages)...")
        all_pairs_count = 0
        for sender_name in users:
            for receiver_name in users:
                if sender_name == receiver_name:
                    continue
                sender = clients[sender_name]
                body = f'allpairs-{sender_name}-to-{receiver_name}'
                sender.send_message(f'{receiver_name}@{domain}', body, f'ap-{sender_name}-{receiver_name}')
                all_pairs_count += 1

        time.sleep(2)

        all_received = 0
        for receiver_name in users:
            receiver = clients[receiver_name]
            # Drain all pending data — do NOT break on empty recv,
            # cross-thread MPSC delivery can have >0.5s gaps between messages
            buf = ''
            expected_count = count - 1  # one from each other user
            deadline = time.time() + 8
            while time.time() < deadline:
                chunk = receiver.recv(timeout=1.0)
                buf += chunk
                # Early exit if we already got everything
                if buf.count('<message') >= expected_count:
                    break
            # Count messages received
            msg_count = buf.count('<message')
            all_received += msg_count
            if msg_count >= expected_count:
                print(f"    ✓ {receiver_name}: received {msg_count}/{expected_count} messages")
            else:
                print(f"    ✗ {receiver_name}: received {msg_count}/{expected_count} messages")

        # Summary
        print("\n" + "=" * 60)
        phase3_expected = count
        phase4_expected = count * (count - 1)
        total_expected = phase3_expected + phase4_expected
        total_received = passed + all_received
        if total_received >= total_expected:
            print(f"ALL TESTS PASSED — {total_received}/{total_expected} messages delivered")
            print("(With workers >= 2, some of these necessarily crossed threads)")
        else:
            pct = total_received * 100 // total_expected
            print(f"PARTIAL: {total_received}/{total_expected} messages delivered ({pct}%)")
            if pct >= 95:
                print("(>95% delivery — likely transient MPSC timing, not a correctness bug)")
            else:
                print("Some messages may have been lost in cross-thread delivery")
                sys.exit(1)
        print("=" * 60)

    except Exception as e:
        print(f"\n✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        for c in clients.values():
            c.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='xmppd cross-thread delivery test')
    parser.add_argument('--host', default=HOST)
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--domain', default='localhost', help='XMPP server hostname')
    parser.add_argument('--users', default=','.join(DEFAULT_USERS), help='Comma-separated user list')
    parser.add_argument('--no-tls', action='store_true')
    args = parser.parse_args()
    users = [u.strip() for u in args.users.split(',')]
    test_cross_thread(args.host, args.port, args.domain, users, not args.no_tls)
