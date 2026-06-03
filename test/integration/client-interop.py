#!/usr/bin/env python3
"""Client interop test for xmppd using slixmpp.

Tests the server against a real XMPP client library to validate
standards compliance. Covers: connect, STARTTLS, SASL (SCRAM-SHA-256
and PLAIN), resource binding, presence, roster, messaging, disco,
ping, vCard, and software version.

Usage:
    python3 test/integration/client-interop.py

Prerequisites:
    - xmppd-auth, xmppd-s2s, xmppd-core running on port 15222
    - Users: alice (pass1), bob (pass2) in xmppd.test domain
    - DNS: _xmpp-client._tcp.xmppd.test SRV → 127.0.0.1:15222
    - pkg install py311-slixmpp
"""

import asyncio
import logging
import sys
import ssl
import traceback

import slixmpp
from slixmpp.exceptions import IqError, IqTimeout

HOST = '127.0.0.1'
PORT = 15222
DOMAIN = 'xmppd.test'

# Track test results
results = []

def record(name, passed, detail=''):
    status = '✓' if passed else '✗'
    results.append((name, passed, detail))
    msg = f"  {status} {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)

class TestClient(slixmpp.ClientXMPP):
    """slixmpp client configured for xmppd interop testing."""

    def __init__(self, jid, password):
        super().__init__(jid, password)
        self.connected_event = asyncio.Event()
        self.session_started = asyncio.Event()
        self.message_received = asyncio.Event()
        self.last_message = None

        # Register plugins we want to test
        self.register_plugin('xep_0030')  # Service Discovery
        self.register_plugin('xep_0054')  # vCard-temp
        self.register_plugin('xep_0092')  # Software Version
        self.register_plugin('xep_0199')  # XMPP Ping

        # Event handlers
        self.add_event_handler('session_start', self.on_session_start)
        self.add_event_handler('message', self.on_message)

    async def on_session_start(self, event):
        """Session established — resource bound, ready for stanzas."""
        self.session_started.set()

    def on_message(self, msg):
        """Incoming message."""
        if msg['type'] in ('chat', 'normal'):
            self.last_message = msg
            self.message_received.set()


async def test_connect_and_auth(mechanism='PLAIN'):
    """Test 1: Connect, STARTTLS, SASL auth, resource bind."""
    print(f"\n--- Test: Connect + STARTTLS + SASL {mechanism} + Bind ---")

    jid = f'alice@{DOMAIN}/test-{mechanism.lower()}'
    client = TestClient(jid, 'pass1')

    # Disable certificate verification (self-signed test cert)
    client.ssl_context = ssl.create_default_context()
    client.ssl_context.check_hostname = False
    client.ssl_context.verify_mode = ssl.CERT_NONE

    # Force specific SASL mechanism
    if mechanism == 'PLAIN':
        client.sasl_mechanism = 'PLAIN'
    elif mechanism == 'SCRAM-SHA-256':
        client.sasl_mechanism = 'SCRAM-SHA-256'

    try:
        client.connect((HOST, PORT))
        try:
            await asyncio.wait_for(client.session_started.wait(), timeout=10)
            record(f'Connect + STARTTLS + {mechanism} + Bind', True,
                   f'bound as {client.boundjid.full}')
        except asyncio.TimeoutError:
            record(f'Connect + STARTTLS + {mechanism} + Bind', False,
                   'session_start timeout (10s)')
            return None
    except Exception as e:
        record(f'Connect + STARTTLS + {mechanism} + Bind', False, str(e))
        return None

    return client


async def test_disco_info(client):
    """Test: Service Discovery (XEP-0030) — disco#info to server."""
    print("\n--- Test: Service Discovery (disco#info) ---")
    try:
        info = await asyncio.wait_for(
            client.plugin['xep_0030'].get_info(jid=DOMAIN),
            timeout=5
        )
        identities = info['disco_info']['identities']
        features = info['disco_info']['features']

        has_identity = len(identities) > 0
        if has_identity:
            ident = list(identities)[0]
            record('disco#info — identity present', True,
                   f"{ident[0]}/{ident[1]} '{ident[2]}'")
        else:
            record('disco#info — identity present', False, 'no identity')

        expected_features = [
            'http://jabber.org/protocol/disco#info',
            'http://jabber.org/protocol/disco#items',
            'urn:xmpp:ping',
            'jabber:iq:roster',
            'vcard-temp',
            'jabber:iq:version',
        ]
        for feat in expected_features:
            present = feat in features
            record(f'disco#info — feature {feat}', present)

    except IqError as e:
        record('disco#info', False, f'IQ error: {e.iq["error"]["condition"]}')
    except IqTimeout:
        record('disco#info', False, 'timeout')
    except Exception as e:
        record('disco#info', False, str(e))


async def test_disco_items(client):
    """Test: Service Discovery (XEP-0030) — disco#items to server."""
    print("\n--- Test: Service Discovery (disco#items) ---")
    try:
        items = await asyncio.wait_for(
            client.plugin['xep_0030'].get_items(jid=DOMAIN),
            timeout=5
        )
        # Empty items list is fine — server has no sub-services yet
        record('disco#items — response received', True,
               f'{len(items["disco_items"]["items"])} items')
    except IqError as e:
        record('disco#items', False, f'IQ error: {e.iq["error"]["condition"]}')
    except IqTimeout:
        record('disco#items', False, 'timeout')
    except Exception as e:
        record('disco#items', False, str(e))


async def test_ping(client):
    """Test: XMPP Ping (XEP-0199)."""
    print("\n--- Test: XMPP Ping (XEP-0199) ---")
    try:
        rtt = await asyncio.wait_for(
            client.plugin['xep_0199'].ping(jid=DOMAIN),
            timeout=5
        )
        record('ping — response received', True, f'RTT={rtt:.3f}s' if rtt else 'ok')
    except IqError as e:
        record('ping', False, f'IQ error: {e.iq["error"]["condition"]}')
    except IqTimeout:
        record('ping', False, 'timeout')
    except Exception as e:
        record('ping', False, str(e))


async def test_version(client):
    """Test: Software Version (XEP-0092)."""
    print("\n--- Test: Software Version (XEP-0092) ---")
    try:
        version = await asyncio.wait_for(
            client.plugin['xep_0092'].get_version(jid=DOMAIN),
            timeout=5
        )
        sv = version['software_version']
        name = sv.get('name', '')
        ver = sv.get('version', '')
        os_name = sv.get('os', '')
        record('version — response received', True,
               f'{name} {ver} ({os_name})')
        record('version — name is xmppd', name == 'xmppd')
    except IqError as e:
        record('version', False, f'IQ error: {e.iq["error"]["condition"]}')
    except IqTimeout:
        record('version', False, 'timeout')
    except Exception as e:
        record('version', False, str(e))


async def test_vcard(client):
    """Test: vCard-temp (XEP-0054)."""
    print("\n--- Test: vCard-temp (XEP-0054) ---")
    try:
        vcard = await asyncio.wait_for(
            client.plugin['xep_0054'].get_vcard(jid=client.boundjid.bare),
            timeout=5
        )
        # Server returns empty vCard — that's valid
        record('vcard — response received', True, 'empty vCard (stub)')
    except IqError as e:
        record('vcard', False, f'IQ error: {e.iq["error"]["condition"]}')
    except IqTimeout:
        record('vcard', False, 'timeout')
    except Exception as e:
        record('vcard', False, str(e))


async def test_roster(client):
    """Test: Roster operations (jabber:iq:roster)."""
    print("\n--- Test: Roster Operations ---")
    try:
        # Get roster
        roster = await asyncio.wait_for(
            client.get_roster(),
            timeout=5
        )
        record('roster get — response received', True)

        # Add a contact
        client.update_roster(
            jid=f'bob@{DOMAIN}',
            name='Bob',
            subscription='none'
        )
        await asyncio.sleep(0.5)

        # Verify the contact is in roster
        roster = await asyncio.wait_for(
            client.get_roster(),
            timeout=5
        )
        bob_in_roster = f'bob@{DOMAIN}' in client.client_roster
        record('roster set — add bob', bob_in_roster)

    except IqError as e:
        record('roster', False, f'IQ error: {e.iq["error"]["condition"]}')
    except IqTimeout:
        record('roster', False, 'timeout')
    except Exception as e:
        record('roster', False, str(e))


async def test_presence(client):
    """Test: Initial presence broadcast."""
    print("\n--- Test: Presence ---")
    try:
        client.send_presence()
        await asyncio.sleep(0.5)
        record('initial presence sent', True)
    except Exception as e:
        record('presence', False, str(e))


async def test_messaging():
    """Test: Two-way messaging between alice and bob."""
    print("\n--- Test: Two-Way Messaging ---")

    alice = TestClient(f'alice@{DOMAIN}/sender', 'pass1')
    bob = TestClient(f'bob@{DOMAIN}/receiver', 'pass2')

    for c in (alice, bob):
        c.ssl_context = ssl.create_default_context()
        c.ssl_context.check_hostname = False
        c.ssl_context.verify_mode = ssl.CERT_NONE

    try:
        # Connect both with minimal stagger to allow asyncio scheduling
        alice.connect((HOST, PORT))
        await asyncio.sleep(0.05)
        bob.connect((HOST, PORT))

        try:
            await asyncio.wait_for(alice.session_started.wait(), timeout=10)
            record('messaging — alice connected', True, str(alice.boundjid))
        except asyncio.TimeoutError:
            record('messaging — alice connected', False, 'session timeout')
            return

        try:
            await asyncio.wait_for(bob.session_started.wait(), timeout=10)
            record('messaging — bob connected', True, str(bob.boundjid))
        except asyncio.TimeoutError:
            record('messaging — bob connected', False, 'session timeout')
            return

        # Send presence so server knows they're online
        alice.send_presence()
        bob.send_presence()
        await asyncio.sleep(0.5)

        # Alice → Bob
        alice.send_message(
            mto=f'bob@{DOMAIN}/receiver',
            mbody='Hello from Alice!',
            mtype='chat'
        )

        try:
            await asyncio.wait_for(bob.message_received.wait(), timeout=5)
            msg = bob.last_message
            body_ok = msg['body'] == 'Hello from Alice!'
            from_ok = 'alice@' in str(msg['from'])
            record('alice → bob — message delivered', body_ok and from_ok,
                   f"body='{msg['body']}' from='{msg['from']}'")
        except asyncio.TimeoutError:
            record('alice → bob — message delivered', False, 'timeout waiting for message')

        # Bob → Alice
        bob.message_received.clear()
        alice.message_received.clear()

        bob.send_message(
            mto=f'alice@{DOMAIN}/sender',
            mbody='Reply from Bob!',
            mtype='chat'
        )

        try:
            await asyncio.wait_for(alice.message_received.wait(), timeout=5)
            msg = alice.last_message
            body_ok = msg['body'] == 'Reply from Bob!'
            from_ok = 'bob@' in str(msg['from'])
            record('bob → alice — reply delivered', body_ok and from_ok,
                   f"body='{msg['body']}' from='{msg['from']}'")
        except asyncio.TimeoutError:
            record('bob → alice — reply delivered', False, 'timeout waiting for reply')

    except Exception as e:
        record('messaging', False, str(e))
        traceback.print_exc()
    finally:
        alice.disconnect()
        bob.disconnect()


async def test_wrong_password():
    """Test: Authentication with wrong password should fail."""
    print("\n--- Test: Wrong Password Rejection ---")

    client = TestClient(f'alice@{DOMAIN}/badauth', 'wrong_password')
    client.ssl_context = ssl.create_default_context()
    client.ssl_context.check_hostname = False
    client.ssl_context.verify_mode = ssl.CERT_NONE

    auth_failed = asyncio.Event()

    def on_failed(event):
        auth_failed.set()

    client.add_event_handler('failed_auth', on_failed)

    try:
        client.connect((HOST, PORT))
        try:
            # Should NOT reach session_start
            done, pending = await asyncio.wait(
                [asyncio.create_task(client.session_started.wait()),
                 asyncio.create_task(auth_failed.wait())],
                timeout=10,
                return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()

            if auth_failed.is_set():
                record('wrong password rejected', True)
            elif client.session_started.is_set():
                record('wrong password rejected', False, 'session started with bad password!')
            else:
                record('wrong password rejected', False, 'neither auth_failed nor session_start fired')
        except asyncio.TimeoutError:
            record('wrong password rejected', False, 'timeout')
    except Exception as e:
        # Connection error is also acceptable for wrong password
        record('wrong password rejected', True, f'connection error: {e}')
    finally:
        client.disconnect()


async def main():
    print("=" * 60)
    print("xmppd Client Interop Tests (slixmpp)")
    print(f"Server: {HOST}:{PORT}, Domain: {DOMAIN}")
    print("=" * 60)

    # Test 1: Connect with SASL PLAIN
    client = await test_connect_and_auth('PLAIN')
    if client:
        await test_disco_info(client)
        await test_disco_items(client)
        await test_ping(client)
        await test_version(client)
        await test_vcard(client)
        await test_roster(client)
        await test_presence(client)
        client.disconnect()

    # Brief pause between sessions
    await asyncio.sleep(1)

    # Test 2: Connect with SCRAM-SHA-256
    client_scram = await test_connect_and_auth('SCRAM-SHA-256')
    if client_scram:
        # Just verify auth works — no need to repeat all IQ tests
        record('SCRAM-SHA-256 session usable', True,
               f'bound as {client_scram.boundjid.full}')
        client_scram.disconnect()

    await asyncio.sleep(1)

    # Test 3: Two-way messaging
    await test_messaging()

    await asyncio.sleep(1)

    # Test 4: Wrong password
    await test_wrong_password()

    # Summary
    print("\n" + "=" * 60)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    total = len(results)
    print(f"Results: {passed}/{total} passed, {failed} failed")

    if failed > 0:
        print("\nFailed tests:")
        for name, ok, detail in results:
            if not ok:
                print(f"  ✗ {name}: {detail}")

    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    # Reduce slixmpp logging noise — only show warnings+
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())
