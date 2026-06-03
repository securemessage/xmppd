#!/usr/bin/env python3
"""S2S federation test — bidirectional message delivery via xmppd ↔ Prosody.

Tests that messages flow in both directions across a federated S2S connection
using DANE-EE + SASL EXTERNAL authentication.

Usage:
    # First restore DNS and start daemons (see README or resume prompt)
    python3 test/integration/s2s-federation.py

Prerequisites:
    - xmppd-auth, xmppd-s2s, xmppd-core running (ports 15222/15269)
    - Prosody running in prosody-test jail (ports 25222/25269)
    - Users: alice@xmppd.test (pass1), alice@prosody.test (pass123)
    - DNS: SRV + DANE TLSA records for both domains (s2s-test.conf)
    - xmppd.test A record must be 127.0.0.1 (not 192.168.1.233)
    - pkg install py311-slixmpp
"""

import asyncio
import logging
import ssl
import sys
import uuid

import slixmpp

# Configuration
XMPPD_HOST = '127.0.0.1'
XMPPD_C2S_PORT = 15222
PROSODY_HOST = '127.0.0.1'
PROSODY_C2S_PORT = 25222

XMPPD_USER = 'alice@xmppd.test'
XMPPD_PASS = 'pass1'
PROSODY_USER = 'alice@prosody.test'
PROSODY_PASS = 'pass123'

TIMEOUT = 30  # seconds for message delivery

results = []

def record(name, passed, detail=''):
    status = '✓' if passed else '✗'
    results.append((name, passed, detail))
    msg = f"  {status} {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)


class FederationClient(slixmpp.ClientXMPP):
    """slixmpp client for federation testing."""

    def __init__(self, jid, password):
        super().__init__(jid, password)
        self.session_ready = asyncio.Event()
        self.received_messages = []
        self.message_event = asyncio.Event()

        self.add_event_handler('session_start', self.on_session_start)
        self.add_event_handler('message', self.on_message)

    async def on_session_start(self, event):
        await self.get_roster()
        self.send_presence()
        self.session_ready.set()

    def on_message(self, msg):
        if msg['type'] in ('chat', 'normal'):
            self.received_messages.append(msg)
            self.message_event.set()

    async def wait_for_message(self, expected_body=None, timeout=TIMEOUT):
        """Wait for a message to arrive with optional body matching.
        
        If expected_body is given, waits until a message with that exact body
        arrives (skipping stale/queued messages from prior sessions).
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                return None
            self.message_event.clear()
            # Check already-received messages first
            if expected_body:
                for msg in self.received_messages:
                    if msg['body'] == expected_body:
                        return msg
            try:
                await asyncio.wait_for(self.message_event.wait(), timeout=remaining)
                if expected_body:
                    for msg in self.received_messages:
                        if msg['body'] == expected_body:
                            return msg
                    continue  # Keep waiting for the right message
                return self.received_messages[-1] if self.received_messages else None
            except asyncio.TimeoutError:
                return None


async def connect_client(jid, password, host, port, label):
    """Connect and authenticate a client, return it ready for stanzas."""
    client = FederationClient(jid, password)

    # Accept self-signed certs
    client.ssl_context = ssl.create_default_context()
    client.ssl_context.check_hostname = False
    client.ssl_context.verify_mode = ssl.CERT_NONE

    client.connect((host, port))

    try:
        await asyncio.wait_for(client.session_ready.wait(), timeout=15)
        record(f'{label} connect + auth', True, f'{client.boundjid.full}')
    except asyncio.TimeoutError:
        record(f'{label} connect + auth', False, 'session_start timeout')
        return None

    return client


async def test_xmppd_to_prosody():
    """Test: xmppd user sends message to Prosody user."""
    print("\n--- Test: xmppd → Prosody message delivery ---")

    xmppd_client = await connect_client(
        XMPPD_USER, XMPPD_PASS, XMPPD_HOST, XMPPD_C2S_PORT, 'xmppd')
    prosody_client = await connect_client(
        PROSODY_USER, PROSODY_PASS, PROSODY_HOST, PROSODY_C2S_PORT, 'Prosody')

    if not xmppd_client or not prosody_client:
        record('xmppd→Prosody delivery', False, 'client setup failed')
        return

    try:
        # Send message from xmppd to Prosody
        test_body = f'Hello from xmppd! [{uuid.uuid4().hex[:8]}]'
        xmppd_client.send_message(
            mto=PROSODY_USER,
            mbody=test_body,
            mtype='chat'
        )

        # Wait for delivery on Prosody side (skip stale offline messages)
        msg = await prosody_client.wait_for_message(expected_body=test_body, timeout=TIMEOUT)
        if msg and msg['body'] == test_body:
            record('xmppd→Prosody delivery', True,
                   f'from={msg["from"]}, body matches')
        elif msg:
            record('xmppd→Prosody delivery', False,
                   f'body mismatch: got "{msg["body"]}"')
        else:
            record('xmppd→Prosody delivery', False, 'timeout waiting for message')
    finally:
        xmppd_client.disconnect()
        prosody_client.disconnect()
        await asyncio.sleep(0.5)


async def test_prosody_to_xmppd():
    """Test: Prosody user sends message to xmppd user."""
    print("\n--- Test: Prosody → xmppd message delivery ---")

    xmppd_client = await connect_client(
        XMPPD_USER, XMPPD_PASS, XMPPD_HOST, XMPPD_C2S_PORT, 'xmppd')
    prosody_client = await connect_client(
        PROSODY_USER, PROSODY_PASS, PROSODY_HOST, PROSODY_C2S_PORT, 'Prosody')

    if not xmppd_client or not prosody_client:
        record('Prosody→xmppd delivery', False, 'client setup failed')
        return

    try:
        # Send message from Prosody to xmppd
        test_body = f'Hello from Prosody! [{uuid.uuid4().hex[:8]}]'
        prosody_client.send_message(
            mto=XMPPD_USER,
            mbody=test_body,
            mtype='chat'
        )

        # Wait for delivery on xmppd side (skip stale offline messages)
        msg = await xmppd_client.wait_for_message(expected_body=test_body, timeout=TIMEOUT)
        if msg and msg['body'] == test_body:
            record('Prosody→xmppd delivery', True,
                   f'from={msg["from"]}, body matches')
        elif msg:
            record('Prosody→xmppd delivery', False,
                   f'body mismatch: got "{msg["body"]}"')
        else:
            record('Prosody→xmppd delivery', False, 'timeout waiting for message')
    finally:
        xmppd_client.disconnect()
        prosody_client.disconnect()
        await asyncio.sleep(0.5)


async def test_offline_delivery():
    """Test: message sent while xmppd user is offline, delivered on connect."""
    print("\n--- Test: Offline delivery (Prosody → offline xmppd user) ---")

    # First connect Prosody client
    prosody_client = await connect_client(
        PROSODY_USER, PROSODY_PASS, PROSODY_HOST, PROSODY_C2S_PORT, 'Prosody')

    if not prosody_client:
        record('Offline delivery', False, 'Prosody client setup failed')
        return

    try:
        # Send message to xmppd user who is NOT connected
        test_body = f'Offline message [{uuid.uuid4().hex[:8]}]'
        prosody_client.send_message(
            mto=XMPPD_USER,
            mbody=test_body,
            mtype='chat'
        )

        # Wait for S2S delivery to complete (xmppd stores it offline)
        await asyncio.sleep(5)

        # Now connect the xmppd user — should receive the offline message
        xmppd_client = await connect_client(
            XMPPD_USER, XMPPD_PASS, XMPPD_HOST, XMPPD_C2S_PORT, 'xmppd')

        if not xmppd_client:
            record('Offline delivery', False, 'xmppd client setup failed')
            return

        try:
            msg = await xmppd_client.wait_for_message(expected_body=test_body, timeout=15)
            if msg and msg['body'] == test_body:
                record('Offline delivery', True,
                       f'message delivered on connect, body matches')
            elif msg:
                record('Offline delivery', False,
                       f'body mismatch: got "{msg["body"]}"')
            else:
                record('Offline delivery', False,
                       'no offline message received on connect')
        finally:
            xmppd_client.disconnect()
    finally:
        prosody_client.disconnect()
        await asyncio.sleep(0.5)


async def main():
    print("=" * 60)
    print("S2S Federation Test — xmppd ↔ Prosody")
    print("=" * 60)

    await test_xmppd_to_prosody()
    await test_prosody_to_xmppd()
    await test_offline_delivery()

    # Summary
    print("\n" + "=" * 60)
    passed = sum(1 for _, p, _ in results if p)
    total = len(results)
    print(f"Results: {passed}/{total} passed")

    if passed < total:
        print("\nFailed:")
        for name, p, detail in results:
            if not p:
                print(f"  ✗ {name}: {detail}")
        sys.exit(1)
    else:
        print("All tests passed!")
        sys.exit(0)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    # Enable S2S debug logging for troubleshooting
    # logging.getLogger('slixmpp').setLevel(logging.DEBUG)
    asyncio.run(main())
