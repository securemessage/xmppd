#!/usr/bin/env python3
"""End-to-end test for T71/T78/T44/T45 quick wins against the xmppd jail.

Tests:
  1. disco#info — verify chatstates, receipts, message-correct features
  2. MUC join + groupchat message + second user join — verify history replay
  3. Chat state notification forwarding (XEP-0085)

Prerequisites:
    - xmppd running in the xmppd jail (morante.dev)
    - Users: alice, bob (password: test1234)
    - MUC host: conference.morante.dev
"""

import asyncio
import logging
import ssl
import sys
import uuid

import slixmpp
from slixmpp.exceptions import IqError, IqTimeout

HOST = '127.0.0.1'
PORT = 5222
DOMAIN = 'morante.dev'
MUC_SERVICE = 'conference.morante.dev'

ALICE_JID = 'alice@morante.dev'
ALICE_PASS = 'test1234'
BOB_JID = 'bob@morante.dev'
BOB_PASS = 'test1234'

TIMEOUT = 10
results = []

def record(name, passed, detail=''):
    status = '✓' if passed else '✗'
    results.append((name, passed, detail))
    msg = f"  {status} {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)

def make_client(jid, password):
    client = slixmpp.ClientXMPP(jid, password)
    client.register_plugin('xep_0030')  # disco
    client.register_plugin('xep_0045')  # MUC
    client.register_plugin('xep_0085')  # chat states
    client.register_plugin('xep_0199')  # ping
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client.ssl_context = ctx
    return client


async def test_disco_features():
    """Test 1: disco#info features include our new XEPs."""
    print("\n--- Test 1: disco#info features ---")
    client = make_client(ALICE_JID, ALICE_PASS)
    connected = asyncio.Event()
    client.add_event_handler('session_start', lambda _: connected.set())
    client.connect((HOST, PORT))

    try:
        await asyncio.wait_for(connected.wait(), timeout=TIMEOUT)
        client.send_presence()
        await asyncio.sleep(0.5)

        info = await asyncio.wait_for(
            client['xep_0030'].get_info(jid=DOMAIN), timeout=5)
        features = info['disco_info']['features']

        expected = [
            ('http://jabber.org/protocol/chatstates', 'XEP-0085 Chat States'),
            ('urn:xmpp:receipts', 'XEP-0184 Delivery Receipts'),
            ('urn:xmpp:message-correct:0', 'XEP-0308 Message Correction'),
            ('urn:xmpp:mam:2', 'XEP-0313 MAM'),
        ]
        for feat_var, label in expected:
            present = feat_var in features
            record(f'disco#info — {label}', present,
                   feat_var if present else f'MISSING: {feat_var}')

    except Exception as e:
        record('disco#info', False, str(e))
    finally:
        client.disconnect()
        await asyncio.sleep(0.3)


async def test_muc_history():
    """Test 2: MUC room history replay on join.

    Flow:
      1. Alice creates room, sends 3 messages
      2. Alice leaves
      3. Bob joins — should receive 3 history messages with <delay/> stamps
    """
    print("\n--- Test 2: MUC room history replay ---")
    room_name = f"histtest-{uuid.uuid4().hex[:8]}"
    room_jid = f"{room_name}@{MUC_SERVICE}"

    # --- Alice creates room and sends messages ---
    alice = make_client(ALICE_JID, ALICE_PASS)
    alice_connected = asyncio.Event()
    alice.add_event_handler('session_start', lambda _: alice_connected.set())
    alice.connect((HOST, PORT))

    try:
        await asyncio.wait_for(alice_connected.wait(), timeout=TIMEOUT)
        alice.send_presence()
        await asyncio.sleep(0.5)

        # Join room
        await alice['xep_0045'].join_muc(room_jid, 'Alice')
        await asyncio.sleep(1)
        record('Alice created room', True, room_jid)

        # Send 3 messages
        test_messages = ['Hello room!', 'Message two', 'Message three']
        for msg_text in test_messages:
            alice.send_message(mto=room_jid, mbody=msg_text, mtype='groupchat')
            await asyncio.sleep(0.3)
        record('Alice sent 3 groupchat messages', True)

        # Leave room
        alice['xep_0045'].leave_muc(room_jid, 'Alice')
        await asyncio.sleep(0.5)

    except Exception as e:
        record('Alice phase', False, str(e))
    finally:
        alice.disconnect()
        await asyncio.sleep(0.3)

    # --- Bob joins and checks for history ---
    bob = make_client(BOB_JID, BOB_PASS)
    bob_connected = asyncio.Event()
    bob.add_event_handler('session_start', lambda _: bob_connected.set())

    history_messages = []

    def on_groupchat(msg):
        # History messages have <delay/> element
        delay = msg.xml.find('{urn:xmpp:delay}delay')
        body = msg['body']
        if body:
            history_messages.append({
                'body': body,
                'has_delay': delay is not None,
                'from': str(msg['from']),
                'stamp': delay.get('stamp') if delay is not None else None,
            })

    bob.add_event_handler('groupchat_message', on_groupchat)
    bob.connect((HOST, PORT))

    try:
        await asyncio.wait_for(bob_connected.wait(), timeout=TIMEOUT)
        bob.send_presence()
        await asyncio.sleep(0.5)

        # Join room — should trigger history replay
        await bob['xep_0045'].join_muc(room_jid, 'Bob')
        await asyncio.sleep(2)  # Give time for history delivery

        # Check results
        history_with_delay = [m for m in history_messages if m['has_delay']]
        record(f'Bob received history messages',
               len(history_with_delay) >= 3,
               f'{len(history_with_delay)} messages with delay stamps')

        if len(history_with_delay) >= 3:
            bodies = [m['body'] for m in history_with_delay]
            for expected_body in test_messages:
                found = expected_body in bodies
                record(f'  History contains "{expected_body}"', found)

            # Verify delay stamps are present and well-formed
            for m in history_with_delay:
                has_stamp = m['stamp'] is not None and 'T' in m['stamp']
                record(f'  Delay stamp format', has_stamp,
                       m['stamp'] if has_stamp else 'missing/malformed')
                break  # Just check one

        # Leave
        bob['xep_0045'].leave_muc(room_jid, 'Bob')
        await asyncio.sleep(0.3)

    except Exception as e:
        record('Bob phase', False, str(e))
    finally:
        bob.disconnect()
        await asyncio.sleep(0.3)


async def test_chat_state_forwarding():
    """Test 3: Chat state notifications forwarded between users (XEP-0085)."""
    print("\n--- Test 3: Chat state forwarding (XEP-0085) ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    alice_connected = asyncio.Event()
    bob_connected = asyncio.Event()
    alice.add_event_handler('session_start', lambda _: alice_connected.set())
    bob.add_event_handler('session_start', lambda _: bob_connected.set())

    received_states = []

    def on_chatstate(msg):
        for state in ['active', 'composing', 'paused', 'inactive', 'gone']:
            if msg.xml.find(f'{{http://jabber.org/protocol/chatstates}}{state}') is not None:
                received_states.append(state)

    bob.add_event_handler('message', on_chatstate)

    alice.connect((HOST, PORT))
    bob.connect((HOST, PORT))

    try:
        await asyncio.wait_for(alice_connected.wait(), timeout=TIMEOUT)
        await asyncio.wait_for(bob_connected.wait(), timeout=TIMEOUT)
        alice.send_presence()
        bob.send_presence()
        await asyncio.sleep(0.5)

        # Alice sends message with <active/> chat state to Bob
        msg = alice.make_message(mto=BOB_JID, mbody='Hello Bob!', mtype='chat')
        active_el = slixmpp.xmlstream.ET.SubElement(
            msg.xml, '{http://jabber.org/protocol/chatstates}active')
        msg.send()
        await asyncio.sleep(1)

        # Check if Bob got the chat state
        has_active = 'active' in received_states
        record('Chat state forwarded (active)', has_active,
               f'received states: {received_states}' if received_states else 'no states received')

    except Exception as e:
        record('Chat state test', False, str(e))
    finally:
        alice.disconnect()
        bob.disconnect()
        await asyncio.sleep(0.3)


async def main():
    print("=" * 60)
    print("xmppd E2E Quick Wins Test (T71/T78/T44/T45)")
    print(f"Target: {DOMAIN} ({HOST}:{PORT})")
    print("=" * 60)

    await test_disco_features()
    await test_muc_history()
    await test_chat_state_forwarding()

    # Summary
    print("\n" + "=" * 60)
    passed = sum(1 for _, p, _ in results if p)
    failed = sum(1 for _, p, _ in results if not p)
    print(f"Results: {passed} passed, {failed} failed, {len(results)} total")
    if failed > 0:
        print("\nFailed tests:")
        for name, p, detail in results:
            if not p:
                print(f"  ✗ {name} — {detail}")
    print("=" * 60)
    sys.exit(1 if failed > 0 else 0)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())
