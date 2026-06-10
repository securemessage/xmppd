#!/usr/bin/env python3
"""End-to-end test for MAM features (T81/T82/T83) against the xmppd jail.

Tests:
  1. disco#info — urn:xmpp:sid:0 advertised
  2. Send message, query MAM — verify message appears in recipient's archive
  3. Sender's archive — verify sender's own copy is stored
  4. stanza-id injection — delivered message contains <stanza-id> element
  5. MUC MAM — query room archive after groupchat messages
  6. Room disco#info — urn:xmpp:mam:2 advertised on room JID

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
from slixmpp.xmlstream import ET

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
    client.register_plugin('xep_0199')  # ping
    # NOT registering xep_0313 — we handle MAM results manually via raw handlers
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client.ssl_context = ctx
    return client


async def connect_client(client):
    connected = asyncio.Event()
    client.add_event_handler('session_start', lambda _: connected.set())
    client.connect((HOST, PORT))
    await asyncio.wait_for(connected.wait(), timeout=TIMEOUT)
    client.send_presence()
    await asyncio.sleep(0.5)


async def test_disco_stanza_id():
    """Test 1: disco#info includes urn:xmpp:sid:0."""
    print("\n--- Test 1: disco#info — urn:xmpp:sid:0 ---")
    client = make_client(ALICE_JID, ALICE_PASS)
    try:
        await connect_client(client)
        info = await asyncio.wait_for(
            client['xep_0030'].get_info(jid=DOMAIN), timeout=5)
        features = info['disco_info']['features']
        present = 'urn:xmpp:sid:0' in features
        record('disco#info — urn:xmpp:sid:0', present,
               'urn:xmpp:sid:0' if present else 'MISSING')
    except Exception as e:
        record('disco#info — urn:xmpp:sid:0', False, str(e))
    finally:
        client.disconnect()


async def test_mam_online_delivery():
    """Test 2+3+4: Send message between online users, verify MAM + stanza-id."""
    print("\n--- Test 2: MAM archive for online delivery ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    received_messages = []
    test_body = f"MAM test {uuid.uuid4().hex[:8]}"

    def bob_message_handler(msg):
        if msg['type'] == 'chat' and msg['body']:
            received_messages.append(msg)

    bob.add_event_handler('message', bob_message_handler)

    try:
        await connect_client(alice)
        await connect_client(bob)

        # Alice sends a message to Bob
        alice.send_message(mto=BOB_JID, mbody=test_body, mtype='chat')
        await asyncio.sleep(1)

        # Verify Bob received it
        record('Bob received message', len(received_messages) > 0,
               f'{len(received_messages)} messages received')

        # Check for stanza-id in delivered message (T82)
        stanza_id_found = False
        stanza_id_value = ''
        if received_messages:
            msg_xml = ET.tostring(received_messages[0].xml, encoding='unicode')
            if 'stanza-id' in msg_xml and 'urn:xmpp:sid:0' in msg_xml:
                stanza_id_found = True
                for elem in received_messages[0].xml.iter():
                    if 'stanza-id' in elem.tag:
                        stanza_id_value = elem.get('id', '')
                        break
            if not stanza_id_found:
                print(f"    DEBUG: {msg_xml[:300]}")

        record('stanza-id injected (XEP-0359)', stanza_id_found,
               f"id='{stanza_id_value}'" if stanza_id_found else 'NOT FOUND in delivered stanza')

        # Query Bob's MAM archive (T81 — recipient copy)
        print("\n--- Test 3: Recipient MAM archive ---")
        try:
            # Send raw MAM query IQ (avoid slixmpp plugin interference)
            mam_id = f'mam-{uuid.uuid4().hex[:8]}'
            raw_mam = (
                f"<iq type='set' id='{mam_id}'>"
                f"<query xmlns='urn:xmpp:mam:2'>"
                f"<x xmlns='jabber:x:data' type='submit'>"
                f"<field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field>"
                f"<field var='with'><value>{ALICE_JID}</value></field>"
                f"</x></query></iq>"
            )

            # Collect ALL incoming stanzas (messages + IQs) via raw handler
            mam_results = []
            iq_responses = []

            def raw_stanza_handler(stanza):
                tag = stanza.xml.tag
                if 'message' in tag:
                    if stanza.xml.find('.//{urn:xmpp:mam:2}result') is not None:
                        mam_results.append(stanza)
                elif 'iq' in tag:
                    iq_responses.append(stanza)

            bob.register_handler(slixmpp.Callback(
                'MAM Catch All', slixmpp.MatchXPath('{jabber:client}message'),
                raw_stanza_handler, stream=None))
            bob.send_raw(raw_mam)
            await asyncio.sleep(2)

            # Check if our test message is in the archive
            found_in_archive = False
            for result_msg in mam_results:
                if test_body in str(result_msg):
                    found_in_archive = True
                    break

            record('Message in recipient MAM archive', found_in_archive,
                   f'{len(mam_results)} MAM results' + (' — test body found' if found_in_archive else ' — test body NOT found'))

        except Exception as e:
            record('Recipient MAM archive query', False, str(e))

        # Query Alice's MAM archive (T81 — sender copy)
        print("\n--- Test 4: Sender MAM archive ---")
        try:
            mam_id2 = f'mam-{uuid.uuid4().hex[:8]}'
            raw_mam2 = (
                f"<iq type='set' id='{mam_id2}'>"
                f"<query xmlns='urn:xmpp:mam:2'>"
                f"<x xmlns='jabber:x:data' type='submit'>"
                f"<field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field>"
                f"<field var='with'><value>{BOB_JID}</value></field>"
                f"</x></query></iq>"
            )

            mam_results2 = []

            def mam_result_handler2(stanza):
                if 'message' in stanza.xml.tag:
                    if stanza.xml.find('.//{urn:xmpp:mam:2}result') is not None:
                        mam_results2.append(stanza)

            alice.register_handler(slixmpp.Callback(
                'MAM Sender', slixmpp.MatchXPath('{jabber:client}message'),
                mam_result_handler2, stream=None))
            alice.send_raw(raw_mam2)
            await asyncio.sleep(2)

            found_sender_copy = False
            for result_msg in mam_results2:
                if test_body in str(result_msg):
                    found_sender_copy = True
                    break

            record('Message in sender MAM archive', found_sender_copy,
                   f'{len(mam_results2)} MAM results' + (' — sender copy found' if found_sender_copy else ' — sender copy NOT found'))

        except Exception as e:
            record('Sender MAM archive query', False, str(e))

    except Exception as e:
        record('MAM online delivery test', False, str(e))
    finally:
        alice.disconnect()
        bob.disconnect()


async def test_muc_mam():
    """Test 5+6: MUC MAM query + room disco#info urn:xmpp:mam:2."""
    print("\n--- Test 5: Room disco#info — urn:xmpp:mam:2 ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    room_name = f"mamtest-{uuid.uuid4().hex[:8]}"
    room_jid = f"{room_name}@{MUC_SERVICE}"

    try:
        await connect_client(alice)

        # Join room (creates it)
        alice['xep_0045'].join_muc(room_jid, 'Alice')
        await asyncio.sleep(1)

        # Check room disco#info for MAM feature
        try:
            info = await asyncio.wait_for(
                alice['xep_0030'].get_info(jid=room_jid), timeout=5)
            features = info['disco_info']['features']
            mam_in_room = 'urn:xmpp:mam:2' in features
            record('Room disco#info — urn:xmpp:mam:2', mam_in_room,
                   'urn:xmpp:mam:2' if mam_in_room else 'MISSING')
        except Exception as e:
            record('Room disco#info', False, str(e))

        # Send groupchat messages
        print("\n--- Test 6: MUC MAM query ---")
        test_body_muc = f"MUC MAM test {uuid.uuid4().hex[:8]}"
        msg = alice.make_message(mto=room_jid, mbody=test_body_muc, mtype='groupchat')
        msg.send()
        await asyncio.sleep(1)

        # Query room MAM
        try:
            mam_id3 = f'mam-{uuid.uuid4().hex[:8]}'
            raw_muc_mam = (
                f"<iq type='set' id='{mam_id3}' to='{room_jid}'>"
                f"<query xmlns='urn:xmpp:mam:2'/></iq>"
            )

            muc_mam_results = []

            def muc_mam_handler(stanza):
                if 'message' in stanza.xml.tag:
                    if stanza.xml.find('.//{urn:xmpp:mam:2}result') is not None:
                        muc_mam_results.append(stanza)

            alice.register_handler(slixmpp.Callback(
                'MUC MAM', slixmpp.MatchXPath('{jabber:client}message'),
                muc_mam_handler, stream=None))
            alice.send_raw(raw_muc_mam)
            await asyncio.sleep(2)

            found_muc_msg = False
            for result_msg in muc_mam_results:
                if test_body_muc in str(result_msg):
                    found_muc_msg = True
                    break

            record('MUC message in room MAM archive', found_muc_msg,
                   f'{len(muc_mam_results)} results' + (' — found' if found_muc_msg else ' — NOT found'))

        except Exception as e:
            record('MUC MAM query', False, str(e))

    except Exception as e:
        record('MUC MAM test setup', False, str(e))
    finally:
        alice.disconnect()


async def main():
    print("=" * 60)
    print("xmppd E2E MAM Test (T81/T82/T83)")
    print(f"Target: {DOMAIN} ({HOST}:{PORT})")
    print("=" * 60)

    await test_disco_stanza_id()
    await test_mam_online_delivery()
    await test_muc_mam()

    print("\n" + "=" * 60)
    passed = sum(1 for _, p, _ in results if p)
    failed = sum(1 for _, p, _ in results if not p)
    print(f"Results: {passed} passed, {failed} failed, {len(results)} total")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())
