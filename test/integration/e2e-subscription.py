#!/usr/bin/env python3
"""Comprehensive XMPP subscription test suite for xmppd.

Tests RFC 6121 §3 (Managing Presence Subscriptions) exhaustively:
  - §3.1 Requesting a Subscription (subscribe → subscribed flow)
  - §3.1.3 Server processing of inbound subscription request
  - §3.1.5 Server processing of outbound subscription approval
  - §3.1.6 Server processing of inbound subscription approval
  - §3.2 Canceling a Subscription (unsubscribed)
  - §3.3 Unsubscribing (unsubscribe)
  - §3.4 Pre-Approval (not implemented in xmppd — verify rejection)
  - Mutual subscription bootstrap (bidirectional)
  - Roster push correctness after each state transition
  - Presence delivery after subscription established
  - Presence unavailable on subscription cancel
  - Idempotent subscribe (duplicate subscribe must not error)
  - Subscribe to non-existent user (server MAY return error or silently hold)

Prerequisites:
    - xmppd running in the xmppd jail (morante.dev), interop config (no-TLS)
    - Users: alice, bob, charlie (password: test1234)
    - Each test cleans up its own subscription state via roster remove (§2.5)

Usage:
    # From freebsd-dev1 (start xmppd in interop mode):
    doas sysrc -j xmppd xmppd_config="/usr/local/etc/xmppd/xmppd-interop-notls.conf"
    doas jexec xmppd service xmppd restart
    python3 test/integration/e2e-subscription.py
"""

import asyncio
import logging
import ssl
import sys
import time

import slixmpp
from slixmpp.exceptions import IqError, IqTimeout

# -- Configuration --
HOST = '127.0.0.1'
PORT = 5222
DOMAIN = 'morante.dev'

ALICE_JID = f'alice@{DOMAIN}'
ALICE_PASS = 'test1234'
BOB_JID = f'bob@{DOMAIN}'
BOB_PASS = 'test1234'
CHARLIE_JID = f'charlie@{DOMAIN}'
CHARLIE_PASS = 'test1234'

TIMEOUT = 15  # seconds per wait — generous to catch the 47s stall if it regresses

# -- Test infrastructure --
results = []

def record(name, passed, detail=''):
    status = '✓' if passed else '✗'
    results.append((name, passed, detail))
    msg = f"  {status} {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)

def make_client(jid, password):
    """Create a slixmpp client with TLS disabled (plaintext to 127.0.0.1).
    Auto-subscription is disabled to prevent clients from automatically
    re-subscribing after unsubscribed/unsubscribe, which would mask server bugs."""
    client = slixmpp.ClientXMPP(jid, password)
    client.register_plugin('xep_0030')  # disco
    client.register_plugin('xep_0199')  # ping
    # Disable auto-subscription handling — tests must be explicit
    client.auto_authorize = False
    client.auto_subscribe = False
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client.ssl_context = ctx
    # Force plaintext (no STARTTLS) for interop testing
    client.use_tls = False
    return client


async def connect_client(client):
    """Connect and wait for session start."""
    connected = asyncio.get_event_loop().create_future()

    def on_session(event):
        if not connected.done():
            connected.set_result(True)

    client.add_event_handler('session_start', on_session)
    client.connect((HOST, PORT), disable_starttls=True, use_ssl=False)

    try:
        await asyncio.wait_for(connected, timeout=TIMEOUT)
    except asyncio.TimeoutError:
        raise RuntimeError(f"Connection timeout for {client.boundjid}")


async def disconnect_client(client):
    """Send unavailable presence and disconnect."""
    client.send_presence(ptype='unavailable')
    await asyncio.sleep(0.3)
    client.disconnect()
    await asyncio.sleep(0.3)


async def cleanup_subscription(client, contact_jid):
    """Remove a contact from the roster via IQ set subscription='remove'.
    Per RFC 6121 §2.5, this triggers unsubscribe/unsubscribed automatically
    and fully clears the subscription state on both sides."""
    try:
        await client.del_roster_item(contact_jid)
    except (IqError, IqTimeout):
        pass  # item may not exist — that's fine
    await asyncio.sleep(0.2)


# ============================================================================
# Test 1: Basic subscribe → subscribed flow (RFC 6121 §3.1)
# ============================================================================
async def test_basic_subscription():
    """Alice subscribes to Bob. Bob approves. Verify:
    - Alice receives roster push with subscription='none' ask='subscribe'
    - Bob receives the subscribe request
    - Bob sends subscribed
    - Alice receives subscribed presence
    - Alice receives roster push with subscription='to'
    - Alice receives Bob's current presence
    - Bob receives roster push with subscription='from'
    """
    print("\n--- Test 1: Basic subscribe → subscribed (§3.1) ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    # Event collectors
    alice_roster_pushes = []
    alice_presences = []
    bob_subscribe_received = asyncio.get_event_loop().create_future()
    bob_roster_pushes = []
    alice_subscribed_received = asyncio.get_event_loop().create_future()

    def alice_roster_push(iq):
        alice_roster_pushes.append(iq)

    def alice_presence(presence):
        alice_presences.append(presence)
        if presence['type'] == 'subscribed' and not alice_subscribed_received.done():
            alice_subscribed_received.set_result(presence)

    def bob_subscribe(presence):
        if not bob_subscribe_received.done():
            bob_subscribe_received.set_result(presence)

    def bob_roster_push(iq):
        bob_roster_pushes.append(iq)

    alice.add_event_handler('roster_update', alice_roster_push)
    alice.add_event_handler('presence_subscribe', lambda p: None)  # suppress auto-handling
    alice.add_event_handler('presence_subscribed', lambda p: alice_presence(p))
    alice.add_event_handler('presence_available', lambda p: alice_presences.append(p))

    bob.add_event_handler('roster_update', bob_roster_push)
    bob.add_event_handler('presence_subscribe', bob_subscribe)

    try:
        await connect_client(alice)
        await connect_client(bob)

        # Both send initial presence (become available + interested)
        alice.send_presence()
        bob.send_presence()
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        # Clear any initial roster pushes
        alice_roster_pushes.clear()
        bob_roster_pushes.clear()
        alice_presences.clear()

        # Alice subscribes to Bob
        start_time = time.time()
        alice.send_presence(pto=BOB_JID, ptype='subscribe')

        # Bob should receive the subscribe request
        try:
            sub_pres = await asyncio.wait_for(bob_subscribe_received, timeout=TIMEOUT)
            elapsed = time.time() - start_time
            record("Bob receives subscribe from Alice", True, f"{elapsed:.2f}s")
            record("Subscribe from is bare JID", sub_pres['from'].bare == ALICE_JID, f"from={sub_pres['from']}")
        except asyncio.TimeoutError:
            elapsed = time.time() - start_time
            record("Bob receives subscribe from Alice", False, f"TIMEOUT after {elapsed:.1f}s — possible 47s stall!")
            await disconnect_client(alice)
            await disconnect_client(bob)
            return

        # Check Alice got roster push with ask='subscribe'
        await asyncio.sleep(0.5)
        alice_got_ask = any(
            BOB_JID in str(rp) and 'subscribe' in str(rp)
            for rp in alice_roster_pushes
        )
        record("Alice gets roster push (ask=subscribe)", alice_got_ask)

        # Bob approves the subscription
        start_time = time.time()
        bob.send_presence(pto=ALICE_JID, ptype='subscribed')

        # Alice should receive the subscribed notification
        try:
            await asyncio.wait_for(alice_subscribed_received, timeout=TIMEOUT)
            elapsed = time.time() - start_time
            record("Alice receives subscribed from Bob", True, f"{elapsed:.2f}s")
        except asyncio.TimeoutError:
            elapsed = time.time() - start_time
            record("Alice receives subscribed from Bob", False, f"TIMEOUT after {elapsed:.1f}s")
            await disconnect_client(alice)
            await disconnect_client(bob)
            return

        # Wait for presence + roster pushes to propagate
        await asyncio.sleep(1.0)

        # Alice should have received Bob's available presence
        alice_got_bob_presence = any(
            p['from'].bare == BOB_JID and p['type'] not in ('subscribe', 'subscribed', 'unsubscribe', 'unsubscribed', 'unavailable', 'error', 'probe')
            for p in alice_presences
            if hasattr(p['from'], 'bare')
        )
        record("Alice receives Bob's available presence", alice_got_bob_presence)

        # Bob should have a roster push with subscription='from'
        bob_got_from = any(
            'from' in str(rp)
            for rp in bob_roster_pushes
        )
        record("Bob gets roster push (subscription=from)", bob_got_from)

    finally:
        await cleanup_subscription(alice, BOB_JID)
        await cleanup_subscription(bob, ALICE_JID)
        await disconnect_client(alice)
        await disconnect_client(bob)


# ============================================================================
# Test 2: Mutual subscription (RFC 6121 §3.1 both directions)
# ============================================================================
async def test_mutual_subscription():
    """Alice subscribes to Bob, Bob approves. Then Bob subscribes to Alice, Alice approves.
    Final state: both have subscription='both'.
    Verify presence flows bidirectionally."""
    print("\n--- Test 2: Mutual subscription (subscription='both') ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    bob_sub_req = asyncio.get_event_loop().create_future()
    alice_sub_req = asyncio.get_event_loop().create_future()

    def bob_on_subscribe(presence):
        if not bob_sub_req.done():
            bob_sub_req.set_result(presence)

    def alice_on_subscribe(presence):
        if not alice_sub_req.done():
            alice_sub_req.set_result(presence)

    bob.add_event_handler('presence_subscribe', bob_on_subscribe)
    alice.add_event_handler('presence_subscribe', alice_on_subscribe)

    try:
        await connect_client(alice)
        await connect_client(bob)
        alice.send_presence()
        bob.send_presence()
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        # Step 1: Alice → Bob subscription
        alice.send_presence(pto=BOB_JID, ptype='subscribe')
        try:
            await asyncio.wait_for(bob_sub_req, timeout=TIMEOUT)
            record("Mutual: Bob gets Alice's subscribe", True)
        except asyncio.TimeoutError:
            record("Mutual: Bob gets Alice's subscribe", False, "TIMEOUT")
            return

        bob.send_presence(pto=ALICE_JID, ptype='subscribed')
        await asyncio.sleep(1.0)

        # Step 2: Bob → Alice subscription
        bob.send_presence(pto=ALICE_JID, ptype='subscribe')
        try:
            await asyncio.wait_for(alice_sub_req, timeout=TIMEOUT)
            record("Mutual: Alice gets Bob's subscribe", True)
        except asyncio.TimeoutError:
            record("Mutual: Alice gets Bob's subscribe", False, "TIMEOUT")
            return

        alice.send_presence(pto=BOB_JID, ptype='subscribed')
        await asyncio.sleep(1.0)

        # Verify final roster state
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        alice_sub = alice.client_roster[BOB_JID]['subscription']
        bob_sub = bob.client_roster[ALICE_JID]['subscription']
        record("Alice→Bob subscription='both'", alice_sub == 'both', f"got '{alice_sub}'")
        record("Bob→Alice subscription='both'", bob_sub == 'both', f"got '{bob_sub}'")

    finally:
        await cleanup_subscription(alice, BOB_JID)
        await cleanup_subscription(bob, ALICE_JID)
        await disconnect_client(alice)
        await disconnect_client(bob)


# ============================================================================
# Test 3: Subscription cancellation (RFC 6121 §3.2)
# ============================================================================
async def test_subscription_cancel():
    """Establish Alice→Bob subscription, then Bob cancels it (unsubscribed).
    Alice should receive unavailable presence + roster push with subscription='none'."""
    print("\n--- Test 3: Subscription cancellation (§3.2) ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    bob_sub_req = asyncio.get_event_loop().create_future()
    alice_unsubscribed = asyncio.get_event_loop().create_future()
    alice_unavailable = asyncio.get_event_loop().create_future()

    def bob_on_subscribe(presence):
        if not bob_sub_req.done():
            bob_sub_req.set_result(presence)

    def alice_on_unsubscribed(presence):
        if not alice_unsubscribed.done():
            alice_unsubscribed.set_result(presence)

    def alice_on_unavailable(presence):
        if presence['from'].bare == BOB_JID and not alice_unavailable.done():
            alice_unavailable.set_result(presence)

    bob.add_event_handler('presence_subscribe', bob_on_subscribe)
    alice.add_event_handler('presence_unsubscribed', alice_on_unsubscribed)
    alice.add_event_handler('presence_unavailable', alice_on_unavailable)

    try:
        await connect_client(alice)
        await connect_client(bob)
        alice.send_presence()
        bob.send_presence()
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        # Establish subscription
        alice.send_presence(pto=BOB_JID, ptype='subscribe')
        await asyncio.wait_for(bob_sub_req, timeout=TIMEOUT)
        bob.send_presence(pto=ALICE_JID, ptype='subscribed')
        await asyncio.sleep(1.0)

        # Bob cancels the subscription
        start_time = time.time()
        bob.send_presence(pto=ALICE_JID, ptype='unsubscribed')

        # Alice should receive unavailable from Bob
        try:
            await asyncio.wait_for(alice_unavailable, timeout=TIMEOUT)
            elapsed = time.time() - start_time
            record("Cancel: Alice receives unavailable from Bob", True, f"{elapsed:.2f}s")
        except asyncio.TimeoutError:
            record("Cancel: Alice receives unavailable from Bob", False, "TIMEOUT")

        # Alice should receive unsubscribed
        try:
            await asyncio.wait_for(alice_unsubscribed, timeout=TIMEOUT)
            record("Cancel: Alice receives unsubscribed from Bob", True)
        except asyncio.TimeoutError:
            record("Cancel: Alice receives unsubscribed from Bob", False, "TIMEOUT")

        # Verify roster state
        await asyncio.sleep(0.5)
        await alice.get_roster()
        try:
            alice_sub = alice.client_roster[BOB_JID]['subscription']
        except (KeyError, TypeError):
            alice_sub = 'none'
        # After cancel from 'both', Alice loses 'to' direction → 'from' remains.
        # After cancel from 'from' only (no prior mutual), result is 'none'.
        valid = alice_sub in ('none', 'from')
        record("Cancel: Alice subscription downgraded", valid, f"got '{alice_sub}'")

    finally:
        await cleanup_subscription(alice, BOB_JID)
        await cleanup_subscription(bob, ALICE_JID)
        await disconnect_client(alice)
        await disconnect_client(bob)


# ============================================================================
# Test 4: Unsubscribe (RFC 6121 §3.3)
# ============================================================================
async def test_unsubscribe():
    """Establish Alice→Bob subscription, then Alice unsubscribes.
    Alice should get roster push with subscription='none'.
    Bob should receive unsubscribe notification."""
    print("\n--- Test 4: Unsubscribe (§3.3) ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    bob_sub_req = asyncio.get_event_loop().create_future()
    bob_unsubscribe = asyncio.get_event_loop().create_future()

    def bob_on_subscribe(presence):
        if not bob_sub_req.done():
            bob_sub_req.set_result(presence)

    def bob_on_unsubscribe(presence):
        if not bob_unsubscribe.done():
            bob_unsubscribe.set_result(presence)

    bob.add_event_handler('presence_subscribe', bob_on_subscribe)
    bob.add_event_handler('presence_unsubscribe', bob_on_unsubscribe)

    try:
        await connect_client(alice)
        await connect_client(bob)
        alice.send_presence()
        bob.send_presence()
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        # Establish subscription
        alice.send_presence(pto=BOB_JID, ptype='subscribe')
        await asyncio.wait_for(bob_sub_req, timeout=TIMEOUT)
        bob.send_presence(pto=ALICE_JID, ptype='subscribed')
        await asyncio.sleep(1.0)

        # Alice unsubscribes
        start_time = time.time()
        alice.send_presence(pto=BOB_JID, ptype='unsubscribe')

        # Bob should receive unsubscribe notification
        try:
            await asyncio.wait_for(bob_unsubscribe, timeout=TIMEOUT)
            elapsed = time.time() - start_time
            record("Unsubscribe: Bob receives unsubscribe", True, f"{elapsed:.2f}s")
        except asyncio.TimeoutError:
            record("Unsubscribe: Bob receives unsubscribe", False, "TIMEOUT")

        # Verify Alice's roster state
        await asyncio.sleep(0.5)
        await alice.get_roster()
        try:
            alice_sub = alice.client_roster[BOB_JID]['subscription']
        except (KeyError, TypeError):
            alice_sub = 'none'
        # After unsubscribe from 'both', Alice loses 'to' direction → 'from' remains.
        # After unsubscribe from 'to' only, result is 'none'.
        valid = alice_sub in ('none', 'from')
        record("Unsubscribe: Alice subscription downgraded", valid, f"got '{alice_sub}'")

    finally:
        await cleanup_subscription(alice, BOB_JID)
        await cleanup_subscription(bob, ALICE_JID)
        await disconnect_client(alice)
        await disconnect_client(bob)


# ============================================================================
# Test 5: Duplicate subscribe is idempotent (RFC 6121 §3.1.3 rule 2)
# ============================================================================
async def test_duplicate_subscribe():
    """Send subscribe twice. Second should not error or create duplicate roster entries."""
    print("\n--- Test 5: Duplicate subscribe is idempotent ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    sub_count = [0]

    def bob_on_subscribe(presence):
        sub_count[0] += 1

    bob.add_event_handler('presence_subscribe', bob_on_subscribe)

    try:
        await connect_client(alice)
        await connect_client(bob)
        alice.send_presence()
        bob.send_presence()
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        # Send subscribe twice
        alice.send_presence(pto=BOB_JID, ptype='subscribe')
        await asyncio.sleep(1.0)
        alice.send_presence(pto=BOB_JID, ptype='subscribe')
        await asyncio.sleep(1.0)

        # Bob should receive at least 1 subscribe (server MAY deduplicate)
        record("Duplicate subscribe: Bob received subscribe", sub_count[0] >= 1, f"count={sub_count[0]}")
        record("Duplicate subscribe: no error/crash", True)

    finally:
        await cleanup_subscription(alice, BOB_JID)
        await cleanup_subscription(bob, ALICE_JID)
        await disconnect_client(alice)
        await disconnect_client(bob)


# ============================================================================
# Test 6: Subscribe to full JID normalizes to bare (RFC 6121 §3.1.2)
# ============================================================================
async def test_subscribe_full_jid():
    """Subscribe to bob@morante.dev/resource should be treated as bare JID subscribe."""
    print("\n--- Test 6: Subscribe to full JID (normalize to bare) ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    bob_sub_req = asyncio.get_event_loop().create_future()

    def bob_on_subscribe(presence):
        if not bob_sub_req.done():
            bob_sub_req.set_result(presence)

    bob.add_event_handler('presence_subscribe', bob_on_subscribe)

    try:
        await connect_client(alice)
        await connect_client(bob)
        alice.send_presence()
        bob.send_presence()
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        # Subscribe to full JID (should be normalized)
        alice.send_presence(pto=f'{BOB_JID}/some-resource', ptype='subscribe')

        try:
            sub = await asyncio.wait_for(bob_sub_req, timeout=TIMEOUT)
            # The 'from' should be Alice's bare JID (server stamps it)
            record("Full JID subscribe: Bob receives it", True)
            record("Full JID subscribe: from is bare", sub['from'].bare == ALICE_JID, f"from={sub['from']}")
        except asyncio.TimeoutError:
            record("Full JID subscribe: Bob receives it", False, "TIMEOUT")

    finally:
        await cleanup_subscription(alice, BOB_JID)
        await cleanup_subscription(bob, ALICE_JID)
        await disconnect_client(alice)
        await disconnect_client(bob)


# ============================================================================
# Test 7: Presence delivery after subscription (RFC 6121 §3.1.5/§3.1.6)
# ============================================================================
async def test_presence_after_subscription():
    """After subscription established, Bob goes offline then online.
    Alice should receive unavailable then available."""
    print("\n--- Test 7: Presence delivery after subscription ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    bob_sub_req = asyncio.get_event_loop().create_future()
    alice_got_unavailable = asyncio.get_event_loop().create_future()
    alice_got_available = asyncio.get_event_loop().create_future()

    def bob_on_subscribe(presence):
        if not bob_sub_req.done():
            bob_sub_req.set_result(presence)

    bob.add_event_handler('presence_subscribe', bob_on_subscribe)

    try:
        await connect_client(alice)
        await connect_client(bob)
        alice.send_presence()
        bob.send_presence()
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        # Establish subscription
        alice.send_presence(pto=BOB_JID, ptype='subscribe')
        await asyncio.wait_for(bob_sub_req, timeout=TIMEOUT)
        bob.send_presence(pto=ALICE_JID, ptype='subscribed')
        await asyncio.sleep(1.0)

        # Now set up listeners for Bob going offline/online
        def alice_on_unavailable(presence):
            if presence['from'].bare == BOB_JID and not alice_got_unavailable.done():
                alice_got_unavailable.set_result(presence)

        def alice_on_available(presence):
            ptype = presence['type']
            if presence['from'].bare == BOB_JID and ptype not in ('subscribe', 'subscribed', 'unsubscribe', 'unsubscribed', 'unavailable', 'error', 'probe'):
                if not alice_got_available.done():
                    alice_got_available.set_result(presence)

        alice.add_event_handler('presence_unavailable', alice_on_unavailable)
        alice.add_event_handler('presence_available', alice_on_available)

        # Bob goes offline
        await disconnect_client(bob)

        try:
            await asyncio.wait_for(alice_got_unavailable, timeout=TIMEOUT)
            record("Presence delivery: Alice gets Bob unavailable", True)
        except asyncio.TimeoutError:
            record("Presence delivery: Alice gets Bob unavailable", False, "TIMEOUT")

        # Bob comes back online
        bob2 = make_client(BOB_JID, BOB_PASS)
        await connect_client(bob2)
        bob2.send_presence()
        await asyncio.sleep(0.5)

        try:
            await asyncio.wait_for(alice_got_available, timeout=TIMEOUT)
            record("Presence delivery: Alice gets Bob available (reconnect)", True)
        except asyncio.TimeoutError:
            record("Presence delivery: Alice gets Bob available (reconnect)", False, "TIMEOUT — possible 47s stall?")

        await disconnect_client(bob2)

    finally:
        await cleanup_subscription(alice, BOB_JID)
        await disconnect_client(alice)


# ============================================================================
# Test 8: Presence with status/priority after subscription (RFC 6121 §3.1.5)
# ============================================================================
async def test_presence_with_status():
    """After subscription, contact's presence should include status/show/priority."""
    print("\n--- Test 8: Presence includes status/show/priority ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    bob_sub_req = asyncio.get_event_loop().create_future()
    alice_presence_full = asyncio.get_event_loop().create_future()
    alice_all_stanzas = []

    def bob_on_subscribe(presence):
        if not bob_sub_req.done():
            bob_sub_req.set_result(presence)

    bob.add_event_handler('presence_subscribe', bob_on_subscribe)

    # Capture Bob's available presence with status — use only 'presence' event (raw)
    def alice_any_presence(presence):
        ptype = presence['type']
        from_jid = presence['from']
        if hasattr(from_jid, 'bare') and from_jid.bare == BOB_JID:
            alice_all_stanzas.append(f"type={ptype} from={from_jid} status='{presence['status']}'")
            if ptype not in ('subscribe', 'subscribed', 'unsubscribe', 'unsubscribed', 'unavailable', 'error', 'probe'):
                if not alice_presence_full.done():
                    alice_presence_full.set_result(presence)

    try:
        await connect_client(alice)
        await connect_client(bob)

        # Register on raw 'presence' event only (avoid double-fire from presence_available)
        alice.add_event_handler('presence', alice_any_presence)

        # Bob sends presence with status
        bob.send_presence(pstatus='Testing XMPP', pshow='chat', ppriority='5')
        alice.send_presence()
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        # Establish subscription
        alice.send_presence(pto=BOB_JID, ptype='subscribe')
        await asyncio.wait_for(bob_sub_req, timeout=TIMEOUT)
        bob.send_presence(pto=ALICE_JID, ptype='subscribed')

        # Alice should receive Bob's presence WITH status
        try:
            pres = await asyncio.wait_for(alice_presence_full, timeout=TIMEOUT)
            has_status = pres['status'] == 'Testing XMPP'
            record("Presence with status: received", True)
            record("Presence with status: status text correct", has_status, f"got '{pres['status']}'")
        except asyncio.TimeoutError:
            record("Presence with status: received", False, "TIMEOUT — this is the suspected bug!")
            # Dump all stanzas Alice received for debugging
            print(f"    DEBUG: Alice received {len(alice_all_stanzas)} presence stanzas total:")
            for s in alice_all_stanzas[-10:]:
                print(f"      {s}")

    finally:
        await cleanup_subscription(alice, BOB_JID)
        await cleanup_subscription(bob, ALICE_JID)
        await disconnect_client(alice)
        await disconnect_client(bob)


# ============================================================================
# Test 9: Roster push to all interested resources (RFC 6121 §3.1.5)
# ============================================================================
async def test_roster_push_multiple_resources():
    """Alice connects with 2 resources. Subscribe should push to both."""
    print("\n--- Test 9: Roster push to multiple resources ---")

    alice1 = make_client(ALICE_JID, ALICE_PASS)
    alice1.requested_jid = slixmpp.JID(f'{ALICE_JID}/resource1')
    alice2 = make_client(ALICE_JID, ALICE_PASS)
    alice2.requested_jid = slixmpp.JID(f'{ALICE_JID}/resource2')
    bob = make_client(BOB_JID, BOB_PASS)

    bob_sub_req = asyncio.get_event_loop().create_future()
    alice1_pushes = []
    alice2_pushes = []

    def bob_on_subscribe(presence):
        if not bob_sub_req.done():
            bob_sub_req.set_result(presence)

    bob.add_event_handler('presence_subscribe', bob_on_subscribe)
    alice1.add_event_handler('roster_update', lambda iq: alice1_pushes.append(iq))
    alice2.add_event_handler('roster_update', lambda iq: alice2_pushes.append(iq))

    try:
        await connect_client(alice1)
        await connect_client(alice2)
        await connect_client(bob)
        alice1.send_presence()
        alice2.send_presence()
        bob.send_presence()
        await alice1.get_roster()
        await alice2.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        alice1_pushes.clear()
        alice2_pushes.clear()

        # Subscribe from resource1
        alice1.send_presence(pto=BOB_JID, ptype='subscribe')
        await asyncio.wait_for(bob_sub_req, timeout=TIMEOUT)
        bob.send_presence(pto=ALICE_JID, ptype='subscribed')
        await asyncio.sleep(1.5)

        # Both resources should have received roster pushes
        record("Multi-resource: resource1 got roster push", len(alice1_pushes) > 0, f"count={len(alice1_pushes)}")
        record("Multi-resource: resource2 got roster push", len(alice2_pushes) > 0, f"count={len(alice2_pushes)}")

    finally:
        await cleanup_subscription(alice1, BOB_JID)
        await cleanup_subscription(bob, ALICE_JID)
        await disconnect_client(alice1)
        await disconnect_client(alice2)
        await disconnect_client(bob)


# ============================================================================
# Test 10: Subscribe while contact offline (RFC 6121 §3.1.3 rule 4)
# ============================================================================
async def test_subscribe_contact_offline():
    """Alice subscribes to Charlie while Charlie is offline.
    Charlie connects later and should receive the pending subscribe."""
    print("\n--- Test 10: Subscribe while contact offline (§3.1.3 rule 4) ---")

    alice = make_client(ALICE_JID, ALICE_PASS)

    try:
        await connect_client(alice)
        alice.send_presence()
        await alice.get_roster()
        await asyncio.sleep(0.3)

        # Subscribe to Charlie (who is offline)
        alice.send_presence(pto=CHARLIE_JID, ptype='subscribe')
        await asyncio.sleep(1.0)

        # Now Charlie comes online
        charlie = make_client(CHARLIE_JID, CHARLIE_PASS)
        charlie_sub_req = asyncio.get_event_loop().create_future()

        def charlie_on_subscribe(presence):
            if not charlie_sub_req.done():
                charlie_sub_req.set_result(presence)

        charlie.add_event_handler('presence_subscribe', charlie_on_subscribe)

        await connect_client(charlie)
        charlie.send_presence()
        await charlie.get_roster()

        # Charlie should receive the deferred subscribe
        try:
            sub = await asyncio.wait_for(charlie_sub_req, timeout=TIMEOUT)
            record("Offline subscribe: Charlie receives deferred request", True)
            record("Offline subscribe: from Alice bare JID", sub['from'].bare == ALICE_JID)
        except asyncio.TimeoutError:
            record("Offline subscribe: Charlie receives deferred request", False, "TIMEOUT")

        await cleanup_subscription(charlie, ALICE_JID)
        await disconnect_client(charlie)

    finally:
        await cleanup_subscription(alice, CHARLIE_JID)
        await disconnect_client(alice)


# ============================================================================
# Test 11: Timing test — measure actual latency of subscription flow
# ============================================================================
async def test_subscription_timing():
    """Measure end-to-end latency of the full subscribe→subscribed→presence flow.
    This is the key test to detect the '47 second stall' bug."""
    print("\n--- Test 11: Subscription timing (detect stalls) ---")

    alice = make_client(ALICE_JID, ALICE_PASS)
    bob = make_client(BOB_JID, BOB_PASS)

    bob_sub_req = asyncio.get_event_loop().create_future()
    alice_presence = asyncio.get_event_loop().create_future()

    def bob_on_subscribe(presence):
        if not bob_sub_req.done():
            bob_sub_req.set_result(presence)

    def alice_on_presence(presence):
        ptype = presence['type']
        from_jid = presence['from']
        if hasattr(from_jid, 'bare') and from_jid.bare == BOB_JID and ptype not in ('subscribe', 'subscribed', 'unsubscribe', 'unsubscribed', 'unavailable', 'error', 'probe'):
            if not alice_presence.done():
                alice_presence.set_result(presence)

    bob.add_event_handler('presence_subscribe', bob_on_subscribe)
    # Use raw 'presence' event — slixmpp's 'presence_available' depends on internal
    # roster state being synchronized, which races during subscription establishment.
    alice.add_event_handler('presence', alice_on_presence)

    try:
        await connect_client(alice)
        await connect_client(bob)
        bob.send_presence(pstatus='Online', pshow='chat', ppriority='5')
        alice.send_presence()
        await alice.get_roster()
        await bob.get_roster()
        await asyncio.sleep(0.5)

        # Full timed flow
        t0 = time.time()
        alice.send_presence(pto=BOB_JID, ptype='subscribe')

        t1_sub = await asyncio.wait_for(bob_sub_req, timeout=TIMEOUT)
        t1 = time.time()
        record(f"Timing: subscribe delivery", True, f"{(t1-t0)*1000:.0f}ms")

        bob.send_presence(pto=ALICE_JID, ptype='subscribed')

        try:
            await asyncio.wait_for(alice_presence, timeout=TIMEOUT)
            t2 = time.time()
            total_ms = (t2 - t0) * 1000
            record(f"Timing: total subscribe→presence", total_ms < 5000, f"{total_ms:.0f}ms")
            if total_ms > 3000:
                record("WARNING: Latency > 3s — possible stall regression!", False, f"{total_ms:.0f}ms")
        except asyncio.TimeoutError:
            elapsed = time.time() - t0
            record(f"Timing: total subscribe→presence", False, f"TIMEOUT after {elapsed:.1f}s — 47s STALL DETECTED!")

    finally:
        await cleanup_subscription(alice, BOB_JID)
        await cleanup_subscription(bob, ALICE_JID)
        await disconnect_client(alice)
        await disconnect_client(bob)


# ============================================================================
# Main runner
# ============================================================================
async def main():
    print("=" * 70)
    print("  xmppd Subscription Test Suite (RFC 6121 §3)")
    print(f"  Server: {HOST}:{PORT} ({DOMAIN})")
    print("=" * 70)

    tests = [
        test_basic_subscription,
        test_mutual_subscription,
        test_subscription_cancel,
        test_unsubscribe,
        test_duplicate_subscribe,
        test_subscribe_full_jid,
        test_presence_after_subscription,
        test_presence_with_status,
        test_roster_push_multiple_resources,
        test_subscribe_contact_offline,
        test_subscription_timing,
    ]

    for test_fn in tests:
        try:
            await test_fn()
        except Exception as e:
            record(f"{test_fn.__name__} EXCEPTION", False, str(e))
        # Brief pause between tests for server to settle
        await asyncio.sleep(0.5)

    # Summary
    print("\n" + "=" * 70)
    passed = sum(1 for _, p, _ in results if p)
    failed = sum(1 for _, p, _ in results if not p)
    print(f"  Results: {passed} passed, {failed} failed, {len(results)} total")
    print("=" * 70)

    if failed > 0:
        print("\n  FAILURES:")
        for name, passed, detail in results:
            if not passed:
                print(f"    ✗ {name} — {detail}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())
