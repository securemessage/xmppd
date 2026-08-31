#!/usr/bin/env python3
"""Live repro for T175: RFC 6121 8.5.3.2.1 chat fallback.

Mimics SINT's RFC6121Section8_5_3_2_1_MessageIntegrationTest
testChatOneResourcePrioZero / testChatMultipleResourcesPrioZeroAndNegative:
a type='chat' message addressed to a full JID whose resource is NOT bound
must be delivered to the account's (single) available resource with
non-negative priority.

Usage: XMPP_PORT=... python3 repro-85321.py  (throwaway instance, doc/TESTING.md)
"""

import asyncio
import os
import ssl
import sys

import slixmpp

HOST = os.environ.get('XMPP_HOST', '127.0.0.1')
PORT = int(os.environ.get('XMPP_PORT', '15222'))
DOMAIN = os.environ.get('XMPP_DOMAIN', 'localhost')
ALICE = f'alice@{DOMAIN}'
BOB = f'bob@{DOMAIN}'
TIMEOUT = 10


def make_client(jid, password):
    client = slixmpp.ClientXMPP(jid, password)
    client.register_plugin('xep_0030')
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client.ssl_context = ctx
    client.enable_direct_tls = False
    return client


async def connect(client):
    connected = asyncio.Event()
    client.add_event_handler('session_start', lambda _: connected.set())
    client.connect(HOST, PORT)
    await asyncio.wait_for(connected.wait(), timeout=TIMEOUT)


async def run(multi_resource):
    tag = 'multi' if multi_resource else 'single'
    alice = make_client(f'{ALICE}/default', os.environ.get('XMPP_ALICE_PASS', 'pass1'))
    bob0 = make_client(f'{BOB}/res0', os.environ.get('XMPP_BOB_PASS', 'pass2'))
    clients = [alice, bob0]
    if multi_resource:
        bob1 = make_client(f'{BOB}/res1', os.environ.get('XMPP_BOB_PASS', 'pass2'))
        clients.append(bob1)

    got_it = asyncio.Event()
    holder = {}

    def on_msg_bob0(msg):
        holder['msg'] = str(msg)
        holder['who'] = 'bob0 (prio 0)'
        got_it.set()

    bob0.add_event_handler('message', on_msg_bob0)

    try:
        for c in clients:
            await connect(c)

        # bob0: priority 0 (non-negative) — the legal fallback target
        bob0.send_presence(ppriority=0)
        if multi_resource:
            # bob1: negative priority — MUST NOT receive the fallback
            def on_msg_bob1(msg):
                holder['msg'] = str(msg)
                holder['who'] = 'bob1 (prio -1, WRONG TARGET)'
                got_it.set()
            bob1.add_event_handler('message', on_msg_bob1)
            bob1.send_presence(ppriority=-1)
        await asyncio.sleep(1.0)

        # Chat to a full JID whose resource is not bound
        target = f'{BOB}/nonexistent-res'
        alice.send_message(mto=target, mbody='fallback probe', mtype='chat')

        try:
            await asyncio.wait_for(got_it.wait(), timeout=TIMEOUT)
            print(f'[{tag}] DELIVERED to {holder.get("who")}: {holder["msg"][:120]}')
            return holder.get('who', '').startswith('bob0')
        except asyncio.TimeoutError:
            print(f'[{tag}] NOT DELIVERED — fallback broken')
            return False
    finally:
        for c in clients:
            c.disconnect()
        await asyncio.sleep(0.5)


async def main():
    ok1 = await run(multi_resource=False)
    await asyncio.sleep(1.0)
    ok2 = await run(multi_resource=True)
    return 0 if (ok1 and ok2) else 1


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
