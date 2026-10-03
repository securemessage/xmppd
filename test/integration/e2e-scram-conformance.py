#!/usr/bin/env python3
"""SCRAM-SHA-256 interop conformance probe (RFC 5802 / RFC 7677).

A pure-stdlib SCRAM client: the derivation chain comes from python's
authoritative hashlib.pbkdf2_hmac, not from lib/sasl, so a shared
client/server bug in this repo cannot cancel itself out. The probe fails
unless the server BOTH accepts the standard-derivation ClientProof AND
returns the ServerSignature the standard ServerKey predicts — i.e. the
stored verifier really is standard PBKDF2-HMAC-SHA-256.

Usage:
    python3 test/integration/e2e-scram-conformance.py

Prerequisites:
    - xmppd-auth + xmppd-core running on XMPP_PORT (STARTTLS required)
    - User XMPP_USER with password XMPP_PASSWORD
"""

import base64
import hashlib
import hmac as hmac_mod
import os
import socket
import ssl
import sys

HOST = os.environ.get('XMPP_HOST', '127.0.0.1')
PORT = int(os.environ.get('XMPP_PORT', '15222'))
DOMAIN = os.environ.get('XMPP_DOMAIN', 'localhost')
USER = os.environ.get('XMPP_USER', 'alice')
PASSWORD = os.environ.get('XMPP_PASSWORD', 'pass1')


def read_until(sock, marker, buf=b''):
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError(f'eof waiting for {marker!r}: {buf!r}')
        buf += chunk
    return buf


def main():
    raw = socket.create_connection((HOST, PORT))
    raw.sendall(
        b"<stream:stream to='" + DOMAIN.encode() + b"' xmlns='jabber:client' "
        b"xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )
    read_until(raw, b'</stream:features>')
    raw.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    read_until(raw, b'<proceed')

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(raw, server_hostname=DOMAIN)
    sock.sendall(
        b"<stream:stream to='" + DOMAIN.encode() + b"' xmlns='jabber:client' "
        b"xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )
    read_until(sock, b'</stream:features>')

    cnonce = base64.b64encode(os.urandom(18)).decode()
    bare = f'n={USER},r={cnonce}'
    client_first = 'n,,' + bare
    auth = base64.b64encode(client_first.encode()).decode()
    sock.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'>{auth}</auth>".encode()
    )

    resp = read_until(sock, b'</challenge>')
    start = resp.index(b'>', resp.index(b'<challenge')) + 1
    server_first = base64.b64decode(resp[start:resp.index(b'</challenge>')]).decode()
    parts = dict(kv.split('=', 1) for kv in server_first.split(','))
    rnonce, salt, iters = parts['r'], base64.b64decode(parts['s']), int(parts['i'])
    assert rnonce.startswith(cnonce), 'server nonce did not extend client nonce'

    salted = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode(), salt, iters)
    client_key = hmac_mod.new(salted, b'Client Key', hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    channel_binding = base64.b64encode(b'n,,').decode()
    without_proof = f'c={channel_binding},r={rnonce}'
    auth_message = f'{bare},{server_first},{without_proof}'
    client_sig = hmac_mod.new(stored_key, auth_message.encode(), hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
    server_key = hmac_mod.new(salted, b'Server Key', hashlib.sha256).digest()
    expected_v = base64.b64encode(
        hmac_mod.new(server_key, auth_message.encode(), hashlib.sha256).digest()
    ).decode()

    final = f"{without_proof},p={base64.b64encode(proof).decode()}"
    sock.sendall(
        f"<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{base64.b64encode(final.encode()).decode()}</response>".encode()
    )

    resp = read_until(sock, b'>', b'')
    if b'<failure' in resp:
        print(f'FAIL: server rejected standard-derivation proof: {resp!r}')
        return 1
    sstart = resp.index(b'>', resp.index(b'<success')) + 1
    v = base64.b64decode(resp[sstart:resp.index(b'</success>')]).decode()
    got_v = v.split('=', 1)[1]
    if got_v != expected_v:
        print(f'FAIL: ServerSignature mismatch (stored verifier non-standard?): v={got_v} expected={expected_v}')
        return 1
    print(f'OK: standard PBKDF2-HMAC-SHA-256 proof accepted; ServerSignature verified (i={iters}, salt={parts["s"]})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
