#!/usr/bin/env python3
"""End-to-end test for T165: invite-gated in-band registration (XEP-0077).

Unlike the other suites this one uses a raw socket (not slixmpp) because the
registration happens pre-auth and must inject a custom jabber:x:data field;
slixmpp's xep_0077 client flow only fires when the server advertises
<register/> *instead* of SASL mechanisms, which xmppd does not do.

Tests:
  1. Registration form (jabber:iq:register GET) advertises a jabber:x:data
     form with an 'invite' field.
  2. Submit without an invite field -> error (invite required).
  3. Submit with a wrong invite code -> error.
  4. Submit with the valid invite code -> success.

Prerequisites:
    - Throwaway instance (see doc/TESTING.md) whose auth daemon runs with
      registration enabled and invites REQUIRED (the default; do NOT pass
      --no-require-invite).
    - An invite code created before server start:
        ./zig-out/bin/xmppctl --db /tmp/xmppd-test-db invite create --max-uses 5
      passed to this suite via XMPP_INVITE_CODE.
"""

import os
import socket
import ssl
import sys
import uuid
import xml.etree.ElementTree as ET

HOST = os.environ.get('XMPP_HOST', '127.0.0.1')
PORT = int(os.environ.get('XMPP_PORT', '15222'))
DOMAIN = os.environ.get('XMPP_DOMAIN', 'localhost')
INVITE_CODE = os.environ.get('XMPP_INVITE_CODE', '')

TIMEOUT = 10
results = []


def record(name, passed, detail=''):
    status = '✓' if passed else '✗'
    results.append((name, passed, detail))
    msg = f"  {status} {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)


class XmppConnection:
    """Minimal raw C2S connection: stream open, STARTTLS, IQ exchange."""

    def __init__(self):
        self.sock = None
        self.buf = b''

    def connect(self):
        self.sock = socket.create_connection((HOST, PORT), timeout=TIMEOUT)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def send(self, data):
        self.sock.sendall(data.encode())

    def recv_until(self, *markers):
        """Read until every marker appears in the receive buffer."""
        while True:
            text = self.buf.decode('utf-8', errors='replace')
            if all(m in text for m in markers):
                self.buf = b''
                return text
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                raise TimeoutError(
                    f"timeout waiting for {markers}; got: {text!r}")
            if not chunk:
                raise ConnectionError(
                    f"server closed connection; got: {text!r}")
            self.buf += chunk

    def open_stream(self):
        self.send(
            "<?xml version='1.0'?>"
            "<stream:stream xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams' "
            f"to='{DOMAIN}' version='1.0'>")
        return self.recv_until('</stream:features>')

    def starttls(self):
        features = self.open_stream()
        if 'urn:ietf:params:xml:ns:xmpp-tls' not in features:
            raise RuntimeError(f'server did not offer STARTTLS: {features!r}')
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        self.recv_until('<proceed')
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(self.sock, server_hostname=DOMAIN)
        self.sock.settimeout(TIMEOUT)
        self.buf = b''
        return self.open_stream()

    def recv_iq_response(self, iq_id):
        """Read until the full IQ response for iq_id has arrived.

        A successful result may be a self-closing `<iq ... id='X'/>`; an
        error carries child elements and ends with `</iq>`.
        """
        while True:
            text = self.buf.decode('utf-8', errors='replace')
            if f"id='{iq_id}'/>" in text:
                self.buf = b''
                return text
            if f"id='{iq_id}'" in text and '</iq>' in text:
                self.buf = b''
                return text
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                raise TimeoutError(
                    f"timeout waiting for iq id='{iq_id}'; got: {text!r}")
            if not chunk:
                raise ConnectionError(
                    f"server closed connection; got: {text!r}")
            self.buf += chunk

    def iq_register(self, iq_type, inner):
        """Send a jabber:iq:register IQ and return the response stanza.

        The response is strict-parsed with ElementTree — substring
        assertions alone miss malformed server XML (the v0.8.9
        stray-</field> regression only surfaced under Smack's parser).
        """
        iq_id = uuid.uuid4().hex[:12]
        self.send(
            f"<iq type='{iq_type}' id='{iq_id}' to='{DOMAIN}'>"
            f"<query xmlns='jabber:iq:register'>{inner}</query></iq>")
        resp = self.recv_iq_response(iq_id)
        ET.fromstring(resp)
        return resp


def register_set_inner(username, password, invite=None):
    """Build a registration submit payload: legacy fields + x:data form."""
    fields = (
        f"<field var='username'><value>{username}</value></field>"
        f"<field var='password'><value>{password}</value></field>")
    if invite is not None:
        fields += f"<field var='invite'><value>{invite}</value></field>"
    return (
        f"<username>{username}</username><password>{password}</password>"
        f"<x xmlns='jabber:x:data' type='submit'>{fields}</x>")


def test_form_advertises_invite_field():
    """Test 1: registration form includes a jabber:x:data invite field."""
    print("\n--- Test 1: registration form advertises invite field ---")
    conn = XmppConnection()
    try:
        conn.connect()
        features = conn.starttls()
        record('register stream feature advertised',
               'features/iq-register' in features)
        resp = conn.iq_register('get', '')
        record('form has jabber:x:data', 'jabber:x:data' in resp)
        record("form has 'invite' field", "var='invite'" in resp)
    except Exception as e:
        record('registration form query', False, str(e))
    finally:
        conn.close()


def test_register_without_invite_rejected():
    """Test 2: submit without an invite field is rejected."""
    print("\n--- Test 2: registration without invite is rejected ---")
    conn = XmppConnection()
    try:
        conn.connect()
        conn.starttls()
        user = f'noinvite-{uuid.uuid4().hex[:8]}'
        resp = conn.iq_register('set', register_set_inner(user, 'pw12345'))
        passed = "type='error'" in resp
        record('registration without invite rejected', passed,
               '' if passed else f'unexpected success: {resp!r}')
    except Exception as e:
        record('registration without invite', False, str(e))
    finally:
        conn.close()


def test_register_wrong_invite_rejected():
    """Test 3: submit with a wrong invite code is rejected."""
    print("\n--- Test 3: registration with wrong invite is rejected ---")
    conn = XmppConnection()
    try:
        conn.connect()
        conn.starttls()
        user = f'badinvite-{uuid.uuid4().hex[:8]}'
        resp = conn.iq_register(
            'set', register_set_inner(user, 'pw12345', 'zzz-not-a-real-code'))
        passed = "type='error'" in resp
        record('registration with wrong invite rejected', passed,
               '' if passed else f'unexpected success: {resp!r}')
    except Exception as e:
        record('registration with wrong invite', False, str(e))
    finally:
        conn.close()


def test_register_with_valid_invite():
    """Test 4: submit with the valid invite code succeeds."""
    print("\n--- Test 4: registration with valid invite succeeds ---")
    if not INVITE_CODE:
        record('registration with valid invite', False,
               'XMPP_INVITE_CODE not set — create one with: '
               'xmppctl --db <db> invite create --max-uses 5')
        return
    conn = XmppConnection()
    try:
        conn.connect()
        conn.starttls()
        user = f'invited-{uuid.uuid4().hex[:8]}'
        resp = conn.iq_register(
            'set', register_set_inner(user, 'pw12345', INVITE_CODE))
        passed = "type='result'" in resp
        record('registration with valid invite succeeded', passed,
               '' if passed else f'unexpected error: {resp!r}')
    except Exception as e:
        record('registration with valid invite', False, str(e))
    finally:
        conn.close()


def main():
    print(f'Target: {HOST}:{PORT} domain={DOMAIN}')
    test_form_advertises_invite_field()
    test_register_without_invite_rejected()
    test_register_wrong_invite_rejected()
    test_register_with_valid_invite()

    print('\n=== Results ===')
    failed = sum(1 for _, p, _ in results if not p)
    print(f'{len(results) - failed}/{len(results)} passed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
