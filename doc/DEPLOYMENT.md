# xmppd Deployment Guide (FreeBSD)

## Quick Start

```sh
# Install from package
pkg install xmppd

# Create database directory
mkdir -p /var/db/xmppd /var/run/xmppd /var/log/xmppd
chown jabber:jabber /var/db/xmppd /var/run/xmppd /var/log/xmppd

# Configure
cp /usr/local/etc/xmppd/xmppd.conf.sample /usr/local/etc/xmppd/xmppd.conf
# Edit: set hostname, TLS cert/key paths

# Create first user
xmppctl adduser alice

# Enable and start
sysrc xmppd_enable=YES
service xmppd start
```

## TLS Certificate

xmppd requires a TLS certificate for the XMPP domain. The certificate
must cover the hostname (e.g., `example.com` or `*.example.com`).

```ini
[tls]
cert = /usr/local/etc/xmppd/fullchain.pem
key = /usr/local/etc/xmppd/privkey.pem
```

For Let's Encrypt with DANE, ensure your DNS has a TLSA record:
```
_5222._tcp.xmpp.example.com. IN TLSA 3 1 1 <sha256-of-cert-spki>
```

## DNS Records

Minimal DNS for XMPP:

```
; A record for the XMPP domain
example.com.          IN A     203.0.113.1

; SRV records (clients use these to find the server)
_xmpp-client._tcp.example.com. 3600 IN SRV 0 5 5222 xmpp.example.com.
_xmpp-server._tcp.example.com. 3600 IN SRV 0 5 5269 xmpp.example.com.

; DANE/TLSA (optional but recommended for S2S)
_5222._tcp.xmpp.example.com. IN TLSA 3 1 1 <hash>
_5269._tcp.xmpp.example.com. IN TLSA 3 1 1 <hash>
```

## Jail Deployment

Recommended: run xmppd in a FreeBSD jail for isolation.

```sh
# Create jail (example using classic jails)
jail -c name=xmppd path=/usr/local/jails/xmppd ip4=inherit persist

# Install in jail
pkg -j xmppd install xmppd

# Copy TLS certs into jail
cp /path/to/cert.pem /usr/local/jails/xmppd/usr/local/etc/xmppd/server.pem
cp /path/to/key.pem /usr/local/jails/xmppd/usr/local/etc/xmppd/server.key

# Configure inside jail
jexec xmppd vi /usr/local/etc/xmppd/xmppd.conf

# Create users
jexec xmppd xmppctl adduser alice
jexec xmppd xmppctl adduser bob

# Start
jexec xmppd service xmppd start
```

## OIDC Authentication

To authenticate against an external Identity Provider (e.g., Rauthy, Keycloak):

1. Change `auth_path` to `xmppd-auth-oidc`
2. Add `[oidc]` section with IdP details
3. Set `user_domain` if the IdP uses email-style usernames

See `doc/CONFIGURATION.md` for the full `[oidc]` reference.

**Note:** OIDC uses PLAIN→ROPC delegation. MFA-enabled IdP accounts cannot
authenticate via XMPP (ROPC doesn't support second factors). Use app-specific
passwords or disable MFA for XMPP users.

## User Management

```sh
xmppctl adduser alice            # Interactive password prompt
xmppctl adduser bob --password secret123
xmppctl passwd alice             # Change password
xmppctl deluser charlie          # Delete account + cleanup
xmppctl listusers                # List all local users
xmppctl lock alice               # Permanent account lock
xmppctl unlock alice             # Remove lock
xmppctl invite create            # Generate registration code
```

## Monitoring

- **Log file:** `/var/log/xmppd/xmppd.log` (when `log_file` is set or daemonized)
- **PID file:** `/var/run/xmppd/xmppd.pid`
- **Service status:** `service xmppd status`

## Firewall

Open ports:
- **5222/tcp** — C2S (client connections)
- **5269/tcp** — S2S (federation, if enabled)
