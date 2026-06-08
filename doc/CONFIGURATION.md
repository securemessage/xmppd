# xmppd Configuration

All configuration lives in a single INI file (default: `/usr/local/etc/xmppd/xmppd.conf`).
CLI flags override config file values. Sensible defaults allow running without a config file
in development mode.

## Sections

### [server]

| Key | Default | Description |
|-----|---------|-------------|
| `hostname` | (required) | XMPP domain (e.g., `example.com`) |
| `bind_address` | `0.0.0.0` | Listen address |
| `c2s_port` | `5222` | Client-to-server port |
| `user` | (none) | Drop privileges to this user (children only) |
| `db_path` | `/var/db/xmppd` | Database directory |
| `log_file` | (none) | Log file path (stderr if unset) |

### [tls]

| Key | Default | Description |
|-----|---------|-------------|
| `cert` | (required) | TLS certificate path (PEM, full chain) |
| `key` | (required) | TLS private key path (PEM) |

### [core]

| Key | Default | Description |
|-----|---------|-------------|
| `max_sessions` | `4096` | Maximum concurrent C2S sessions |
| `fan_out_batch_size` | `32` | MUC fan-out yield threshold |

### [auth]

| Key | Default | Description |
|-----|---------|-------------|
| `socket` | `/var/run/xmppd/auth.sock` | IPC socket path |

### [muc]

| Key | Default | Description |
|-----|---------|-------------|
| `host` | `conference.{hostname}` | MUC service domain |

### [master]

| Key | Default | Description |
|-----|---------|-------------|
| `core_path` | `/usr/local/libexec/xmppd/xmppd-core` | Core binary path |
| `auth_path` | `/usr/local/libexec/xmppd/xmppd-auth` | Auth binary path (or `xmppd-auth-oidc`) |
| `s2s_path` | `/usr/local/libexec/xmppd/xmppd-s2s` | S2S federation binary path |

### [oidc] (when using xmppd-auth-oidc)

| Key | Required | Description |
|-----|----------|-------------|
| `issuer` | yes | OIDC issuer URL (must match token `iss` claim) |
| `client_id` | yes | OAuth2 client ID |
| `client_secret` | yes | OAuth2 client secret |
| `token_endpoint` | yes | Token endpoint URL (for ROPC) |
| `jwks_uri` | yes | JWKS endpoint URL (for JWT key fetching) |
| `introspection_endpoint` | no | RFC 7662 introspection (for opaque tokens) |
| `ca_file` | no | CA bundle path for IdP TLS verification |
| `user_domain` | no | Domain appended to bare usernames for ROPC (e.g., `morante.dev`) |

## Example

```ini
[server]
hostname = example.com
user = jabber
db_path = /var/db/xmppd
log_file = /var/log/xmppd/xmppd.log

[tls]
cert = /usr/local/etc/xmppd/fullchain.pem
key = /usr/local/etc/xmppd/privkey.pem

[core]
max_sessions = 4096

[muc]
host = conference.example.com

[master]
core_path = /usr/local/libexec/xmppd/xmppd-core
auth_path = /usr/local/libexec/xmppd/xmppd-auth
```

## OIDC Example

```ini
[master]
auth_path = /usr/local/libexec/xmppd/xmppd-auth-oidc

[oidc]
issuer = https://auth.example.com/auth/v1/
client_id = xmppd
client_secret = your-client-secret
token_endpoint = https://auth.example.com/auth/v1/oidc/token
jwks_uri = https://auth.example.com/auth/v1/oidc/certs
user_domain = example.com
ca_file = /usr/local/etc/xmppd/ca-bundle.pem
```

## CLI Flags

All binaries accept `--config PATH` to specify the config file location.
The master additionally accepts:

- `--background` / `-b` — daemonize (fork + setsid)
- `--help` / `-h` — usage

`xmppctl` accepts:
- `--db PATH` — database directory
- `--auth-socket PATH` — auth daemon IPC socket (tries IPC first, falls back to direct DB)
- `--password VALUE` — non-interactive password
- `--password-file PATH` — read password from file
