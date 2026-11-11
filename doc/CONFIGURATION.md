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
| `rate_limit` | `true` | Authentication rate limiting master switch; `false` disables it entirely (testing/benchmarks only) |
| `max_per_account` | `60` | Max auth attempts per account per window |
| `max_per_ip` | `200` | Max auth attempts per IP per window |
| `window_seconds` | `120` | Rate window size |
| `lockout_duration` | `300` | Temporary lockout length in seconds |
| `lockout_threshold` | `10` | Consecutive account failures before temporary lockout |
| `ip_lockout_threshold` | `20` | Consecutive IP failures before that address is temporarily locked |
| `registration` | `false` | In-band registration (XEP-0077) |
| `require_invite` | `true` | Require invitation code for registration |

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
| `import_avatar` | no | Import IdP `picture` claim into vCard on first login (`true`/`false`, default `false`) |
| `localpart_claim` | no | Claim supplying the first-login localpart suggestion: `preferred_username` (default), `email`, `sub`, or empty string to disable auto-provisioning |
| `localpart_claim_prefix` | no | Prefix stripped from the suggestion claim before PRECIS preparation (e.g., `user:` for identity-oidc handle-form subjects) |
| `localpart_auto_suffix` | no | When the suggested localpart is taken, try `lp-2` .. `lp-99` (`true`/`false`, default `false`: a taken suggestion is refused, never silently suffixed) |

#### Account binding

XMPP accounts bind permanently to the `(iss, sub)` pair (OIDC Core 5.7):
once a subject logs in, its mapping in `{db}/auth` (`oidc_identities`
namespace) decides the account forever, and renamed IdP claims cannot
re-map it. The `localpart_claim` value is only a first-login
*suggestion*: it never binds identity. The suggestion is prepared with
the same RFC 7622 UsernameCaseMapped localpart function as registration
(`NaplesTB` suggests `naplestb`), so two different claims that prepare to
one localpart collide and the second is refused. A suggestion is refused
when the localpart is already bound to another subject, when a provisioned
`users` row exists, or when the account already owns roster, archive or
MUC data (upgrade installs must run `xmppctl oidc-unclaimed` and
`oidc-link` first; see UPGRADING.md). `localpart_claim = email` is
accepted only when the IdP reports `email_verified = true` and is the
weakest choice because email is editable at most IdPs. Setting
`localpart_claim` to an empty string disables auto-provisioning
entirely: every account then needs an explicit `xmppctl oidc-link`.
Local registration runs the reverse index too: XEP-0077 registration and
`xmppctl add` refuse a localpart bound to a subject (`conflict`, and a
bound-localpart error at the ctl) instead of attaching a password
credential to the bound account.

| IdP | Recommended keys | Notes |
|-----|------------------|-------|
| identity-oidc | `localpart_claim = sub`, `localpart_claim_prefix = user:` | While subject IDs are handle-form (`user:name`), strip the prefix. After identityd issue #52 lands opaque subjects, use an admin-controlled preferred username instead. |
| Rauthy | `localpart_claim = preferred_username` | Safe only with immutable usernames and controlled provisioning. `email` is unsafe: it is user-editable and `email_fallback` makes it self-selected. |
| Keycloak | `localpart_claim = preferred_username` | Safe only when username edits are forbidden and provisioning is controlled. Otherwise use `localpart_claim =` (empty) plus operator links. |

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

- `--background` / `-b` - daemonize (fork + setsid)
- `--help` / `-h` - usage

`xmppctl` accepts:
- `--db PATH` - database directory
- `--auth-socket PATH` - auth daemon IPC socket (tries IPC first, falls back to direct DB)
- `--password VALUE` - non-interactive password
- `--password-file PATH` - read password from file
