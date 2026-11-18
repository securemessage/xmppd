# xmppd Configuration

All configuration lives in a single INI file shared by every daemon, selected
with `--config PATH` (`-c`). `xmppd-auth-oidc` defaults to
`/usr/local/etc/xmppd/xmppd.conf` when `--config` is absent. Precedence is
default < file < CLI, tracked per field, with the master's resolved values
forwarded to its children in between (see "Config forwarding" below). An
unknown section or key, a bad value, or a malformed line is a startup error
that names the file and line; defaults live only in the schema
(`src/config/schema.zig`), so `xmppd --help` is the authoritative option
list.

## Sections

### [server]

| Key | Default | Description |
|-----|---------|-------------|
| `hostname` | `localhost` | XMPP domain (e.g., `example.com`) |
| `bind_address` | `0.0.0.0` | Listen address literal (C2S; also S2S unless `s2s.bind_address` is set) |
| `c2s_port` | `5222` | Client-to-server port |
| `db_path` | `/var/db/xmppd/users.db` | User database path; the master also creates `auth/`, `op/`, `archive/` subdirectories under it |
| `lmdb_map_size_mb` | `8192` | LMDB map size in MiB |
| `user` | (none) | Unprivileged user the master's children run as (required when the master runs as root) |
| `log_file` | `/var/log/xmppd/xmppd.log` | Log file path (used with `--background`) |
| `pidfile` | `/var/run/xmppd/xmppd.pid` | PID file path |

### [tls]

| Key | Default | Description |
|-----|---------|-------------|
| `cert` | (none) | TLS certificate path (PEM, full chain) |
| `key` | (none) | TLS private key path (PEM) |
| `enabled` | `true` | Enable STARTTLS |

### [core]

| Key | Default | Description |
|-----|---------|-------------|
| `max_sessions` | `4096` | Maximum concurrent C2S sessions |
| `fan_out_batch_size` | `32` | MUC fan-out yield threshold |
| `max_resources_per_account` | `256` | Maximum resources per account |
| `workers` | `auto` | Worker threads (`auto` = CPU count) |
| `log_level` | `info` | Log verbosity (`debug`, `info`, `warn`, `err`) |

### [auth]

| Key | Default | Description |
|-----|---------|-------------|
| `socket` | `/var/run/xmppd/auth.sock` | IPC socket path |
| `rate_limit` | `true` | Authentication rate limiting master switch; `false` disables it entirely (testing/benchmarks only) |
| `max_per_account` | `60` | Max auth attempts per account per window (alias `rate_max_per_account`) |
| `max_per_ip` | `200` | Max auth attempts per IP per window (alias `rate_max_per_ip`) |
| `window_seconds` | `120` | Rate window size |
| `lockout_duration` | `5m` | Temporary lockout (`300`, `300s` and `5m` are equivalent) |
| `lockout_threshold` | `10` | Consecutive account failures before temporary lockout |
| `ip_lockout_threshold` | `20` | Consecutive IP failures before that address is temporarily locked |
| `users_scan_limit` | `100000` | Startup users scan bound |
| `crypto_threads` | `0` | Password hash threads |
| `registration` | `false` | In-band registration (XEP-0077) |
| `require_invite` | `true` | Require invitation code for registration |

### [s2s]

| Key | Default | Description |
|-----|---------|-------------|
| `socket` | `/var/run/xmppd/s2s.sock` | IPC socket path |
| `port` | `5269` | S2S listening port |
| `enabled` | `true` | Enable s2s federation |
| `bind_address` | (follows `server.bind_address`) | S2S listen address literal |

### [muc]

| Key | Default | Description |
|-----|---------|-------------|
| `host` | `conference.{hostname}` | MUC service domain |

### [master]

| Key | Default | Description |
|-----|---------|-------------|
| `core_path` | `xmppd-core` | Core binary path |
| `auth_path` | `xmppd-auth` | Auth binary path (or `xmppd-auth-oidc`) |
| `s2s_path` | `xmppd-s2s` | S2S federation binary path |

`run_dir` and `background` are CLI-only: a `[master]` file key naming either
is an unknown-key error.

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
| `socket` | no | IPC socket path (default `/var/run/xmppd/oidc.sock`) |
| `max_per_account` | no | Max requests per account (default `60`, alias `rate_max_per_account`) |
| `max_per_ip` | no | Max requests per IP (default `200`, alias `rate_max_per_ip`) |
| `rate_limit` | no | Rate limiting switch (default `true`) |
| `import_avatar` | no | Import IdP `picture` claim into vCard on first login (`true`/`false`, default `false`) |
| `idp_threads` | no | IdP HTTP client threads (default `8`) |
| `idp_max_outstanding` | no | Max in-flight IdP requests (default `256`) |
| `idp_connect_timeout_ms` | no | IdP connect timeout (default `3000`) |
| `idp_timeout_ms` | no | IdP request timeout (default `10000`) |
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

Claiming a localpart is a conditional write that must hold against every
process that can open `{db}/auth` (`xmppd-auth-oidc`, the core daemon,
`xmppctl`, and any second auth daemon). Only the LMDB and SQLite
backends serialize that check across processes; RocksDB orders
`putIfAbsent` with an in-process mutex, so `xmppd-auth-oidc` refuses to
start when the operational storage backend is RocksDB. OIDC account
binding requires `-Dop-storage=lmdb` (the default) or
`-Dop-storage=sqlite`.

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

All binaries accept `--config PATH` (`-c`) to specify the config file
location. `xmppd --help` prints the generated list below; it is produced
from the schema, so it cannot drift from what the parser accepts:

```
  --host <HOST>           XMPP server hostname
  --port <PORT>           c2s listen port
  --bind <BIND>           c2s/s2s listen address literal
  --cert <CERT>           TLS certificate file (PEM)
  --key <KEY>             TLS private key file (PEM)
  --core-path <CORE-PATH> path to xmppd-core
  --auth-path <AUTH-PATH> path to xmppd-auth
  --s2s-path <S2S-PATH>   path to xmppd-s2s
  --no-s2s                disable s2s federation
  --auth-socket <AUTH-SOCKET> auth IPC socket path
  --db <DB>               user database path
  --config, -c <CONFIG>   config file path (passed to children)
  --log-file <LOG-FILE>   log file path (--background)
  --run-dir <RUN-DIR>     runtime dir for pid files
  --background, -b        daemonize (fork, detach from terminal)
  --version, -v           print version and exit
  --help, -h              show this help
```

## Config forwarding

The master forwards the *resolved* values to its children. After loading
the file and its own CLI it serializes the effective fields once into a
sealed in-memory fd that `xmppd-core` and `xmppd-s2s` inherit through
the supervisor's `pass_fds` remap, named on their argv as `--conf-fd N`.
Their precedence is therefore default < file < forwarded < CLI: a file
key or a master CLI flag (`xmppd -c xmppd.conf --host x.test`) reaches
every child exactly once, and a child-side CLI flag still wins for a
manual run. The child argv carries only what the file grammar cannot
express: the inherited listen-fd remap slots (`--listen-fd`) and the
conf-fd slot itself. `xmppd-auth` still receives its resolved values on
argv until it moves to the same loader. A core or s2s started by hand
without `--conf-fd` reads `--config` directly. On SIGHUP the master
rebuilds the fd from the reloaded configuration before forwarding the
signal, so a respawned child sees the new values; no child re-reads the
file.

`xmppctl` accepts:
- `-c`, `--config PATH` - read the shared config file
- `--db PATH` - database directory (default: the shared `[server] db_path`)
- `--auth-socket PATH` - auth daemon IPC socket (tries IPC first, falls back to direct DB)
- `--password VALUE` - non-interactive password
- `--password-file PATH` - read password from file
