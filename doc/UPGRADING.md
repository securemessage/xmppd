# Upgrading

## 0.9.0 -> 0.9.1: OIDC account binding

v0.9.1 changes how `xmppd-auth-oidc` maps IdP identities to XMPP
accounts. Accounts now bind permanently to the `(iss, sub)` pair; the
first login of a new subject only *suggests* a localpart and is refused
whenever the localpart is already bound to another subject, has a
provisioned `users` row, or already owns account data (roster, offline
queue, vCard, PEP, blocklist, pending subscriptions, MUC affiliations,
MAM archive).

**This matters on any install where accounts already exist.** A first
login that would previously have walked into an existing account is now
refused instead of claimed, and the log says so:

```
oidc: refusing auto-claim of 'alice': existing account data found; use xmppctl oidc-link
```

### Migration procedure

1. Stop `xmppd-auth-oidc` (the rest of the stack may stay up).
2. Install the v0.9.1 binaries.
3. Run discovery: `xmppctl oidc-unclaimed` lists every localpart that
   owns data but has no OIDC binding yet.
4. For each localpart, either
   - link it to the right subject: `xmppctl oidc-link <localpart> <iss> <sub>`, or
   - prepare a file of `localpart <iss> <sub>` lines and run
     `xmppctl oidc-link-import <file>`.
5. Start `xmppd-auth-oidc`. New subjects self-provision on first login;
   linked subjects land on their existing accounts.
6. `xmppctl oidc-links` lists all bindings;
   `xmppctl oidc-unlink <localpart>` removes one.

### Config keys

- `localpart_claim` (default `preferred_username`): which claim suggests
  the localpart on first login. `sub` is valid (e.g. identity-oidc while
  its subject IDs are handle-form, with `localpart_claim_prefix =
  user:`). Empty string disables auto-provisioning entirely.
- `localpart_claim_prefix`: prefix stripped from the suggestion before
  preparation. The suggestion is prepared with the same RFC 7622
  localpart function as account names, so spellings that fold together
  collide and lose.
- `localpart_auto_suffix` (default `false`): `true` allows `lp-2` ..
  `lp-99` when the suggestion is taken.
- `email` is accepted only when the IdP reports `email_verified = true`
  and is the weakest suggestion source.

If you previously relied on `username_claim`, it no longer exists;
`localpart_claim` is the replacement.

### Storage backend

First-login binding claims a localpart through a conditional write that
must hold across every process on `{db}/auth`. RocksDB serializes that
check inside the process only, so `xmppd-auth-oidc` now refuses to start
when the operational storage backend is RocksDB. OIDC requires
`-Dop-storage=lmdb` (the default) or `-Dop-storage=sqlite`.

## 0.9.0 -> 0.9.1: strict master configuration

The master (`xmppd`) now parses the configuration file through the shared
strict loader before it starts children. A file that started v0.9.0 can
fail v0.9.1:

- an unknown section or key, a bad value or a malformed line is a startup
  error printed as `conf:LINE: [section] key 'name': ...` and the master
  exits non-zero (v0.9.0 ignored these or silently defaulted them);
- `[s2s] enabled = false` in the file now suppresses the s2s child
  (v0.9.0 read only the `--no-s2s` flag; the file key was ignored); and
- `[core] workers` accepts a number or `auto`; any other value is a
  startup error (v0.9.0 treated it as `auto`).

Pre-flight check before restarting:

    xmppd -c /path/to/xmppd.conf --help

Exit status 0 with the generated option list on stdout means the file
parses and every key is known. Exit status 1 with a `file:line`
diagnostic on stderr names the first problem; fix it and rerun. `--help`
prints and exits before any child is spawned, so the check is safe
against a running install.

## 0.9.0 -> 0.9.1: shared loader for core, s2s and xmppctl

`xmppd-core`, `xmppd-s2s` and `xmppctl` now load configuration through
the same strict loader as the master. Supervised core and s2s children
no longer receive resolved values on their argv: the master serializes
the resolved configuration once into a sealed in-memory fd passed as
`--conf-fd N`, so file keys and master CLI overrides reach a child
exactly once. Their argv now carries only what the file grammar cannot
express: the inherited listen-fd remap slots and the conf-fd slot
itself. On SIGHUP the master rebuilds the fd before forwarding the
signal; children never re-read the file. A core or s2s started by hand
without `--conf-fd` reads its `--config` file directly, with precedence
default < file < CLI, exactly as a supervised child does with the
forwarded values in between.

Behavior changes that ride along:

- `xmppd-core` honors `[tls] cert` and `[tls] key` from the file;
  v0.9.0's core ignored the file's TLS keys and only `--cert`/`--key`
  reached it.
- `xmppd-s2s --config PATH` is honored; v0.9.0 consumed the flag and
  ignored the file. Unknown s2s arguments changed from a logged warning
  to a startup error.
- `xmppctl` accepts `-c`/`--config` and reads the shared file, so
  `[server] db_path` and `[auth] socket` apply to it. Unknown options are startup errors (v0.9.0 treated an
  unrecognized argument as the command name), `--max-uses` and
  `--expires` are ordinary options accepted in any position instead of
  only after `invite create`, unknown arguments to `invite create` are
  errors instead of being ignored, and `--help` prints usage and exits
  0. Without `--db` or a config file, the storage directory default is the
  shared `[server] db_path` default `/var/db/xmppd`.

## 0.9.0 -> 0.9.1: strict auth daemon configuration

`xmppd-auth` and `xmppd-auth-oidc` now use the shared typed loader and
receive the master's sealed configuration fd as `--conf-fd N`. The master
no longer passes resolved database, socket or other file values on their
argv. Precedence is default < file < forwarded < CLI for both daemons.
Standalone runs still accept `--config`; standalone OIDC retains its
default `/usr/local/etc/xmppd/xmppd.conf` path.

**Bad auth values are now startup errors.** Non-numeric values, integers
outside their target type, rate maxima above 65535, a zero rate window,
invalid IdP pool bounds, and lockouts that are not whole seconds refuse
startup instead of silently falling back to a default or being clamped.
File errors include `file:line` and the key. Unknown arguments and unknown
file keys are errors too. Existing `[oidc] rate_max_per_account` and
`rate_max_per_ip` spellings remain accepted as aliases.

Both `--help` outputs are generated from the schema and include every
accepted CLI spelling and the actual defaults. The shared storage default
stays `/var/db/xmppd`, and `auth.crypto_threads` defaults to `4` (`0`
disables the pool). An unset `[oidc] socket` inherits `[auth] socket`;
an explicit OIDC socket or child `--socket` overrides it.
