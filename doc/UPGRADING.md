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
