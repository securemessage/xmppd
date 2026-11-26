# A5: protocol v2, stateless SCRAM verify (ADR-6)

Status: decided per ADR-6; this note fixes the wire layouts, cache bounds and
the scale litmus. T272, T279, T308, T327, V4, V6.

## 1. Protocol v2 flow

Today SCRAM-SHA-256 costs two IPC round trips and one row of daemon state per
in-flight exchange (the 8192-slot `scram_sessions` table keyed by
(lane, conn_id), with the T279 lane-close sweep and the 60 s stale probe).

v2 makes SCRAM a one-round-trip exchange like PLAIN:

1. Client `<auth mechanism='SCRAM-SHA-256'>` with client-first-message.
   Core decodes the payload, splits the gs2 header, reads `n=` and `r=` out of
   client-first-message-bare, and looks up `(salt, iterations)` in its
   per-worker SCRAM parameter cache keyed by the raw `n=` name.
   - Hit (and unexpired): core builds server-first itself: a fresh 24-byte
     server nonce, base64'd and appended to the client nonce,
     `r=<combined>,s=<salt-b64>,i=<iterations>`. It sends `<challenge>` and
     parks {client-first-bare, server-first, raw n= name} in a per-worker
     exchange slot (section 7).
   - Miss or expired: core sends `scram_params_request` and parks the session
     in `awaiting_params`. On `scram_params` it caches the pair, builds
     server-first, sends `<challenge>`, same as above.
2. Client `<response>` with client-final-message. Core sends one
   `scram_verify` and parks the session in `awaiting_result`.
3. Auth daemon parses all three wire messages back out of the frame,
   checks nonce and parameters, runs `policy.admit`, verifies the proof
   against StoredKey, records the outcome, inserts the server nonce into the
   replay cache, and replies `auth_success` (server_final `v=<b64 sig>`) or
   `auth_failure`. It holds nothing for the exchange afterwards.
4. PLAIN and OAUTHBEARER are untouched: still `auth_request`, one round trip.

Session correlation is the existing `conn_id` (gen<<16 | slot) plus
`auth_ipc_gen`; `auth_abort` still arrives on connection death and simply has
nothing to delete.

## 2. Wire messages (comptime codec)

Fields encode in declaration order: u8/bool/enum(u8) = 1 B, u32 = 4 B LE,
[]const u8 = u16 LE len + bytes. Tags take the next free auth slots; s2s stays
at 0x10 and up.

```zig
pub const Tag = enum(u8) {
    // ... 0x01-0x0D unchanged ...
    scram_params_request = 0x0E, // Core->Auth
    scram_params         = 0x0F, // Auth->Core
    // 0x10-0x12 s2s (unchanged)
    scram_verify         = 0x13, // Core->Auth
    scram_stale          = 0x14, // Auth->Core
};

pub const ScramParamsRequest = struct {
    conn_id: u32,
    /// Raw n= name from client-first-bare (the daemon applies precis).
    username: []const u8,
    /// Client IP for the lock check (not counted; see section 4).
    client_ip: []const u8,
};

pub const ScramParams = struct {
    conn_id: u32,
    /// Binary salt (32 B today). Public: any client that starts SCRAM
    /// sees it in server-first, so it crosses IPC in the clear by design.
    salt: []const u8,
    iteration_count: u32,
    /// No "user exists" flag: unknown users get the deterministic fake of
    /// section 5, so the reply shape never reveals an account.
};

pub const ScramVerify = struct {
    conn_id: u32,
    client_ip: []const u8,
    /// Same pair AuthRequest carries today (0=none, 1=tls-server-end-point,
    /// 2=tls-exporter).
    cb_type: u8,
    cb_data: []const u8,
    /// client-first-message-bare: "n=<raw>,r=<cnonce>[,extensions]"
    client_first_bare: []const u8,
    /// gs2 channel binding flag from client-first ('n', 'y' or 'p'). Core
    /// reads it while splitting bare. It must travel separately: taking the
    /// flag from the client-final's own c= field would let a client offer
    /// 'p' in client-first and then authenticate with an 'n' binding, a
    /// channel-binding downgrade.
    gs2_flag: u8,
    /// The exact server-first-message core sent: "r=<combined>,s=<b64>,i=<n>"
    server_first: []const u8,
    /// The full client-final-message: "c=<b64>,r=<combined>,p=<b64>"
    client_final: []const u8,
};
```

`scram_verify` answers reuse `auth_success`/`auth_failure` (`server_final`
carries `v=<b64 ServerSignature>`) plus `scram_stale`: when the
client-bound server-first (salt, iterations) no longer matches the stored
credentials, the daemon replies `scram_stale{conn_id, username}` instead of
a password failure; the core evicts its params-cache entry for that name,
fails the attempt with temporary-auth-failure so the client's retry
re-fetches, and counts `scram_stale`. `sasl_response` and `auth_challenge`
become dead tags once v2 is the only SCRAM path; they stay reserved (the wire
contract is versioned as a whole) but their handlers and the union members
are deleted with the session table.

## 3. Daemon-side verify (`mech/scram.zig`, allocation-free)

`handleScramVerify` runs entirely on the loop: the crypto is two HMAC-SHA-256
and one SHA-256 over ~1 KiB, a few microseconds; no PBKDF2 (StoredKey and
ServerKey are already derived). Order of checks mirrors v1 so outcome
reasons stay identical:

1. Parse client-first-bare: `n=` and `r=` out of the bare; malformed ->
   `invalid_encoding`. `gs2_flag` must be 'n', 'y' or 'p' (the same check
   handleClientFirst does today); the decoded `c=` gs2 header is then
   cross-checked against it exactly as validateChannelBinding does, and a
   `p` exchange with `cb_type=0` or empty `cb_data` fails
   `ChannelBindingMismatch`.
2. `localpart()` the raw name; unpreparable -> `not_authorized` (same as v1).
3. `policy.admit(account, client_ip)`: one admission per exchange, counting
   IP and account once. Denial -> its FailureReason.
4. Parse server-first: `r=<combined>`, `s=`, `i=`. `combined` must start with
   the client nonce from step 1; the remainder is the server nonce. Salt and
   iterations must equal the looked-up credentials (real or fake) so a stale
   or forged server-first can never be signed. A salt/iteration mismatch
   answers `scram_stale` (section 2) rather than `not_authorized`.
5. Nonce freshness: the server nonce carries the core's issue time
   (`b64(u64 unix seconds || 18 random bytes)`); the daemon refuses a nonce
   older than the replay window or beyond clock-skew ahead. The timestamp
   sits inside server-first, which the client proof covers, so a replayer
   cannot refresh it. Across a verifier restart the replay table is empty,
   so a nonce issued through verifier-start + skew inclusive is also
   refused: the startup second is ambiguous and a pre-restart nonce can be
   future-dated up to that bound. The client must restart with a later
   challenge.
6. Replay cache: server nonce present and unexpired -> `not_authorized`.
7. Parse client-final: `c=` channel binding per the v1 rules, `r=` must equal
   `combined`, `p=` decodes the proof. AuthMessage =
   bare + "," + server-first + "," + client-final-without-proof.
   HMAC verify vs StoredKey (timing-safe); failure -> recordOutcome +
   `not_authorized`.
8. Insert the server nonce into the replay cache (consumed either way once
   the exchange verifies as well-formed), recordOutcome, reply auth_success
   with `v=<b64 HMAC(ServerKey, AuthMessage)>`.

Credential lookup reuses the daemon cred cache + `store.lookup` exactly as
today. Unknown user: the fake credentials of section 5, so the verify runs
the same work and fails with the same `not_authorized` as a wrong password.

## 4. `scram_params` handler

- `policy.check("", client_ip)` only: a non-counting lock check so a locked
  IP is refused without spending an admission on what is only a public-data
  read. The real admission is `scram_verify`'s `policy.admit`.
- Store hit: `{salt, iteration_count}` from the credentials.
- Store miss: the deterministic fake of section 5.
- Store error: `auth_failure` `temporary-auth-failure` (v1 semantics).

## 5. Deterministic fakes (no user enumeration)

The daemon generates one 32-byte secret on first start and persists it in
`{db}/auth/scram_secret` (0600, `secureZero` on teardown), so a fake salt is
as stable across restarts as a real one. Publication is atomic and durable:
write and fsync a unique temporary file, link it into place, then fsync the
directory. A corrupt published file is left untouched and fails startup for
offline repair; it is never unlinked or replaced, even when startups race.
For an unknown user `u`:

```
salt        = HMAC(secret, "a5-scram-salt"   | u)
stored_key  = HMAC(secret, "a5-scram-stored" | u)
server_key  = HMAC(secret, "a5-scram-server" | u)
iterations  = sasl.default_iteration_count  // the one constant password-set uses
```

Same secret + same name -> same fake, so repeated probes cannot tell a
missing account from a real one, and the server-first shape (salt length,
iteration count, nonce format) is identical. The verify path runs the same
HMAC work against the fake keys and fails the proof check, matching the
wrong-password outcome byte for byte.

## 6. Replay cache (daemon)

Fixed-capacity open-addressed table, no timer, sized from configuration:
the capacity derives from the configured login-rate ceiling times the
nonce freshness window, so a full table means the rate limit was already
exceeded, not that nonces expired early.

- The tag is HMAC(scram_secret, nonce) truncated to 16 B, so an attacker
  cannot steer inserts into one probe window; the daemon-side secret is
  drawn at init.
- Freshness is covered by the proof: the server nonce embeds the core's
  issue time (see step 5 of the verify), so the daemon refuses nonces
  outside [now - window, now + skew] and a replayer cannot mint a fresh
  timestamp without invalidating the client proof.
- Insert: hash the tag, linear probe up to 8 slots, take the first free or
  expired slot. Expiry is the nonce's issue second + window inclusive, so
  the tag outlives the whole freshness interval including forward skew. If
  all 8 are live the verify is REFUSED with temporary-auth-failure, counted:
  a live tag is never evicted, so a nonce reads as seen for its whole window.
- Lookup: an expired entry counts as absent and is reclaimed in place.
- Occupancy moves `metrics.scramActivated`/`scramReleased`-style high water
  (the A1 counter block gains a replay-cache high water in place of the
  session-table one).

This is the anti-replay guarantee ADR-6 asks for: any second client-final
carrying an already-consumed server nonce is refused inside the nonce's
lifetime. Cross-lane uniqueness is automatic because nonces are random, not
per-lane.

## 7. Core-side caches and state

Parameter cache (per worker, no atomics):

- Direct-mapped 1024-entry table keyed by Wyhash of the raw `n=` name:
  {hash, name[256], salt[32], iterations, fetched_at}. TTL 300 s checked at
  use; a stale or wrong entry cannot sign anyway (step 4 of the verify), so
  overwrite on collision is safe. The name is stored so a hash collision can
  never serve the wrong params.

Parked exchange state (per worker, bounded):

- Sessions carry no inline exchange buffers. The ~2 KiB of exchange state
  (gs2 flag, raw n= name, bare client-first, client nonce, pending
  server-first, channel binding) parks in a per-worker `ScramExchangePool`
  (`scram_exchange.zig`): sessions hold a generation-checked token
  (gen<<16|slot) into `core.scram_exchange_slots` (default 256) slots,
  acquire reuses a live slot on retry, and lifecycle teardown returns it.
  A full pool answers temporary-auth-failure and counts
  `scram_exchange_full`.
- The params-cache TTL handles most staleness; a password change inside it
  is caught at verify time by the salt/iteration check and answered
  `scram_stale`, which evicts the entry so the retry re-fetches.
- New `AuthState` values `awaiting_params`, `awaiting_client_final` (the
  challenge is now sent by core, so `awaiting_challenge` becomes unused for
  SCRAM; PLAIN/OAUTHBEARER keep `awaiting_result` via `auth_request`).

## 8. Section 0 scale litmus (auth pipeline)

1. Execution model: thread-per-core on the core side; the auth daemon stays
   one process per the ADR-6 decision (A7 per-lane auth threads is the
   scheduled follow-up only if re-measure still shows the daemon as the
   limit). Every reply correlates by conn_id, so the design already fits the
   multi-lane model.
2. Linear scaling: v2 deletes the daemon's last per-connection table; the
   replay cache is single-writer (loop thread), bounded, lock-free by
   ownership. Core parameter cache is per worker. No shared atomics added.
3. Shared resources: the credential store is read through the existing
   cache + read path; scram_verify does one lookup per exchange, same as v1,
   and zero on a cred-cache hit.
4. Nothing blocks a loop: verify is ~us of HMAC on the loop; PBKDF2 remains
   on the crypto pool for PLAIN/register/passwd; LMDB reads are page-cache
   reads on the same footing as today.
5. Connection economics: no per-session exchange fields at all (a u32
   token); the worker pre-allocates the slot pool once
   (~2.1 KiB x scram_exchange_slots) and the daemon drops
   ~8192 x sizeof(ScramSession) of table.
6. Many requests per connection: IPC frames are independent and correlated;
   scram_verify interleaves freely on a lane.
7. Beyond one host: unchanged; the daemon stays unix-socket-local per the
   architecture (core and auth are co-hosted by design).
8. Expensive operations priced: verify cost is bounded and measured (A1 pool
   histogram + counters); admission control is policy.admit, unchanged.
9. Overload: every table bounded; replay-cache eviction policy keeps inserts
   O(1); a full table degrades to evicting old nonces, never to blocking.
10. Measured: LG10k re-measure on this branch vs master is part of the
    deliverable (same rig as A1).

## 9. Deletions

- `scram_sessions` table (8192 ScramSession), `findOrCreateScramSlot`,
  `findScramSlot`, `cleanupSession`, `closeLaneSessions`, the stale probe.
- `handleScramInit`, `handleSaslResponse`, the `sasl_response` and
  `auth_challenge` union members and tags' handlers.
- `ScramServer`'s arena path on the server side is replaced by a
  non-allocating verify (the client side `ScramClient` is untouched; s2s and
  xmppc still use it).

## 10. Tests (each fails when its change is reverted)

- RFC 7677 SCRAM-SHA-256 exchange through the v2 path against the published
  test vector.
- A replayed client-final (same server nonce twice) is refused; a nonce
  replayed after the window is refused on freshness, and a future-dated
  nonce beyond skew is refused. Restart-floor tests cover a stamp equal to
  verifier startup and a future-dated stamp at the skew boundary, with a
  post-cutoff control succeeding in both.
- A full probe window refuses the verify with temporary-auth-failure rather
  than evicting a live tag, and the original nonce still reads as seen.
- An unknown user's scram_params reply is indistinguishable in shape from a
  known user's and deterministic across lookups; the advertised iteration
  count matches what password-set derives for real accounts, and the fake
  secret is stable across daemon restarts. Concurrent starters publish one
  secret; a corrupt published secret fails startup and remains in place for
  offline repair.
- gs2 `p` with mismatched channel-binding data fails.
- A password change between cached params and verify answers scram_stale,
  the core evicts its cache entry, and the next attempt succeeds.
- A full exchange pool refuses acquire with temporary-auth-failure, and the
  slot is released after the verify sends.
- After a scram_verify reply the handler exposes no per-exchange state
  (replay cache excepted): verified by the removed table plus a state probe.
