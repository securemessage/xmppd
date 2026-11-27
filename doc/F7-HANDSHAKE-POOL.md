# F7: process-shared TLS context and handshake pool

Plan reference: T197/F7, ADR-11 approved as option B. This note is the design record for the lib/net TLS handshake pool and the core c2s adoption. Its scope is STARTTLS on c2s. X1 will reuse the same pool for outbound s2s and DANE work.

## 0. Scale litmus

1. **Execution model.** xmppd-core is thread per worker. Every worker owns one legacy kqueue loop for established sessions. The handshake pool adds N dedicated threads. Each pool thread owns one lib/net Loop and therefore one kqueue. Worker loops never execute `SSL_do_handshake` in production.
2. **Linear scaling.** Workers scale established-session I/O by listener count. Handshake CPU scales by `[tls] handshake_threads`; `auto` derives a bounded count from the host CPU count. A pool thread never shares a kqueue or a handshake object with another pool thread.
3. **Shared resources.** One OpenSSL `SSL_CTX` is created once per xmppd-core process and shared by every worker. OpenSSL documents `SSL_CTX` as shareable across threads when individual `SSL` objects are used by one thread at a time. The implementation honors the stronger ownership rule: a `net.Tls` object is owned either by the worker or by one pool job, never by both.
4. **Nothing blocks a loop.** Worker loops do no handshake cryptography. Pool threads exist specifically for that cryptography and drive it from real fd readiness. Submission and completion use bounded queues plus event wakeups. There is no sleep loop, poll loop, or timer-driven I/O.
5. **Connection economics.** A handoff moves the fd and TLS object out of the session into a fixed-size pool job. The session may close and be freed while the handshake continues; the job remains the sole owner of the fd and TLS object. Completion returns both to the worker, which either reattaches them to a live session or destroys them when the token is stale. Memory ownership therefore does not depend on session lifetime.
6. **Many requests per connection.** Only the STARTTLS upgrade boundary uses the pool. Established XMPP traffic remains on the worker loop. Post-handshake `SSL_read` and `SSL_write` rules are unchanged, including kTLS RX always going through `SSL_read`.
7. **Beyond one host.** The pool has no cross-host coupling. The process-shared context also makes TLS 1.3 session tickets coherent across the SO_REUSEPORT_LB workers in one xmppd-core process. Horizontal scale remains multiple xmppd instances behind ordinary routing or DNS.
8. **Expensive operations are priced.** Handshake admission is bounded in two dimensions: active handshakes per pool thread and queued handoffs per pool thread. A saturated pool refuses admission and the STARTTLS session fails closed. The refusal is countable and bounded; it cannot grow memory or thread count under a storm.
9. **Overload behavior.** Direct TCP accept pressure already waits in the kernel accept queue because accepted sockets are bounded by session capacity. STARTTLS differs because the socket is already accepted: the priced refusal closes that session instead of letting unbounded handoffs accumulate. Ordinary established sessions continue because their loops do not execute handshake cryptography.
10. **Measurement.** The evidence requirement is an interleaved master/head c2s TLS accept-storm comparison. Primary measures are login rate or completed handshakes per second, worker-loop stall, and completed handshake count. The design also records kTLS TX/RX and cipher once per completed handshake.

## 1. Ownership and handoff

```text
worker loop                    pool lane thread
-----------                    ---------------
Session                        Lane
  Connection.fd                  Loop/kqueue
  Connection.tls  -- handoff --> Job { fd, Tls, worker token }
  fd kqueue deleted              active table + timer
       ^                             |
       |--------- completion --------+
             fd, Tls, result
```

The handoff sequence is strict:

1. STARTTLS reaches the upgrade point only after `<proceed/>` has drained and there is no plaintext read-ahead.
2. The worker creates the server `SSL` object from the process-shared context.
3. The worker stages deletion of the fd read and write knotes, moves fd and TLS object into the job, and submits it. If admission is refused the session fails closed.
4. The pool lane promotes queued jobs only up to its active concurrency bound. Each active job gets one lifecycle deadline. Handshake steps run on the lane thread.
5. Completion detaches the fd from the lane loop before posting the result. The completion queue is bounded by total in-flight capacity, so a completion cannot allocate or grow without bound.
6. The worker drains its completion pipe, validates the session token generation, and either adopts the fd/TLS object or destroys it as stale.

A session closing mid-handshake does not close the fd: ownership already moved to the job. This avoids the unsafe pair of a pool thread dereferencing freed session memory and a worker closing an fd still registered in another kqueue. Token invalidation is only a routing decision, not a memory-safety mechanism.

## 2. Pool sizing

```zig
[tls]
handshake_threads = auto        # auto: ceil(cpu_count / 4), clamped 1..8
handshake_concurrency = 32      # active handshakes per pool thread
handshake_queue = 128           # queued handoffs per pool thread
handshake_timeout_ms = 10000    # lifecycle deadline per handshake
```

The auto rule makes the pool thread-count aware without pretending that handshake threads have dedicated physical cores. On the six-core measurement host auto selects two lanes, matching the ADR-11 estimate that two lanes already cover roughly ten thousand full ECDSA P-256 handshakes per second. Operators running a dedicated TLS host can raise the count explicitly.

The default active bound is deliberate. TLS handshake cryptography is parallel across lanes, but each lane still serializes its own `SSL_do_handshake` steps. Thirty-two active sockets per lane is enough to keep crypto pipelined behind network readiness without making one lane's completion batch large.

## 3. c2s adoption

Core c2s still uses the legacy worker loop rather than lib/net Conn. The pool therefore exposes a small fd/Tls handoff API rather than requiring a rewrite of c2s in the same change. This keeps F7 coherent: the CPU-bound work moves off the loop while the existing STARTTLS ordering rules stay intact.

On successful completion the worker:

- restores the fd and `net.Tls` object to the connection;
- marks TLS established and clears the pool-in-flight bit;
- logs version, cipher, and `BIO_get_ktls_send`/`BIO_get_ktls_recv` exactly once;
- restarts the XMPP stream state and XML reader;
- drains `SSL_pending` for pipelined post-TLS bytes;
- re-registers read interest and the disabled DISPATCH write knote.

On failure or timeout the returned fd and TLS object are destroyed once, then the session is closed. On a stale token they are destroyed without touching a reused session slot.

A test-only direct path remains in `Connection.continueHandshake` so existing small unit tests can exercise the TLS state machine without spawning a pool. xmppd-core configures a pool whenever TLS is enabled; there is no production fallback to loop handshakes.

## 4. Tickets and buffer release

ADR-11 requires measurement before changing OpenSSL's TLS 1.3 ticket count or enabling `SSL_MODE_RELEASE_BUFFERS`. The evaluation dimensions are:

- handshake CPU and completed handshakes per second for ticket counts 0, 1, 2 and 4;
- worker-loop stall under the same accept storm;
- memory retained by idle established TLS connections with and without release buffers;
- correctness constraints: no key updates, no moving-write-buffer dependency, socket BIO only, kTLS engagement logged.

Until the measurement says otherwise the implementation keeps OpenSSL's default ticket count and does not enable release buffers. The RFC 8446 recommendation is independent of ticket count, so the operator-facing certificate guidance remains ECDSA P-256 for the load rig and production handshakes.

## 5. Revert checks

The tests must fail when any of these regressions return:

- a c2s STARTTLS upgrade invokes `Connection.continueHandshake` on a worker loop while a pool is configured;
- a completion is accepted without token generation validation;
- a stale completion writes into a reused session slot;
- pool admission grows past active plus queue capacity;
- a closing session frees TLS memory still owned by a pool job;
- kTLS TX/RX and cipher are not logged exactly once on successful completion.

## 6. Failure modes

- **Admission full:** close the STARTTLS session and count the refusal. The rest of the worker is unaffected.
- **Handshake timeout:** the lane completes the job as failed after its deadline; no timer drives I/O.
- **Peer disconnect:** the handshake fails on the lane and follows the normal failure completion.
- **Worker exits before completion:** pool shutdown destroys queued and active jobs directly. No completion is posted to a dead worker.
- **Completion pipe backpressure:** pipe bytes are only a coalesced wake. A full pipe is harmless because the worker drains the bounded completion ring until empty.
- **fd number reuse:** the fd is never closed while registered in a lane loop. Completion detaches before handback, and the worker re-registers only after ownership returns.

## 7. Evidence snapshot

Measurement rig: one ECDSA P-256 certificate, four core workers, 200 distinct accounts, `xmppc-load -scenario login -connect-rate 2000 -engines 4`, client userland TLS on loopback per FreeBSD PR 296498. Master and head were both ReleaseSafe. Runs were interleaved but remain a small two-cell snapshot, not the full three-run median required for final merge evidence.

| cell | ramp | login/s pipe | login/s wall | driver stall max | STARTTLS p50 | TLS p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| master run 1 | 1.76s | 119 | 113 | 16273us | 16472us | 9037us |
| head run 1 | 1.63s | 128 | 123 | 37133us | 27485us | 18306us |
| master run 2 | 1.64s | 134 | 122 | 37977us | 27985us | 24568us |

The interleaving shows large run-to-run noise on this shared host. Head is within the master envelope for login rate and STARTTLS/TLS latency once the second master run is included; it does not yet prove a latency improvement. The important structural evidence is that all 200 STARTTLS upgrades were submitted to the pool exactly once, completed exactly once, and logged TLSv1.3 `TLS_AES_256_GCM_SHA384` with server-side `ktls tx=true rx=true`.

The final merge evidence still needs the full interleaved three-run median and server-loop stall instrumentation rather than the client-driver stall proxy above.

## 8. Deliberate non-goals

- s2s adoption, outbound DANE verification scheduling, and bounded outbound handshakes are X1.
- Replacing the legacy c2s loop with lib/net Conn is not part of F7.
- Direct TLS c2s listeners remain future work. When added, they must submit accepted sockets to the same pool before any plaintext byte is consumed.
