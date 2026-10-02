## kTLS on FreeBSD (mandatory rules)

This repository uses FreeBSD kernel TLS. Before changing any TLS, OpenSSL or socket I/O code, read
the `freebsd-ktls` skill (`SKILL.md`, then `reference/`), and obey these rules. Each one comes from a
real failure or a measurement on FreeBSD 15.1:

- `SSL_OP_ENABLE_KTLS` is correct on FreeBSD. Never remove it to fix `bad record mac`; run
  `~/.agents/skills/freebsd-ktls/tools/ktls-selftest.sh` on the same network path first.
- kTLS on both ends over `127.0.0.1`, between VNET jails, or host to jail fails on affected kernels
  (FreeBSD PR 296498). That is a kernel bug, not a code bug. Test with one userland-TLS end or two hosts.
- After the handshake, check `BIO_get_ktls_send` and `BIO_get_ktls_recv` and log both. Fallback is silent.
- Never `read()`/`recv()` a kTLS-RX socket; use `SSL_read`. Raw `send()` is fine when TX is kTLS.
- Socket BIO only (`SSL_set_fd`), never memory-BIO pairs, on the kTLS path.
- After `WANT_WRITE`, retry `SSL_write` with an identical pointer and length. Do not rely on
  `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER` (silent corruption below OpenSSL 3.5.7).
- Never call `SSL_key_update()`; a KeyUpdate in either direction kills the connection.
- Kernel TLS code is event-driven (kqueue). No `select`, `poll` or timers on the data path.
- Prove any claim about kTLS behavior with a command and its output. If you cannot run one, say so.
