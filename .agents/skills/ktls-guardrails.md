---
paths:
  - "**/tls.zig"
  - "**/tls_*.zig"
  - "**/*_tls.zig"
  - "**/ssl.zig"
  - "**/ssl_*.zig"
  - "**/tls_openssl.zig"
  - "**/*ktls*"
  - "**/*kTLS*"
  - "**/lib/tls/**"
  - "**/*.c"
  - "**/*.h"
---

KTLS GUARDRAILS (FreeBSD kernel TLS). You touched a file that may contain TLS or kTLS code.
If the file does not use OpenSSL, SSL_*, BIO_*, TCP_TXTLS_ENABLE or kern.ipc.tls, ignore this rule.
Otherwise these are hard rules, each one learned from a real failure or measured on FreeBSD 15.1:

1. SSL_OP_ENABLE_KTLS is the CORRECT, portable flag on FreeBSD. It is not a Linux-only flag. Never
   remove it to "fix" a bad-record-mac error, and never write a comment claiming otherwise. First
   run tools/ktls-selftest.sh from the freebsd-ktls skill on the same network path.
2. A failure only when BOTH ends use kTLS over 127.0.0.1, between VNET jails (epair/bridge), or
   host to jail is FreeBSD PR 296498 (kernel). It is not a bug in this code. Fix the test: make one
   end userland TLS (flag off) or use two physical hosts.
3. After the handshake always check BIO_get_ktls_send(SSL_get_wbio(ssl)) and
   BIO_get_ktls_recv(SSL_get_rbio(ssl)). OpenSSL falls back to userland crypto silently. Log both.
4. Never read() or recv() a socket whose RX is kTLS. Always SSL_read. send() on the raw fd is fine
   when ktls_tx is 1.
5. Never use memory-BIO pairs on the kTLS path. Use SSL_set_fd (socket BIO).
6. After SSL_ERROR_WANT_WRITE retry SSL_write with an IDENTICAL pointer and length (stable per
   connection buffer). Do not rely on SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: with kTLS it silently
   corrupts data on OpenSSL below 3.5.7 (base FreeBSD 15.1 has 3.5.6; ports openssl is 3.0.22).
7. Never call SSL_key_update(). Any TLS 1.3 KeyUpdate, sent or received, kills a kTLS connection
   ("no suitable record layer"; the kernel returns EALREADY). The flags still read 1 afterwards.
8. Do not call SSL_CTX_set_max_send_fragment, enable compression or set a record padding callback:
   each silently disables kTLS.
9. Use one OpenSSL: headers and libraries from the same prefix. dev1 has base 3.5.6 (libssl.so.35)
   and ports 3.0.22 (libssl.so.12). Check with ldd.
10. Event-driven only: kqueue, no select/poll/timers on the data path. Drain SSL_read to WANT_READ
    under EV_CLEAR.

Full detail, evidence and test tools: the freebsd-ktls skill (SKILL.md, reference/, tools/).
Do not change TLS behavior without running the relevant tool from tools/ and reporting its output.
