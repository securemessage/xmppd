//! # xmppc — libstrophe-shaped XMPP client-core (Zig)
//!
//! Event-driven XMPP client-core library for the xmppd project (T32 phase 1).
//! Reuses the shared protocol primitives (xml, xmpp, sasl, tls, ssl, dns) and
//! adds the client-side pieces that `lib/xmpp` deliberately leaves to the peer:
//!
//!   * `ClientStream` (stream.zig) — client-side stream FSM (RFC 6120 + XEP-0198)
//!   * `SaslClient`   (sasl.zig)   — client SASL mechanism coordinator
//!   * `Session`      (session.zig) — connect → TCP → STARTTLS → SASL → bind
//!                                   → SM, driven by ONE kqueue loop for N clients
//!   * `Sm`           (sm.zig)     — Stream Management r/h ack bookkeeping (phase 2)
//!
//! Design invariants (see Continuum board XMPPC/task-brief-91e96a28):
//!   * Own API boundary from day one — nothing here imports src/; src/ does not
//!     import lib/xmppc.
//!   * Event-driven only (kqueue; no thread per connection, no polling).
//!   * N client objects on one kqueue loop is a hard requirement (load-driver).
//!
//! Consumers: the xmppd T32 load driver (phase 2), then Kumiko Chat (M9) via a
//! thin C-ABI wrapper.

pub const stream = @import("stream.zig");
pub const sasl = @import("sasl.zig");
pub const session = @import("session.zig");

pub const ClientStream = stream.ClientStream;
pub const ClientState = stream.ClientState;
pub const ServerEvent = stream.ServerEvent;
pub const ClientAction = stream.ClientAction;
pub const Features = stream.Features;
pub const StreamHeader = stream.StreamHeader;
pub const StreamError = stream.StreamError;
pub const SmResult = stream.SmResult;

pub const SaslClient = sasl.SaslClient;

pub const Engine = session.Engine;
pub const Session = session.Session;

test {
    _ = stream;
    _ = sasl;
    _ = session;
}
