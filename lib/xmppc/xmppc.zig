//! # xmppc — libstrophe-shaped XMPP client-core (Zig)
//!
//! Event-driven XMPP client-core library for the xmppd project (T32 phase 1).
//! Reuses the shared protocol primitives (xml, xmpp, sasl, tls, ssl, dns) and
//! adds the client-side pieces that `lib/xmpp` deliberately leaves to the peer:
//!
//!   * `ClientStream` (stream.zig) — client-side stream FSM (RFC 6120 + XEP-0198)
//!   * `SaslClient`   (sasl.zig)   — client SASL mechanism coordinator
//!   * `Engine`       (engine.zig) — ONE kqueue loop driving N Sessions
//!   * `Session`      (session.zig) — connect → TCP → STARTTLS → SASL → bind
//!                                   → SM, one connection lifecycle
//!   * `Parser`       (parser.zig) — XML reader events → stream.ServerEvent,
//!                                   plus application stanza capture
//!   * `Sm`           (sm.zig)     — Stream Management r/h ack bookkeeping (phase 2)
//!
//! Consumers receive everything through ONE tagged-union event handler
//! (`Engine.setEventHandler` with `Event`: established / closed / stanza —
//! a C-ABI wrapper maps 1:1) and write stanzas with `Session.sendStanza`
//! (established streams only). Delayed work (reconnect backoff, periodic
//! application duties) uses `Engine.schedule`/`Engine.cancelTimer`: one-shot
//! timers on the same kqueue loop whose callbacks run on the engine thread
//! and keep the loop alive while pending (T-A9AE7D9C).
//!
//! Design invariants (see Continuum board XMPPC/task-brief-91e96a28):
//!   * Own API boundary from day one — nothing here imports src/; src/ does not
//!     import lib/xmppc.
//!   * Event-driven only (kqueue; no thread per connection, no polling).
//!   * N client objects on one kqueue loop is a hard requirement (load-driver).
//!
//! Consumers: the xmppd T32 load driver (phase 2), then Kumiko Chat (M9) via a
//! thin C-ABI wrapper.
//!
//! SECURITY (T202/T-B5D56AD3): server authentication is DANE-first.
//! `Session.tls_policy` (seeded from `Engine.default_tls_policy`) selects:
//!   * dane_first (default) — the resolution's TLSA records authenticate the
//!     peer chain (DANE-EE or DANE-TA; fail closed on mismatch); only when no
//!     TLSA exists does it fall back to PKIX (system CA store + hostname
//!     check against the stream domain, which is also the SNI).
//!   * none — lab rigs only: SSL_VERIFY_NONE, no hostname check. Never use
//!     against untrusted networks.

pub const stream = @import("stream.zig");
pub const sasl = @import("sasl.zig");
pub const session = @import("session.zig");
pub const engine = @import("engine.zig");
pub const parser = @import("parser.zig");
pub const transport = @import("transport.zig");

pub const ClientStream = stream.ClientStream;
pub const ClientState = stream.ClientState;
pub const ServerEvent = stream.ServerEvent;
pub const ClientAction = stream.ClientAction;
pub const Features = stream.Features;
pub const StreamHeader = stream.StreamHeader;
pub const StreamError = stream.StreamError;
pub const SmResult = stream.SmResult;

pub const SaslClient = sasl.SaslClient;

pub const Engine = engine.Engine;
pub const Session = session.Session;
pub const SessionConfig = session.SessionConfig;
pub const Event = session.Event;
pub const EventHandler = session.EventHandler;
pub const Stanza = session.Stanza;
pub const StanzaChild = parser.StanzaChild;
pub const Transport = transport.Transport;
pub const Handle = engine.Handle;

test {
    _ = stream;
    _ = sasl;
    _ = session;
    _ = engine;
    _ = parser;
    _ = transport;
}
