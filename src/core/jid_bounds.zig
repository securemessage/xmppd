//! JID size bounds shared by the core modules. This is a leaf file so that
//! buffer-only consumers (fanout) can size stacks without importing
//! router.zig, which would pull the router and server test graphs into every
//! consumer's own test module.

/// A bare JID that can be a store key is at most MAX_KEY_LEN (511) bytes, so
/// this buffer holds every valid key in full (S4).
pub const BARE_JID_MAX = 512;
/// Full-JID buffer bound. A bound session's JID is already capped by the
/// session-map bind buffer (asserted in server.zig); remote contact JIDs get
/// headroom up to this bound instead of truncating (S4).
pub const FULL_JID_MAX = 1024;
/// Stack buffer bound for a stanza assembled inline that embeds up to two
/// JIDs (a sender and a recipient) plus fixed markup. Sized to two maximum
/// full JIDs so a maximum-length JID can never truncate the stanza.
pub const JID_STANZA_MAX = 2 * FULL_JID_MAX + 64;
