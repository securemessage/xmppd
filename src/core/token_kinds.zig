//! Token kind tags for kqueue udata and cross-worker addressing (ADR-4).
//!
//! Constants only, no imports: every module may pull this file relatively
//! without a build-graph edge, and two modules each holding their own copy
//! still agree on every value.

/// Never issued; a zeroed udata decodes to this and resolves nowhere.
pub const none: u8 = 0;

/// A live session slot on one worker's sessions[] table.
pub const session: u8 = 1;

/// kqueue udata sentinels (index 0, gen 0): not session slots, dispatched
/// by kind before the token is ever validated.
pub const listener: u8 = 2;
pub const ipc_auth: u8 = 3;
pub const ipc_s2s: u8 = 4;
pub const wake_pipe: u8 = 5;
pub const self_wake: u8 = 6;

/// Fixed periodic timers; their kqueue ident still carries the dispatch
/// key, the udata kind is bookkeeping for stale-event accounting.
pub const timer_sm_expiry: u8 = 7;
pub const timer_offline_sweep: u8 = 8;
pub const timer_auth_reconnect: u8 = 9;
pub const timer_s2s_reconnect: u8 = 10;

/// Delivery-ring pseudo-targets: address a broadcast or actor channel,
/// never a session slot.
pub const multicast: u8 = 16;
pub const room_actor: u8 = 17;
pub const sm_actor: u8 = 18;

/// MUC occupant record that names a remote (S2S) session rather than a
/// local session slot.
pub const remote: u8 = 19;
