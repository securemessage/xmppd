//! # presence/broadcast: outbound presence to remote domains
//!
//! The S2S egress helpers for pre-built presence stanzas moved out of
//! server.zig (ADR-12). Local broadcast and probe fan-out live in
//! handler.zig; these two functions only wrap the s2s IPC send.

const std = @import("std");
const server_mod = @import("../worker/worker.zig");
const Server = server_mod.Server;
const Session = server_mod.Session;
const ChangeList = @import("../worker/loop.zig").ChangeList;

const log = std.log.scoped(.xmppd);

/// Forward a pre-built presence stanza to a remote domain via S2S IPC.
/// Used by subscription/presence handlers where the stanza XML is already built.
pub fn forwardPresenceXmlToS2s(self: *Server, session: *Session, from_str: []const u8, to_str: []const u8, stanza_xml: []const u8, changes: *ChangeList) void {
    _ = changes; // Write interest: reconcileIpcWriteInterest (S10).
    if (!self.s2s_ipc.connected) {
        log.info("connection {d} presence to remote {s} — no S2S daemon", .{ session.conn.id, to_str });
        return;
    }

    self.s2s_ipc.send(.{ .s2s_deliver = .{
        .from_jid = from_str,
        .to_jid = to_str,
        .stanza_xml = stanza_xml,
    } }) catch {
        log.err("connection {d} failed to forward presence to S2S", .{session.conn.id});
        return;
    };
    // Write interest: reconcileIpcWriteInterest (S10).
}

/// Forward a pre-built presence stanza to a remote domain via S2S IPC.
/// Variant without a session reference — used by broadcast presence.
pub fn sendPresenceViaS2s(self: *Server, from_str: []const u8, to_str: []const u8, stanza_xml: []const u8, changes: *ChangeList) void {
    _ = changes; // Write interest: reconcileIpcWriteInterest (S10).
    if (!self.s2s_ipc.connected) return;

    self.s2s_ipc.send(.{ .s2s_deliver = .{
        .from_jid = from_str,
        .to_jid = to_str,
        .stanza_xml = stanza_xml,
    } }) catch return;
    // Write interest: reconcileIpcWriteInterest (S10).
}
