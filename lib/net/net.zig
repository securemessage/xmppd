//! lib/net: shared event-loop substrate for xmppd (ADR-8, F2 core).
//!
//! FreeBSD only: kqueue, SO_REUSEPORT_LB, LOCAL_PEERCRED. One Loop per
//! thread; only Token values, detached fds, *Wake and *Broadcast may cross
//! threads. See DESIGN.md for the full contract.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .freebsd) {
        @compileError("lib/net is FreeBSD only (kqueue, SO_REUSEPORT_LB, LOCAL_PEERCRED)");
    }
}

pub const Token = @import("token.zig").Token;
pub const SlotMap = @import("slotmap.zig").SlotMap;
pub const kevent = @import("kevent.zig");
pub const loop = @import("loop.zig");
pub const Loop = loop.Loop;
pub const Handle = loop.Handle;
pub const Interest = loop.Interest;
pub const Filter = loop.Filter;
pub const Event = loop.Event;
pub const Io = loop.Io;
pub const ChangeFailure = loop.ChangeFailure;
pub const Wake = @import("wake.zig").Wake;
pub const Broadcast = @import("wake.zig").Broadcast;
pub const TimerWheel = @import("timer_wheel.zig").TimerWheel;
pub const TimerId = loop.TimerId;
pub const Deadline = loop.Deadline;
pub const bindTcp = @import("bind.zig").bindTcp;
pub const bindUnix = @import("bind.zig").bindUnix;
pub const TcpOptions = @import("bind.zig").TcpOptions;
pub const UnixOptions = @import("bind.zig").UnixOptions;
pub const BindError = @import("bind.zig").BindError;
pub const Listener = @import("bind.zig").Listener;
pub const PeerCred = @import("bind.zig").PeerCred;
pub const peerCred = @import("bind.zig").peerCred;

test {
    std.testing.refAllDecls(@This());
}
