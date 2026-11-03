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

test {
    std.testing.refAllDecls(@This());
}
