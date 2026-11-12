//! # Root allocator selection (ADR-7, Q1)
//!
//! One Root per daemon process, held by main for the process lifetime and
//! passed down as the system allocator. The `-Dallocator` build option picks
//! the backing implementation:
//!
//! - `debug`: std.heap.DebugAllocator; leak and double-free checks run at
//!   deinit. Default in Debug builds and always used in test binaries, so
//!   tests keep their leak detection at every optimize mode.
//! - `c`: libc allocator (jemalloc on FreeBSD), thread-cached, no shared
//!   lock on the hot path. Default in ReleaseSafe, ReleaseFast and
//!   ReleaseSmall; the worker threads of xmppd-core share it by design.
//! - `smp`: std.heap.smp_allocator; kept selectable for measurement.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

pub const Kind = enum { debug, c, smp };

pub const kind: Kind = if (builtin.is_test)
    .debug
else
    std.meta.stringToEnum(Kind, build_options.allocator) orelse .debug;

pub const Root = switch (kind) {
    .debug => DebugRoot,
    .c, .smp => TrivialRoot,
};

const DebugRoot = struct {
    inner: std.heap.DebugAllocator(.{}) = .init,

    pub fn init() DebugRoot {
        return .{};
    }

    /// DebugAllocator reports leaks and double frees at deinit.
    pub fn deinit(self: *DebugRoot) void {
        _ = self.inner.deinit();
    }

    pub fn allocator(self: *DebugRoot) std.mem.Allocator {
        return self.inner.allocator();
    }
};

const TrivialRoot = struct {
    pub fn init() TrivialRoot {
        return .{};
    }

    /// jemalloc and the SMP allocator have no teardown.
    pub fn deinit(_: *TrivialRoot) void {}

    pub fn allocator(_: *TrivialRoot) std.mem.Allocator {
        return if (kind == .smp) std.heap.smp_allocator else std.heap.c_allocator;
    }
};

test "Root allocator allocates and frees in the test-selected kind" {
    // Tests always resolve to debug (builtin.is_test), so this exercises
    // DebugAllocator end to end.
    try std.testing.expectEqual(Kind.debug, kind);
    var root = Root.init();
    defer root.deinit();
    const a = root.allocator();
    const buf = try a.alloc(u8, 128);
    defer a.free(buf);
    @memset(buf, 0xAA);
    try std.testing.expectEqual(@as(u8, 0xAA), buf[0]);
}
