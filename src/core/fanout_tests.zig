//! Standalone test root for muc/fanout.zig. The fanout test module must be
//! rooted inside src/core so the file's relative imports stay in-module.
comptime {
    _ = @import("muc/fanout.zig");
}
