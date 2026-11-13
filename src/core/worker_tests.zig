//! Standalone test root for worker/worker.zig. The server test module must
//! be rooted inside src/core so the file's relative imports stay in-module.
comptime {
    _ = @import("worker/worker.zig");
}
