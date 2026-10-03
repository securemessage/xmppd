//! # xmppc per-session memory probe (T-09BD8909)
//!
//! Counts allocator bytes held by N live Sessions (no network: measures the
//! allocation shape, not I/O). Used for before/after A/B of the buffer
//! discipline work. Prints live/peak/per-session bytes.

const std = @import("std");
const xmppc = @import("xmppc");

const Counting = struct {
    inner: std.mem.Allocator,
    used: usize = 0,
    peak: usize = 0,

    fn track(self: *Counting, delta: usize, grow: bool) void {
        self.used = if (grow) self.used + delta else self.used - delta;
        if (self.used > self.peak) self.peak = self.used;
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const p = self.inner.rawAlloc(len, ptr_align, ra) orelse return null;
        self.track(len, true);
        return p;
    }
    fn remap(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const p = self.inner.rawRemap(buf, buf_align, new_len, ra) orelse return null;
        if (new_len > buf.len) self.track(new_len - buf.len, true) else self.track(buf.len - new_len, false);
        return p;
    }
    fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ra: usize) void {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.track(buf.len, false);
        self.inner.rawFree(buf, buf_align, ra);
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = Counting.alloc,
        .resize = struct {
            fn f(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ra: usize) bool {
                const self: *Counting = @ptrCast(@alignCast(ctx));
                if (self.inner.rawResize(buf, buf_align, new_len, ra)) {
                    if (new_len > buf.len) self.track(new_len - buf.len, true) else self.track(buf.len - new_len, false);
                    return true;
                }
                return false;
            }
        }.f,
        .remap = Counting.remap,
        .free = Counting.free,
    };

    fn allocator(self: *Counting) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

pub fn main() !void {
    const n: usize = blk: {
        const args = try std.process.argsAlloc(std.heap.page_allocator);
        defer std.process.argsFree(std.heap.page_allocator, args);
        break :blk if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 1000;
    };

    var counting = Counting{ .inner = std.heap.c_allocator };
    const alloc = counting.allocator();

    const base_live = counting.used;
    var sessions = try std.ArrayList(xmppc.Session).initCapacity(alloc, n);
    defer sessions.deinit(alloc);
    const base_after_array = counting.used;

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const s = try xmppc.Session.init(alloc);
        sessions.appendAssumeCapacity(s);
    }

    const per_session = if (n > 0) (counting.peak - base_after_array) / n else 0;
    std.debug.print("sessions={d} live={d} peak={d} per_session={d}\n", .{ n, counting.used, counting.peak, per_session });

    for (sessions.items) |*s| s.destroy(alloc);
    sessions.clearRetainingCapacity();
    std.debug.print("after teardown: live={d} (base {d})\n", .{ counting.used, base_live });
}
