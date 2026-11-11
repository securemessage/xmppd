//! Microbenchmark: crypto pool submit/complete path (A9).
//! Built via `zig build bench-crypto-pool`; the crypto_pool module is
//! pinned to ReleaseFast.
//!
//! Per run: end-to-end jobs/s through a 4-worker pool with
//! iteration_count = 1 (pool machinery dominates, not PBKDF2), and
//! allocations per accepted job counted on the pool's own allocator.
//! Wall clock is CLOCK_MONOTONIC (std.time.Timer is MONOTONIC_FAST on
//! FreeBSD and quantizes to the kernel tick).

const std = @import("std");
const crypto_pool = @import("crypto_pool");
const sasl = @import("sasl");

const jobs_per_run = 20_000;
const runs = 3;
const workers = 4;

const Counter = struct {
    parent: std.mem.Allocator,
    allocs: u64 = 0,

    fn allocator(self: *Counter) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Counter = @ptrCast(@alignCast(ctx));
        const p = self.parent.rawAlloc(len, alignment, ret_addr);
        if (p != null) self.allocs += 1;
        return p;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Counter = @ptrCast(@alignCast(ctx));
        return self.parent.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Counter = @ptrCast(@alignCast(ctx));
        return self.parent.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *Counter = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(memory, alignment, ret_addr);
    }
};

fn nowNs() i128 {
    const ts = std.posix.clock_gettime(.MONOTONIC) catch unreachable;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

pub fn main() !void {
    var stdout_buf: [256]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const out = &stdout_writer.interface;

    var counter = Counter{ .parent = std.heap.c_allocator };
    var pool = crypto_pool.CryptoPool{ .allocator = counter.allocator() };
    try pool.start(workers);
    defer pool.stop();

    const salt: [32]u8 = @splat(7);
    const creds = try sasl.StoredCredentials.derive("benchmark-password", salt, 1);

    var rates: [runs]f64 = undefined;
    var alloc_rates: [runs]f64 = undefined;

    for (0..runs) |r| {
        counter.allocs = 0;
        var submitted: usize = 0;
        var received: usize = 0;
        const t0 = nowNs();
        while (received < jobs_per_run) {
            var progressed = false;
            while (submitted < jobs_per_run) {
                _ = pool.put("benchmark-password", salt, 1, creds.stored_key) catch |err| switch (err) {
                    error.QueueFull => break,
                    else => return err,
                };
                submitted += 1;
                progressed = true;
            }
            pool.drainPipe();
            while (pool.popCompletion()) |_| {
                received += 1;
                progressed = true;
            }
            if (!progressed) {
                std.Thread.sleep(50 * std.time.ns_per_us);
            }
        }
        const elapsed_ns = nowNs() - t0;
        rates[r] = @as(f64, jobs_per_run) / (@as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s);
        alloc_rates[r] = @as(f64, @floatFromInt(counter.allocs)) / jobs_per_run;
        try out.print("run {d}: {d:.0} jobs/s, {d:.3} allocs/job ({d} jobs)\n", .{ r + 1, rates[r], alloc_rates[r], jobs_per_run });
    }
    std.mem.sort(f64, &rates, {}, std.sort.asc(f64));
    std.mem.sort(f64, &alloc_rates, {}, std.sort.asc(f64));
    try out.print("median: {d:.0} jobs/s, {d:.3} allocs/job\n", .{ rates[runs / 2], alloc_rates[runs / 2] });
    try out.flush();
}
