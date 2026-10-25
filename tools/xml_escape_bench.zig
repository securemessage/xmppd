//! Microbenchmark: SIMD run-copy escaper (lib/xml/writer.zig writeEscaped)
//! vs the scalar per-byte escaper it replaces. Built via
//! `zig build bench-xml-escape` (module is pinned to ReleaseFast).
//!
//! Method: a deterministic corpus per density row, enough iterations that
//! each sample runs for well over a second, three runs, median reported.
//! Timestamps use CLOCK_MONOTONIC (not std.time.Timer, which is
//! MONOTONIC_FAST on FreeBSD and quantizes to the kernel tick).

const std = @import("std");
const xml_writer = @import("xml-writer");

const corpus_len = 4096;
const runs = 3;
const target_ns = 2 * std.time.ns_per_s;

fn scalarEscape(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| {
        switch (c) {
            '&' => try w.writeAll("&amp;"),
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '\'' => try w.writeAll("&apos;"),
            '"' => try w.writeAll("&quot;"),
            else => try w.writeByte(c),
        }
    }
}

fn nowNs() i128 {
    const ts = std.posix.clock_gettime(.MONOTONIC) catch unreachable;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

fn fillCorpus(buf: []u8, escape_ppm: u32) void {
    var prng = std.Random.DefaultPrng.init(0xB3_B3_B3);
    const rand = prng.random();
    const clean = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;-_";
    const escapable = "&<>'\"";
    for (buf) |*b| {
        if (rand.uintLessThan(u32, 1_000_000) < escape_ppm) {
            b.* = escapable[rand.uintLessThan(usize, escapable.len)];
        } else {
            b.* = clean[rand.uintLessThan(usize, clean.len)];
        }
    }
}

/// writeEscaped now takes an EscapeMode; the bench runs the text mode.
fn simdEscape(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    return xml_writer.writeEscaped(w, s, .text);
}

/// Time `iters` calls of `esc` over `corpus`; returns ns per iteration.
fn timeOne(
    esc: *const fn (w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void,
    corpus: []const u8,
    out_buf: []u8,
    iters: usize,
) f64 {
    var w: std.Io.Writer = .fixed(out_buf);
    esc(&w, corpus) catch unreachable;
    std.mem.doNotOptimizeAway(w.end);

    const t0 = nowNs();
    var i: usize = 0;
    while (i < iters) : (i += 1) {
        w = .fixed(out_buf);
        esc(&w, corpus) catch unreachable;
        std.mem.doNotOptimizeAway(w.end);
    }
    const ns = nowNs() - t0;
    return @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(iters));
}

fn median3(samples: *[runs]f64) f64 {
    std.mem.sort(f64, samples, {}, std.sort.asc(f64));
    return samples[runs / 2];
}

pub fn main() !void {
    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = std.fs.File.stdout().writer(&stdout_buf);
    const out = &stdout_w.interface;

    var corpus: [corpus_len]u8 = undefined;
    // Worst-case output is 6x input; give the fixed buffer headroom.
    var out_buf: [corpus_len * 6]u8 = undefined;

    const rows = .{
        .{ "clean", 0 },
        .{ "1% escapables", 10_000 },
        .{ "10% escapables", 100_000 },
        .{ "all escapables", 1_000_000 },
    };

    const hdr = .{ "corpus 4KiB", "scalar ns", "simd ns", "speedup" };
    try out.print("{s:<16} {s:>12} {s:>12} {s:>8}\n", hdr);
    inline for (rows) |row| {
        fillCorpus(&corpus, row[1]);

        // Calibrate iteration count so one sample exceeds target_ns.
        const probe_ns = timeOne(scalarEscape, &corpus, &out_buf, 64);
        const iters: usize = @intFromFloat(@max(64.0, @as(f64, target_ns) / @max(probe_ns, 1)));

        var scalar_ns: [runs]f64 = undefined;
        var simd_ns: [runs]f64 = undefined;
        var r: usize = 0;
        while (r < runs) : (r += 1) {
            scalar_ns[r] = timeOne(scalarEscape, &corpus, &out_buf, iters);
            simd_ns[r] = timeOne(simdEscape, &corpus, &out_buf, iters);
        }
        const s = median3(&scalar_ns);
        const v = median3(&simd_ns);
        try out.print("{s:<16} {d:>12.1} {d:>12.1} {d:>7.2}x\n", .{ row[0], s, v, s / v });
    }
    try out.flush();
}
