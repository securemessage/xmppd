//! M3 microbenchmarks for the v0.9.1 baseline (T-61BC40BB / Phorge T374).
//!
//! Built by `zig build bench`, always ReleaseFast, against the public API
//! surface that exists at the pinned baseline d85dd37: lib/xml Scanner,
//! src/core MpscQueue (cross-worker envelope ring), SessionMap lookups,
//! and SCRAM/PBKDF2 verify costs. StanzaWriter has no public API yet
//! (F4), so it is not benched here.
//!
//! Output: one machine-readable `bench: <case> ...` line per case.
//! Run 3 times and take the median when recording numbers.

const std = @import("std");
const xml = @import("xml");
const sasl = @import("sasl");
const session_map = @import("session_map");
const delivery_queue = @import("delivery_queue");

const GPA = std.heap.c_allocator;

// SessionMap.bind logs info per bind; the bench seeds thousands.
pub const std_options: std.Options = .{ .log_level = .warn };

pub fn main() !void {
    try benchXmlParse();
    try benchMpscRing();
    try benchSessionMapLookup();
    try benchPbkdf2();
    try benchScramExchange();
}

fn rateLine(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("bench: " ++ fmt ++ "\n", args);
}

// -- XML parse: MB/s and stanzas/s over a 64 MiB stanza corpus --------------

fn benchXmlParse() !void {
    const stanza = "<message from='m2u-17@localhost/load-3' to='m2u-88@localhost/lab-1' type='chat' id='v091-0042' xml:lang='en'><body>the quick brown fox jumps over the lazy dog while the carrier-grade server chews stanzas at ten thousand per second and nobody even notices the kqueue loop</body><received xmlns='urn:xmpp:receipts' id='m2-13'/></message>";
    var corpus = std.ArrayList(u8){};
    defer corpus.deinit(GPA);
    const target = 64 << 20;
    while (corpus.items.len < target) {
        try corpus.appendSlice(GPA, stanza);
    }
    const data = corpus.items;

    var scanner = xml.Scanner.init(GPA);
    defer scanner.deinit();
    var timer = try std.time.Timer.start();
    var pos: usize = 0;
    var tokens: u64 = 0;
    var stanzas: u64 = 0;
    while (@as(?xml.Token, try scanner.next(data, &pos))) |tok| {
        tokens += 1;
        if (tok.type == .element_open and std.mem.eql(u8, tok.local_name, "message")) stanzas += 1;
        // Per-token arena retention stays bounded like the production loops do.
        scanner.resetArena();
    }
    const ns = timer.read();
    const s = @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
    const mb = @as(f64, @floatFromInt(data.len)) / (1024 * 1024);
    rateLine("xml_parse corpus_mib={d:.1} tokens={d} stanzas={d} seconds={d:.3} mb_per_s={d:.1} stanzas_per_s={d:.0}", .{ mb, tokens, stanzas, s, mb / s, @as(f64, @floatFromInt(stanzas)) / s });
}

// -- MPSC ring: enqueue+drain ops/s at 128-byte payloads ---------------------

fn benchMpscRing() !void {
    var queue: delivery_queue.MpscQueue = .{};
    const payload = "stanza payload for the envelope ring benchmark, padded to one hundred and twenty eight bytes so it looks like a typical message..";

    const noop = struct {
        fn on(_: void, _: u32, _: u32, _: []const u8) void {}
    }.on;

    var timer = try std.time.Timer.start();
    var ops: u64 = 0;
    var batches: u64 = 0;
    while (true) {
        // One full ring per batch, like the worst fan-out drain.
        var enqueued: u32 = 0;
        while (enqueued < delivery_queue.QUEUE_SLOTS) : (enqueued += 1) {
            queue.enqueue(0, 0, payload) catch break;
            ops += 1;
        }
        const drained = queue.drain(@as(void, {}), noop);
        ops += drained;
        batches += 1;
        if (timer.read() >= 2 * std.time.ns_per_s) break;
        if (enqueued != drained) return error.RingStuck;
    }
    const seconds = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_s;
    rateLine("mpsc_ring ops={d} batches={d} seconds={d:.3} ops_per_s={d:.0}", .{ ops, batches, seconds, @as(f64, @floatFromInt(ops)) / seconds });
}

// -- SessionMap: 8192 bound sessions, findByFullJid ns/lookup ----------------

fn benchSessionMapLookup() !void {
    const n_users = 8192;
    var map = session_map.SessionMap.init(GPA, false, 256);
    defer map.deinit();

    const locals = try GPA.alloc([]u8, n_users);
    defer GPA.free(locals);
    defer for (locals) |s| GPA.free(s);
    for (locals, 0..) |*slot, i| {
        slot.* = try std.fmt.allocPrint(GPA, "m2u-{d}", .{i});
        _ = try map.bind(0, @intCast(i), slot.*, "localhost", "lab-1");
    }

    const rounds = 200 * n_users;
    var timer = try std.time.Timer.start();
    var rng = std.Random.DefaultPrng.init(0x5190);
    const rand = rng.random();
    for (0..rounds) |_| {
        const local = locals[rand.uintLessThan(usize, locals.len)];
        std.mem.doNotOptimizeAway(map.findByFullJid(local, "localhost", "lab-1"));
    }
    const ns = timer.read();
    const per_lookup = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(rounds));
    rateLine("session_map_lookup entries={d} lookups={d} seconds={d:.3} ns_per_lookup={d:.0}", .{ n_users, rounds, @as(f64, @floatFromInt(ns)) / std.time.ns_per_s, per_lookup });
}

// -- PBKDF2 (HMAC-SHA-256, 4096 iterations): ops/s ---------------------------

fn benchPbkdf2() !void {
    const password = "pass1";
    var salt: [32]u8 = undefined;
    std.crypto.random.bytes(&salt);
    const iterations: u32 = 4096;

    var out: [32]u8 = undefined;
    var timer = try std.time.Timer.start();
    var count: u64 = 0;
    while (true) {
        sasl.scram.pbkdf2(password, &salt, iterations, &out);
        count += 1;
        if (timer.read() >= 2 * std.time.ns_per_s) break;
    }
    const seconds = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_s;
    const us_per_op = @as(f64, @floatFromInt(timer.read())) / @as(f64, @floatFromInt(count)) / 1000;
    rateLine("pbkdf2_ops iterations=4096 ops={d} seconds={d:.3} ops_per_s={d:.0} us_per_op={d:.0}", .{ count, seconds, @as(f64, @floatFromInt(count)) / seconds, us_per_op });
}

// -- SCRAM server verify: full server exchange with precomputed credentials --

fn benchScramExchange() !void {
    const password = "pass1";
    var salt: [32]u8 = undefined;
    std.crypto.random.bytes(&salt);
    const creds = try sasl.scram.StoredCredentials.derive(password, salt, 4096);

    var timer = try std.time.Timer.start();
    var count: u64 = 0;
    while (true) : (count += 1) {
        var client = sasl.ScramClient.init(GPA, "alice", password);
        defer client.deinit();
        var server = sasl.ScramServer.init(GPA);
        defer server.deinit();

        const cf = try client.clientFirst();
        _ = try server.handleClientFirst(cf);
        server.setCredentials(creds);
        const sf = try server.serverFirst();
        try client.parseServerFirst(sf);
        var salted: [32]u8 = undefined;
        sasl.scram.pbkdf2(password, client.salt_raw[0..client.salt_raw_len], client.iteration_count, &salted);
        const final = try client.clientFinal(salted);
        const server_final = try server.handleClientFinal(final);
        _ = server_final;
        if (timer.read() >= 2 * std.time.ns_per_s) break;
    }
    const seconds = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_s;
    rateLine("scram_verify_exchange ops={d} seconds={d:.3} ops_per_s={d:.0}", .{ count, seconds, @as(f64, @floatFromInt(count)) / seconds });
}
