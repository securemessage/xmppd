//! M3 microbenchmarks for the v0.9.1 baseline (T-61BC40BB / Phorge T374).
//!
//! Built by `zig build bench`, always ReleaseFast, against the public API
//! surface: lib/xml Scanner and StanzaWriter, src/core MpscQueue
//! (cross-worker envelope ring), SessionMap lookups, and SCRAM/PBKDF2
//! verify costs.
//!
//! Output: one machine-readable `bench: <case> ...` line per case.
//! Run 3 times and take the median when recording numbers.

const std = @import("std");
const xml = @import("xml");
const sasl = @import("sasl");
const session_map = @import("session_map");
const delivery_queue = @import("delivery_queue");
const ipc = @import("ipc_protocol");

const GPA = std.heap.c_allocator;

// SessionMap.bind logs info per bind; the bench seeds thousands.
pub const std_options: std.Options = .{ .log_level = .warn };

pub fn main() !void {
    try benchXmlParse();
    try benchStanzaWriter();
    try benchMpscRing();
    try benchSessionMapLookup();
    try benchPbkdf2();
    try benchScramExchange();
    try benchIpcCodec();
    try benchIpcFrames();
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

// -- StanzaWriter: serialize the corpus stanza, stanzas/s and MB/s -----------

fn benchStanzaWriter() !void {
    var buf: [4096]u8 = undefined;
    var timer = try std.time.Timer.start();
    var stanzas: u64 = 0;
    var bytes: u64 = 0;
    while (true) {
        var w: std.Io.Writer = .fixed(&buf);
        var sw = xml.StanzaWriter.init(&w);
        try sw.elementOpen("message");
        try sw.attr("from", "m2u-17@localhost/load-3");
        try sw.attr("to", "m2u-88@localhost/lab-1");
        try sw.attr("type", "chat");
        try sw.attr("id", "v091-0042");
        try sw.attr("xml:lang", "en");
        sw.elementOpenEnd();
        try sw.elementOpen("body");
        sw.elementOpenEnd();
        try sw.text("the quick brown fox jumps over the lazy dog while the carrier-grade server chews stanzas at ten thousand per second and nobody even notices the kqueue loop");
        try sw.elementClose("body");
        try sw.elementOpen("received");
        try sw.xmlns("urn:xmpp:receipts");
        try sw.attr("id", "m2-13");
        sw.elementSelfClose();
        try sw.elementClose("message");
        try sw.finish();
        bytes += w.buffered().len;
        stanzas += 1;
        if (timer.read() >= 2 * std.time.ns_per_s) break;
    }
    const seconds = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_s;
    const mb = @as(f64, @floatFromInt(bytes)) / (1024 * 1024);
    rateLine("stanza_write stanzas={d} seconds={d:.3} mb_per_s={d:.1} stanzas_per_s={d:.0}", .{ stanzas, seconds, mb / seconds, @as(f64, @floatFromInt(stanzas)) / seconds });
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

// -- IPC codec: encode+decode round-trip over a representative mix ----------

fn ipcMessageMix() [5]ipc.Message {
    const stanza = "<message from='m2u-17@localhost/load-3' to='m2u-88@remote/lab-1' type='chat' id='v091-0042'><body>the quick brown fox jumps over the lazy dog while the carrier-grade server chews stanzas</body></message>";
    return .{
        .{ .auth_request = .{
            .conn_id = 42,
            .mechanism = .scram_sha_256,
            .client_ip = "192.168.1.100",
            .cb_type = 0,
            .cb_data = "",
            .username = "m2u-17",
            .payload = "n,,n=m2u-17,r=3rfcNHYJY1ZVvWb7l9KqP",
        } },
        .{ .auth_challenge = .{
            .conn_id = 42,
            .challenge = "r=3rfcNHYJY1ZVvWb7l9KqPf2hR6YkKq1yS1xT0w==,s=QSXCR+Q6sek8bf92,i=4096",
        } },
        .{ .sasl_response = .{
            .conn_id = 42,
            .payload = "c=biws,r=3rfcNHYJY1ZVvWb7l9KqPf2hR6YkKq1yS1xT0w==,p=3r2t9N5x0eVlE4B1b3lC1rQ6M8k=",
        } },
        .{ .auth_success = .{
            .conn_id = 42,
            .username = "m2u-17",
            .server_final = "v=UQ6aD8b3m0V9n2eY9P6n4K8x7L5c1dF3s2A0h9G8j7I=",
        } },
        .{ .s2s_deliver = .{
            .from_jid = "m2u-17@localhost/load-3",
            .to_jid = "m2u-88@remote/lab-1",
            .stanza_xml = stanza,
        } },
    };
}

fn benchIpcCodec() !void {
    const messages = ipcMessageMix();
    const buf = try GPA.alloc(u8, ipc.MAX_FRAME_SIZE);
    defer GPA.free(buf);

    var timer = try std.time.Timer.start();
    var ops: u64 = 0;
    var bytes: u64 = 0;
    var i: usize = 0;
    while (true) {
        const n = try ipc.encode(messages[i % messages.len], buf);
        i += 1;
        std.mem.doNotOptimizeAway(try ipc.decode(buf[ipc.HEADER_SIZE..n]));
        ops += 1;
        bytes += n;
        if (timer.read() >= 2 * std.time.ns_per_s) break;
    }
    const seconds = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_s;
    const mb = @as(f64, @floatFromInt(bytes)) / (1024 * 1024);
    rateLine("ipc_codec ops={d} seconds={d:.3} mb_per_s={d:.1} ops_per_s={d:.0}", .{ ops, seconds, mb / seconds, @as(f64, @floatFromInt(ops)) / seconds });
}

// -- IPC frame parse: parseFrame+decode over a pre-encoded stream ------------

fn benchIpcFrames() !void {
    const stanza = "<presence from='m2u-17@remote/lab-1' to='m2u-88@localhost'><show>away</show></presence>";
    const msg = ipc.Message{ .s2s_inbound = .{
        .from_jid = "m2u-17@remote/lab-1",
        .to_jid = "m2u-88@localhost",
        .stanza_xml = stanza,
    } };

    const stream = try GPA.alloc(u8, 4 << 20);
    defer GPA.free(stream);
    var len: usize = 0;
    while (len + ipc.MAX_FRAME_SIZE <= stream.len) {
        len += try ipc.encode(msg, stream[len..]);
    }

    var timer = try std.time.Timer.start();
    var frames: u64 = 0;
    var bytes: u64 = 0;
    while (true) {
        var pos: usize = 0;
        while (try ipc.parseFrame(stream[pos..len])) |f| {
            std.mem.doNotOptimizeAway(try ipc.decode(f.payload));
            pos += f.consumed;
            frames += 1;
            bytes += f.consumed;
        }
        if (timer.read() >= 2 * std.time.ns_per_s) break;
    }
    const seconds = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_s;
    const mb = @as(f64, @floatFromInt(bytes)) / (1024 * 1024);
    rateLine("ipc_frames frames={d} seconds={d:.3} mb_per_s={d:.1} frames_per_s={d:.0}", .{ frames, seconds, mb / seconds, @as(f64, @floatFromInt(frames)) / seconds });
}
