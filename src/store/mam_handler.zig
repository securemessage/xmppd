//! # MAM Query Handler (XEP-0313)
//!
//! Processes MAM IQ queries and generates XML responses using the ArchiveStore.
//! This module is intentionally decoupled from the event loop — it takes
//! parsed query parameters and produces complete XML response strings.
//!
//! ## XEP-0313 Flow
//!
//! 1. Client sends: `<iq type='set'><query xmlns='urn:xmpp:mam:2'> ... </query></iq>`
//! 2. Server responds with a series of `<message>` stanzas wrapped in `<result>`
//! 3. Followed by: `<iq type='result'><fin xmlns='urn:xmpp:mam:2'> <set>...</set> </fin></iq>`
//!
//! The `<fin>` element contains RSM metadata: first, last, count.

const std = @import("std");
const backend = @import("backend");
const archive_store = @import("archive_store");

const ArchiveStore = archive_store.ArchiveStore;
const QueryOptions = archive_store.QueryOptions;

/// Parsed MAM query from an IQ stanza.
pub const MamQuery = struct {
    /// IQ id attribute (for the response).
    iq_id: []const u8 = "",
    /// Bare JID of the querying user (from session binding).
    owner: []const u8 = "",
    /// Query ID (queryid attribute on <query>).
    query_id: []const u8 = "",
    /// Optional: filter by conversation partner.
    with: ?[]const u8 = null,
    /// Optional: start timestamp (XEP-0313 §5.2.1).
    start: ?u64 = null,
    /// Optional: end timestamp.
    end: ?u64 = null,
    /// RSM: after this stanza_id.
    after_id: ?[]const u8 = null,
    /// RSM: before this stanza_id.
    before_id: ?[]const u8 = null,
    /// RSM: max results.
    max: u32 = 50,
};

/// A single result message to send to the client.
pub const MamResultMessage = struct {
    /// The XML for the forwarded <message> element (full MAM result wrapper).
    xml: []const u8,
};

/// The complete MAM response (result messages + fin element).
pub const MamResponse = struct {
    /// Individual <message> stanzas to send (in order).
    messages: []MamResultMessage,
    /// The <iq type='result'><fin .../></iq> closing element.
    fin_iq: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *MamResponse) void {
        for (self.messages) |msg| {
            self.allocator.free(msg.xml);
        }
        self.allocator.free(self.messages);
        self.allocator.free(self.fin_iq);
    }
};

/// Process a MAM query and produce the full response.
pub fn handleMamQuery(
    comptime Backend: type,
    store: *ArchiveStore(Backend),
    query: MamQuery,
    allocator: std.mem.Allocator,
) !MamResponse {
    // Execute the archive query
    const result = try store.query(query.owner, .{
        .with = query.with,
        .start = query.start,
        .end = query.end,
        .after_id = query.after_id,
        .before_id = query.before_id,
        .max = query.max,
    });

    // Build individual <message> stanzas
    var messages = try allocator.alloc(MamResultMessage, result.messages.len);
    errdefer allocator.free(messages);

    for (result.messages, 0..) |msg, i| {
        messages[i] = .{
            .xml = try buildResultMessage(allocator, query.owner, query.query_id, msg),
        };
    }

    // Build the <iq type='result'><fin .../></iq>
    const fin = try buildFinIq(allocator, query.iq_id, result, query.owner);

    // Free archive store results (we've copied what we need)
    for (result.messages) |msg| {
        allocator.free(msg.stanza_id);
        if (msg.stanza_xml.len > 0) allocator.free(@constCast(msg.stanza_xml));
    }
    allocator.free(result.messages);

    return .{
        .messages = messages,
        .fin_iq = fin,
        .allocator = allocator,
    };
}

/// Build a single MAM result <message> wrapper.
///
/// Format (XEP-0313 §5.1):
/// ```xml
/// <message to='owner'>
///   <result xmlns='urn:xmpp:mam:2' queryid='q1' id='stanza_id'>
///     <forwarded xmlns='urn:xmpp:forward:0'>
///       <delay xmlns='urn:xmpp:delay' stamp='2023-01-01T00:00:00Z'/>
///       {original stanza XML}
///     </forwarded>
///   </result>
/// </message>
/// ```
fn buildResultMessage(
    allocator: std.mem.Allocator,
    owner: []const u8,
    query_id: []const u8,
    msg: archive_store.ArchivedMessage,
) ![]const u8 {
    // Pre-calculate size estimate
    const estimate = 256 + owner.len + query_id.len + msg.stanza_id.len + msg.stanza_xml.len;
    const buf = try allocator.alloc(u8, estimate);
    errdefer allocator.free(buf);

    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    w.writeAll("<message to='") catch return error.OutOfMemory;
    w.writeAll(owner) catch return error.OutOfMemory;
    w.writeAll("'><result xmlns='urn:xmpp:mam:2' queryid='") catch return error.OutOfMemory;
    w.writeAll(query_id) catch return error.OutOfMemory;
    w.writeAll("' id='") catch return error.OutOfMemory;
    w.writeAll(msg.stanza_id) catch return error.OutOfMemory;
    w.writeAll("'><forwarded xmlns='urn:xmpp:forward:0'><delay xmlns='urn:xmpp:delay' stamp='") catch return error.OutOfMemory;
    writeTimestamp(w, msg.timestamp) catch return error.OutOfMemory;
    w.writeAll("'/>") catch return error.OutOfMemory;
    w.writeAll(msg.stanza_xml) catch return error.OutOfMemory;
    w.writeAll("</forwarded></result></message>") catch return error.OutOfMemory;

    const written = fbs.getWritten();
    // Shrink allocation to actual size
    if (written.len < buf.len) {
        const exact = try allocator.realloc(buf, written.len);
        return exact;
    }
    return buf;
}

/// Build the final <iq type='result'><fin .../></iq> element.
///
/// Format (XEP-0313 §5.3):
/// ```xml
/// <iq type='result' id='iq_id'>
///   <fin xmlns='urn:xmpp:mam:2' complete='true|false'>
///     <set xmlns='http://jabber.org/protocol/rsm'>
///       <first>first_stanza_id</first>
///       <last>last_stanza_id</last>
///       <count>N</count>
///     </set>
///   </fin>
/// </iq>
/// ```
fn buildFinIq(
    allocator: std.mem.Allocator,
    iq_id: []const u8,
    result: archive_store.QueryResult,
    _: []const u8,
) ![]const u8 {
    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<iq type='result' id='") catch return error.OutOfMemory;
    w.writeAll(iq_id) catch return error.OutOfMemory;
    w.writeAll("'><fin xmlns='urn:xmpp:mam:2'") catch return error.OutOfMemory;
    if (result.complete) {
        w.writeAll(" complete='true'") catch return error.OutOfMemory;
    }
    w.writeAll("><set xmlns='http://jabber.org/protocol/rsm'>") catch return error.OutOfMemory;

    if (result.messages.len > 0) {
        w.writeAll("<first>") catch return error.OutOfMemory;
        w.writeAll(result.messages[0].stanza_id) catch return error.OutOfMemory;
        w.writeAll("</first><last>") catch return error.OutOfMemory;
        w.writeAll(result.messages[result.messages.len - 1].stanza_id) catch return error.OutOfMemory;
        w.writeAll("</last>") catch return error.OutOfMemory;
    }

    w.writeAll("<count>") catch return error.OutOfMemory;
    w.print("{d}", .{result.messages.len}) catch return error.OutOfMemory;
    w.writeAll("</count></set></fin></iq>") catch return error.OutOfMemory;

    return try allocator.dupe(u8, fbs.getWritten());
}

/// Write ISO 8601 timestamp from unix epoch seconds.
fn writeTimestamp(w: anytype, timestamp: u64) !void {
    const epoch: i64 = @intCast(timestamp);
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch) };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();

    w.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        @as(u32, @intFromEnum(md.month)),
        @as(u32, md.day_index) + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    }) catch return error.WriteFailed;
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend.MemoryBackend;

test "handleMamQuery: basic query returns messages" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1700000000, "<message from='bob@example.com'><body>hello</body></message>");
    try store.store("alice@example.com", "bob@example.com", "msg-002", 1700001000, "<message from='bob@example.com'><body>world</body></message>");

    var response = try handleMamQuery(MemoryBackend, &store, .{
        .iq_id = "q1",
        .owner = "alice@example.com",
        .query_id = "mam-query-1",
    }, std.testing.allocator);
    defer response.deinit();

    try std.testing.expectEqual(@as(usize, 2), response.messages.len);
    // Verify result messages contain the expected structure
    try std.testing.expect(std.mem.indexOf(u8, response.messages[0].xml, "urn:xmpp:mam:2") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.messages[0].xml, "msg-00") != null);
    // Verify fin IQ
    try std.testing.expect(std.mem.indexOf(u8, response.fin_iq, "complete='true'") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.fin_iq, "<count>2</count>") != null);
}

test "handleMamQuery: empty result" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    var response = try handleMamQuery(MemoryBackend, &store, .{
        .iq_id = "q2",
        .owner = "alice@example.com",
        .query_id = "empty",
    }, std.testing.allocator);
    defer response.deinit();

    try std.testing.expectEqual(@as(usize, 0), response.messages.len);
    try std.testing.expect(std.mem.indexOf(u8, response.fin_iq, "complete='true'") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.fin_iq, "<count>0</count>") != null);
}

test "handleMamQuery: with contact filter" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1700000000, "<m>bob</m>");
    try store.store("alice@example.com", "carol@example.com", "msg-002", 1700001000, "<m>carol</m>");

    var response = try handleMamQuery(MemoryBackend, &store, .{
        .iq_id = "q3",
        .owner = "alice@example.com",
        .query_id = "filter",
        .with = "bob@example.com",
    }, std.testing.allocator);
    defer response.deinit();

    try std.testing.expectEqual(@as(usize, 1), response.messages.len);
}

test "handleMamQuery: max limit produces incomplete" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1700000000, "<m>1</m>");
    try store.store("alice@example.com", "bob@example.com", "msg-002", 1700001000, "<m>2</m>");
    try store.store("alice@example.com", "bob@example.com", "msg-003", 1700002000, "<m>3</m>");

    var response = try handleMamQuery(MemoryBackend, &store, .{
        .iq_id = "q4",
        .owner = "alice@example.com",
        .query_id = "limited",
        .max = 2,
    }, std.testing.allocator);
    defer response.deinit();

    try std.testing.expectEqual(@as(usize, 2), response.messages.len);
    // When not complete, the fin should NOT have complete='true'
    try std.testing.expect(std.mem.indexOf(u8, response.fin_iq, "complete='true'") == null);
}

test "writeTimestamp: formats correctly" {
    var buf: [32]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeTimestamp(fbs.writer(), 1700000000);
    try std.testing.expectEqualStrings("2023-11-14T22:13:20Z", fbs.getWritten());
}
