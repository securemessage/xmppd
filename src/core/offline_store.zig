//! # OfflineStore — flat-file offline message storage
//!
//! Stores messages for users who are not currently online. When the
//! recipient connects and sends initial presence, queued messages are
//! delivered and removed from the store.
//!
//! ## File format
//!
//! One message per line, pipe-delimited:
//! ```
//! recipient_bare_jid|from_full_jid|timestamp|type|id|xml_payload
//! ```
//!
//! The xml_payload is the full serialized `<message>` stanza (minus outer
//! `<message>` tags) — i.e., the inner XML children (body, thread, etc.).
//! Pipe characters within the payload are preserved via simple escaping
//! (pipes in payload are replaced with \x7C on write and restored on read).
//!
//! ## Lifecycle
//!
//! - `storeMessage()` — called when a message targets an unavailable user
//! - `getMessages()` — retrieves all queued messages for a bare JID
//! - `clearMessages()` — removes all queued messages for a bare JID after delivery
//! - `save()` — atomic write (temp + rename)
//!
//! Messages are stored in-memory and persisted to disk on every store/clear.

const std = @import("std");

const log = std.log.scoped(.offline_store);

/// Maximum number of offline messages per user.
const MAX_PER_USER = 100;

/// Maximum total offline messages in the store.
const MAX_TOTAL = 10000;

/// A single offline message entry.
pub const OfflineMessage = struct {
    /// Bare JID of the recipient (e.g., "bob@localhost").
    recipient: []const u8,
    /// Full JID of the sender (e.g., "alice@localhost/desktop").
    from: []const u8,
    /// Unix timestamp when the message was stored.
    timestamp: i64,
    /// Message type (chat, normal, groupchat, headline, error).
    msg_type: []const u8,
    /// Message id attribute (may be empty).
    msg_id: []const u8,
    /// Inner XML content (body, thread, etc.) — already serialized.
    inner_xml: []const u8,
};

/// Offline message store — all pending messages in memory.
pub const OfflineStore = struct {
    messages: std.ArrayListUnmanaged(OfflineMessage),
    /// Arena allocator for string data.
    arena: std.heap.ArenaAllocator,
    /// Backing allocator (for ArrayListUnmanaged).
    allocator: std.mem.Allocator,
    /// Path to the offline messages file.
    path: []const u8,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) OfflineStore {
        return .{
            .messages = .{},
            .arena = std.heap.ArenaAllocator.init(allocator),
            .allocator = allocator,
            .path = path,
        };
    }

    pub fn deinit(self: *OfflineStore) void {
        self.messages.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Load offline messages from disk.
    pub fn load(self: *OfflineStore) !void {
        const file = std.fs.cwd().openFile(self.path, .{}) catch |err| switch (err) {
            error.FileNotFound => return, // No offline messages yet
            else => return err,
        };
        defer file.close();

        const alloc = self.arena.allocator();
        const contents = try file.readToEndAlloc(alloc, 4 * 1024 * 1024);

        var lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;
            self.parseLine(trimmed) catch continue;
        }

        log.info("loaded {d} offline messages from {s}", .{ self.messages.items.len, self.path });
    }

    fn parseLine(self: *OfflineStore, line: []const u8) !void {
        // Format: recipient|from|timestamp|type|id|inner_xml
        var fields: [6][]const u8 = undefined;
        var field_count: usize = 0;
        var start: usize = 0;

        for (line, 0..) |ch, i| {
            if (ch == '|' and field_count < 5) {
                fields[field_count] = line[start..i];
                field_count += 1;
                start = i + 1;
            }
        }
        // Last field (inner_xml) takes the rest — may contain pipes (escaped)
        if (field_count == 5) {
            fields[5] = line[start..];
        } else {
            return error.InvalidFormat;
        }

        const arena_alloc = self.arena.allocator();
        const msg = OfflineMessage{
            .recipient = try arena_alloc.dupe(u8, fields[0]),
            .from = try arena_alloc.dupe(u8, fields[1]),
            .timestamp = std.fmt.parseInt(i64, fields[2], 10) catch 0,
            .msg_type = try arena_alloc.dupe(u8, fields[3]),
            .msg_id = try arena_alloc.dupe(u8, fields[4]),
            .inner_xml = try self.unescapePayload(arena_alloc, fields[5]),
        };

        try self.messages.append(self.allocator, msg);
    }

    /// Store a message for an offline recipient.
    /// Returns false if the user's queue is full.
    pub fn storeMessage(
        self: *OfflineStore,
        recipient: []const u8,
        from: []const u8,
        msg_type: []const u8,
        msg_id: []const u8,
        inner_xml: []const u8,
    ) bool {
        // Check total limit
        if (self.messages.items.len >= MAX_TOTAL) {
            log.warn("offline store full ({d} messages), dropping message for {s}", .{ MAX_TOTAL, recipient });
            return false;
        }

        // Check per-user limit
        var count: usize = 0;
        for (self.messages.items) |m| {
            if (std.mem.eql(u8, m.recipient, recipient)) {
                count += 1;
                if (count >= MAX_PER_USER) {
                    log.warn("offline queue full for {s} ({d} messages)", .{ recipient, MAX_PER_USER });
                    return false;
                }
            }
        }

        const arena_alloc = self.arena.allocator();
        const msg = OfflineMessage{
            .recipient = arena_alloc.dupe(u8, recipient) catch return false,
            .from = arena_alloc.dupe(u8, from) catch return false,
            .timestamp = std.time.timestamp(),
            .msg_type = arena_alloc.dupe(u8, msg_type) catch return false,
            .msg_id = arena_alloc.dupe(u8, msg_id) catch return false,
            .inner_xml = arena_alloc.dupe(u8, inner_xml) catch return false,
        };

        self.messages.append(self.allocator, msg) catch return false;

        log.info("stored offline message for {s} from {s}", .{ recipient, from });

        // Persist to disk
        self.save() catch |err| {
            log.warn("failed to persist offline store: {}", .{err});
        };

        return true;
    }

    /// Get all pending messages for a bare JID.
    /// Returns a slice of OfflineMessage (references into the store).
    pub fn getMessages(self: *OfflineStore, recipient: []const u8, result_buf: []OfflineMessage) usize {
        var count: usize = 0;
        for (self.messages.items) |m| {
            if (std.mem.eql(u8, m.recipient, recipient)) {
                if (count >= result_buf.len) break;
                result_buf[count] = m;
                count += 1;
            }
        }
        return count;
    }

    /// Count pending messages for a bare JID.
    pub fn countMessages(self: *OfflineStore, recipient: []const u8) usize {
        var count: usize = 0;
        for (self.messages.items) |m| {
            if (std.mem.eql(u8, m.recipient, recipient)) count += 1;
        }
        return count;
    }

    /// Remove all pending messages for a bare JID (after delivery).
    pub fn clearMessages(self: *OfflineStore, recipient: []const u8) void {
        // Remove in reverse to avoid index shifting issues
        var i: usize = self.messages.items.len;
        while (i > 0) {
            i -= 1;
            if (std.mem.eql(u8, self.messages.items[i].recipient, recipient)) {
                _ = self.messages.orderedRemove(i);
            }
        }

        // Persist to disk
        self.save() catch |err| {
            log.warn("failed to persist offline store after clear: {}", .{err});
        };
    }

    /// Atomic save: write to temp file, then rename.
    pub fn save(self: *OfflineStore) !void {
        // Build temp path
        var tmp_buf: [1024]u8 = undefined;
        const tmp_path = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{self.path}) catch return error.PathTooLong;

        // Build content in memory (offline messages are bounded — max ~2MB)
        var content_buf: [2 * 1024 * 1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&content_buf);
        const w = fbs.writer();

        for (self.messages.items) |m| {
            w.writeAll(m.recipient) catch return error.WriteFailed;
            w.writeByte('|') catch return error.WriteFailed;
            w.writeAll(m.from) catch return error.WriteFailed;
            w.writeByte('|') catch return error.WriteFailed;
            w.print("{d}", .{m.timestamp}) catch return error.WriteFailed;
            w.writeByte('|') catch return error.WriteFailed;
            w.writeAll(m.msg_type) catch return error.WriteFailed;
            w.writeByte('|') catch return error.WriteFailed;
            w.writeAll(m.msg_id) catch return error.WriteFailed;
            w.writeByte('|') catch return error.WriteFailed;
            self.escapePayload(w, m.inner_xml) catch return error.WriteFailed;
            w.writeByte('\n') catch return error.WriteFailed;
        }

        // Write to temp file
        const file = std.fs.cwd().createFile(tmp_path, .{}) catch return error.WriteFailed;
        defer file.close();
        file.writeAll(fbs.getWritten()) catch return error.WriteFailed;

        // Atomic rename
        std.fs.cwd().rename(tmp_path, self.path) catch |err| {
            log.warn("failed to rename {s} → {s}: {}", .{ tmp_path, self.path, err });
            return err;
        };
    }

    /// Escape pipe characters in payload for storage.
    fn escapePayload(self: *OfflineStore, writer: anytype, data: []const u8) !void {
        _ = self;
        for (data) |ch| {
            if (ch == '|') {
                try writer.writeAll("\\x7C");
            } else if (ch == '\\') {
                try writer.writeAll("\\\\");
            } else if (ch == '\n') {
                try writer.writeAll("\\n");
            } else {
                try writer.writeByte(ch);
            }
        }
    }

    /// Unescape payload from storage format.
    fn unescapePayload(self: *OfflineStore, arena_alloc: std.mem.Allocator, data: []const u8) ![]const u8 {
        _ = self;
        // Fast path: no escapes
        if (std.mem.indexOf(u8, data, "\\") == null) {
            return try arena_alloc.dupe(u8, data);
        }

        var result = try arena_alloc.alloc(u8, data.len);
        var out_i: usize = 0;
        var in_i: usize = 0;

        while (in_i < data.len) {
            if (data[in_i] == '\\' and in_i + 1 < data.len) {
                if (data[in_i + 1] == '\\') {
                    result[out_i] = '\\';
                    out_i += 1;
                    in_i += 2;
                } else if (data[in_i + 1] == 'n') {
                    result[out_i] = '\n';
                    out_i += 1;
                    in_i += 2;
                } else if (in_i + 3 < data.len and std.mem.eql(u8, data[in_i + 1 .. in_i + 4], "x7C")) {
                    result[out_i] = '|';
                    out_i += 1;
                    in_i += 4;
                } else {
                    result[out_i] = data[in_i];
                    out_i += 1;
                    in_i += 1;
                }
            } else {
                result[out_i] = data[in_i];
                out_i += 1;
                in_i += 1;
            }
        }

        return result[0..out_i];
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "store and retrieve offline message" {
    var store = OfflineStore.init(testing.allocator, "/tmp/xmppd-test-offline.dat");
    defer store.deinit();

    const stored = store.storeMessage(
        "bob@localhost",
        "alice@localhost/desktop",
        "chat",
        "msg1",
        "<body>Hello Bob!</body>",
    );
    try testing.expect(stored);
    try testing.expectEqual(@as(usize, 1), store.messages.items.len);

    var buf: [100]OfflineMessage = undefined;
    const count = store.getMessages("bob@localhost", &buf);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("bob@localhost", buf[0].recipient);
    try testing.expectEqualStrings("alice@localhost/desktop", buf[0].from);
    try testing.expectEqualStrings("chat", buf[0].msg_type);
    try testing.expectEqualStrings("msg1", buf[0].msg_id);
    try testing.expectEqualStrings("<body>Hello Bob!</body>", buf[0].inner_xml);
}

test "clear messages after delivery" {
    var store = OfflineStore.init(testing.allocator, "/tmp/xmppd-test-offline2.dat");
    defer store.deinit();

    _ = store.storeMessage("bob@localhost", "alice@localhost/desktop", "chat", "m1", "<body>1</body>");
    _ = store.storeMessage("bob@localhost", "carol@localhost/phone", "chat", "m2", "<body>2</body>");
    _ = store.storeMessage("alice@localhost", "bob@localhost/mobile", "chat", "m3", "<body>3</body>");

    try testing.expectEqual(@as(usize, 3), store.messages.items.len);
    try testing.expectEqual(@as(usize, 2), store.countMessages("bob@localhost"));
    try testing.expectEqual(@as(usize, 1), store.countMessages("alice@localhost"));

    store.clearMessages("bob@localhost");
    try testing.expectEqual(@as(usize, 1), store.messages.items.len);
    try testing.expectEqual(@as(usize, 0), store.countMessages("bob@localhost"));
    try testing.expectEqual(@as(usize, 1), store.countMessages("alice@localhost"));
}

test "per-user limit enforced" {
    var store = OfflineStore.init(testing.allocator, "/tmp/xmppd-test-offline3.dat");
    defer store.deinit();

    // Store MAX_PER_USER messages
    var i: usize = 0;
    while (i < MAX_PER_USER) : (i += 1) {
        const stored = store.storeMessage("bob@localhost", "alice@localhost/d", "chat", "", "<body>x</body>");
        try testing.expect(stored);
    }

    // Next one should fail
    const overflow = store.storeMessage("bob@localhost", "alice@localhost/d", "chat", "", "<body>y</body>");
    try testing.expect(!overflow);

    // Different user should still work
    const other = store.storeMessage("carol@localhost", "alice@localhost/d", "chat", "", "<body>z</body>");
    try testing.expect(other);
}

test "escape and unescape payload with pipes and newlines" {
    var store = OfflineStore.init(testing.allocator, "/tmp/xmppd-test-offline4.dat");
    defer store.deinit();

    const payload = "<body>line1\nline2|pipe\\backslash</body>";
    _ = store.storeMessage("bob@localhost", "alice@localhost/d", "chat", "m1", payload);

    // Save and reload
    try store.save();

    var store2 = OfflineStore.init(testing.allocator, "/tmp/xmppd-test-offline4.dat");
    defer store2.deinit();
    try store2.load();

    try testing.expectEqual(@as(usize, 1), store2.messages.items.len);
    try testing.expectEqualStrings(payload, store2.messages.items[0].inner_xml);

    // Cleanup
    std.fs.cwd().deleteFile("/tmp/xmppd-test-offline4.dat") catch {};
}
