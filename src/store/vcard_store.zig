//! # VCardStore — generic vCard storage
//!
//! Stores vCard XML blobs per bare JID. No serialization — values are
//! raw XML bytes stored and retrieved as-is.
//!
//! Namespace: `vcards`, Key: `bare_jid`, Value: vCard XML

const std = @import("std");
const backend_mod = @import("backend");

const NAMESPACE = "vcards";

pub fn VCardStore(comptime Backend: type) type {
    comptime backend_mod.assertBackend(Backend);

    return struct {
        backend: *Backend,

        const Self = @This();

        pub fn init(b: *Backend) Self {
            return .{ .backend = b };
        }

        pub fn deinit(self: *Self) void {
            _ = self;
        }

        /// Get a user's vCard XML. Caller owns the returned slice.
        pub fn get(self: *Self, allocator: std.mem.Allocator, bare_jid: []const u8) !?[]u8 {
            return try self.backend.get(allocator, NAMESPACE, bare_jid);
        }

        /// Set (create or replace) a user's vCard.
        pub fn set(self: *Self, bare_jid: []const u8, xml: []const u8) !void {
            try self.backend.put(NAMESPACE, bare_jid, xml);
        }

        /// Delete a user's vCard.
        pub fn delete(self: *Self, bare_jid: []const u8) !void {
            try self.backend.delete(NAMESPACE, bare_jid);
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;
const TestStore = VCardStore(MemoryBackend);

test "VCardStore: set and get" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    const vcard = "<vCard xmlns='vcard-temp'><FN>Alice</FN></vCard>";
    try store.set("alice@localhost", vcard);

    const result = try store.get(std.testing.allocator, "alice@localhost");
    defer if (result) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings(vcard, result.?);
}

test "VCardStore: get missing" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    const result = try store.get(std.testing.allocator, "nobody@localhost");
    try std.testing.expect(result == null);
}

test "VCardStore: update" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.set("alice@localhost", "<vCard><FN>Old</FN></vCard>");
    try store.set("alice@localhost", "<vCard><FN>New</FN></vCard>");

    const result = try store.get(std.testing.allocator, "alice@localhost");
    defer if (result) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("<vCard><FN>New</FN></vCard>", result.?);
}

test "VCardStore: delete" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.set("alice@localhost", "<vCard/>");
    try store.delete("alice@localhost");

    const result = try store.get(std.testing.allocator, "alice@localhost");
    try std.testing.expect(result == null);
}
