//! # InviteStore — Invitation code storage for in-band registration
//!
//! Stores invitation codes in a StorageBackend. Codes are required for
//! account creation when `--require-invite` is set (default: true).
//!
//! ## Binary format (12 bytes)
//!
//! ```
//! | max_uses (2 BE) | current_uses (2 BE) | expires_epoch (4 BE) | created_epoch (4 BE) |
//! ```
//!
//! Namespace: `invites`, Key: invite code string (e.g., `INV-a1b2c3d4e5f6`)

const std = @import("std");
const backend_mod = @import("backend");

const log = std.log.scoped(.invite_store);

const NAMESPACE = "invites";
const VALUE_SIZE = 12;

pub const InviteRecord = struct {
    max_uses: u16,
    current_uses: u16,
    expires_epoch: u32,
    created_epoch: u32,
};

pub fn InviteStore(comptime Backend: type) type {
    comptime backend_mod.assertBackend(Backend);

    return struct {
        backend: *Backend,

        const Self = @This();

        pub fn init(b: *Backend) Self {
            return .{ .backend = b };
        }

        /// Create a new invitation code.
        pub fn create(self: *Self, code: []const u8, max_uses: u16, expires_epoch: u32) !void {
            const now = currentEpoch();
            const value = serialize(.{
                .max_uses = max_uses,
                .current_uses = 0,
                .expires_epoch = expires_epoch,
                .created_epoch = now,
            });
            try self.backend.put(NAMESPACE, code, &value);
            log.info("invite created: {s} (max_uses={d}, expires={d})", .{ code, max_uses, expires_epoch });
        }

        /// Validate and consume an invitation code.
        /// Returns true if the code is valid and was consumed, false otherwise.
        pub fn validate(self: *Self, allocator: std.mem.Allocator, code: []const u8) !bool {
            const raw = self.backend.get(allocator, NAMESPACE, code) catch return false;
            const data = raw orelse return false;
            defer allocator.free(data);

            if (data.len < VALUE_SIZE) return false;
            var record = deserialize(data[0..VALUE_SIZE]);

            const now = currentEpoch();

            // Check expiry
            if (record.expires_epoch > 0 and now >= record.expires_epoch) {
                log.info("invite expired: {s}", .{code});
                return false;
            }

            // Check uses
            if (record.current_uses >= record.max_uses) {
                log.info("invite exhausted: {s} ({d}/{d})", .{ code, record.current_uses, record.max_uses });
                return false;
            }

            // Consume one use
            record.current_uses += 1;
            const updated = serialize(record);
            try self.backend.put(NAMESPACE, code, &updated);

            log.info("invite consumed: {s} ({d}/{d})", .{ code, record.current_uses, record.max_uses });
            return true;
        }

        /// Get an invitation record by code.
        pub fn get(self: *Self, allocator: std.mem.Allocator, code: []const u8) !?InviteRecord {
            const raw = self.backend.get(allocator, NAMESPACE, code) catch return null;
            const data = raw orelse return null;
            defer allocator.free(data);

            if (data.len < VALUE_SIZE) return null;
            return deserialize(data[0..VALUE_SIZE]);
        }

        /// Revoke (delete) an invitation code.
        pub fn revoke(self: *Self, allocator: std.mem.Allocator, code: []const u8) !void {
            const existing = try self.backend.get(allocator, NAMESPACE, code);
            if (existing) |v| {
                allocator.free(v);
                try self.backend.delete(NAMESPACE, code);
                log.info("invite revoked: {s}", .{code});
            }
        }

        /// List all invitation codes. Caller owns returned slices.
        pub fn list(self: *Self, allocator: std.mem.Allocator) ![]InviteEntry {
            var iter = try self.backend.iterator(NAMESPACE, "");

            var results = std.ArrayListUnmanaged(InviteEntry){};
            errdefer {
                for (results.items) |item| allocator.free(item.code);
                results.deinit(allocator);
            }

            while (iter.next()) |entry| {
                if (entry.value.len < VALUE_SIZE) continue;
                const code = try allocator.dupe(u8, entry.key);
                try results.append(allocator, .{
                    .code = code,
                    .record = deserialize(entry.value[0..VALUE_SIZE]),
                });
            }

            return results.toOwnedSlice(allocator);
        }

        pub const InviteEntry = struct {
            code: []const u8,
            record: InviteRecord,
        };

        pub fn freeEntries(allocator: std.mem.Allocator, entries: []const InviteEntry) void {
            for (entries) |entry| allocator.free(entry.code);
            allocator.free(entries);
        }
    };
}

fn serialize(record: InviteRecord) [VALUE_SIZE]u8 {
    var buf: [VALUE_SIZE]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], record.max_uses, .big);
    std.mem.writeInt(u16, buf[2..4], record.current_uses, .big);
    std.mem.writeInt(u32, buf[4..8], record.expires_epoch, .big);
    std.mem.writeInt(u32, buf[8..12], record.created_epoch, .big);
    return buf;
}

fn deserialize(data: *const [VALUE_SIZE]u8) InviteRecord {
    return .{
        .max_uses = std.mem.readInt(u16, data[0..2], .big),
        .current_uses = std.mem.readInt(u16, data[2..4], .big),
        .expires_epoch = std.mem.readInt(u32, data[4..8], .big),
        .created_epoch = std.mem.readInt(u32, data[8..12], .big),
    };
}

fn currentEpoch() u32 {
    const ts = std.time.timestamp();
    return @intCast(@as(u64, @bitCast(ts)) & 0xFFFFFFFF);
}

/// Generate a random invitation code: INV-{12 hex chars}
pub fn generateCode(buf: *[16]u8) []const u8 {
    const prefix = "INV-";
    @memcpy(buf[0..4], prefix);
    var random_bytes: [6]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    const hex_chars = "0123456789abcdef";
    for (random_bytes, 0..) |b, i| {
        buf[4 + i * 2] = hex_chars[b >> 4];
        buf[4 + i * 2 + 1] = hex_chars[b & 0xf];
    }
    return buf[0..16];
}

// ============================================================================
// Tests
// ============================================================================

test "InviteStore: create and validate" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = InviteStore(MemoryBackend).init(&db);

    try store.create("INV-test123", 2, 0); // no expiry

    // First use
    try std.testing.expect(try store.validate(allocator, "INV-test123"));
    // Second use
    try std.testing.expect(try store.validate(allocator, "INV-test123"));
    // Third use — exhausted
    try std.testing.expect(!try store.validate(allocator, "INV-test123"));
}

test "InviteStore: invalid code returns false" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = InviteStore(MemoryBackend).init(&db);

    try std.testing.expect(!try store.validate(allocator, "INV-nonexistent"));
}

test "InviteStore: revoke" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = InviteStore(MemoryBackend).init(&db);

    try store.create("INV-revokeme", 5, 0);
    try store.revoke(allocator, "INV-revokeme");
    try std.testing.expect(!try store.validate(allocator, "INV-revokeme"));
}

test "InviteStore: get record" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = InviteStore(MemoryBackend).init(&db);

    try store.create("INV-info", 3, 0);
    const record = try store.get(allocator, "INV-info");
    try std.testing.expect(record != null);
    try std.testing.expectEqual(@as(u16, 3), record.?.max_uses);
    try std.testing.expectEqual(@as(u16, 0), record.?.current_uses);
}

test "generateCode: produces 16-char code" {
    var buf: [16]u8 = undefined;
    const code = generateCode(&buf);
    try std.testing.expectEqual(@as(usize, 16), code.len);
    try std.testing.expectEqualStrings("INV-", code[0..4]);
}
