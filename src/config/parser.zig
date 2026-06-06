//! # INI Config Parser — Shared configuration for all xmppd daemons
//!
//! Minimal INI-style config parser supporting:
//! - `[section]` headers
//! - `key = value` pairs (whitespace around `=` is trimmed)
//! - `#` and `;` line comments
//! - Empty lines ignored
//! - Keys before any section header go into the "" (root) section
//!
//! ## Usage
//!
//! ```zig
//! const config = @import("config");
//! var cfg = try config.parse(allocator, "/usr/local/etc/xmppd/xmppd.conf");
//! defer cfg.deinit();
//! const issuer = cfg.get("oidc", "issuer") orelse return error.MissingConfig;
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Config = struct {
    allocator: Allocator,
    /// section → (key → value)
    sections: std.StringHashMap(std.StringHashMap([]const u8)),
    /// All owned strings (keys, values, section names from file content).
    content: []const u8,

    pub fn deinit(self: *Config) void {
        var sec_it = self.sections.iterator();
        while (sec_it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.sections.deinit();
        self.allocator.free(self.content);
    }

    /// Get a value from a section. Returns null if section or key doesn't exist.
    pub fn get(self: *const Config, section: []const u8, key: []const u8) ?[]const u8 {
        const sec = self.sections.get(section) orelse return null;
        return sec.get(key);
    }

    /// Get a value from the root (no section) area.
    pub fn getRoot(self: *const Config, key: []const u8) ?[]const u8 {
        return self.get("", key);
    }
};

/// Parse an INI config file at the given path.
pub fn parse(allocator: Allocator, path: []const u8) !Config {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024); // 1MB max

    var sections = std.StringHashMap(std.StringHashMap([]const u8)).init(allocator);

    // Ensure root section exists
    try sections.put("", std.StringHashMap([]const u8).init(allocator));

    var current_section: []const u8 = "";

    var line_iter = std.mem.splitScalar(u8, content, '\n');
    while (line_iter.next()) |raw_line| {
        // Strip \r for Windows line endings
        const line = std.mem.trimRight(u8, raw_line, "\r");

        // Trim leading/trailing whitespace
        const trimmed = std.mem.trim(u8, line, " \t");

        // Skip empty lines and comments
        if (trimmed.len == 0) continue;
        if (trimmed[0] == '#' or trimmed[0] == ';') continue;

        // Section header
        if (trimmed[0] == '[') {
            if (std.mem.indexOfScalar(u8, trimmed, ']')) |end| {
                current_section = trimmed[1..end];
                if (!sections.contains(current_section)) {
                    try sections.put(current_section, std.StringHashMap([]const u8).init(allocator));
                }
            }
            continue;
        }

        // Key = value
        if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_pos| {
            const key = std.mem.trimRight(u8, trimmed[0..eq_pos], " \t");
            const value = std.mem.trimLeft(u8, trimmed[eq_pos + 1 ..], " \t");

            if (key.len == 0) continue;

            const sec_map = sections.getPtr(current_section) orelse continue;
            try sec_map.put(key, value);
        }
    }

    return Config{
        .allocator = allocator,
        .sections = sections,
        .content = content,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parse basic config" {
    const allocator = std.testing.allocator;

    // Write a temp file
    const tmp_path = "/tmp/xmppd-config-test.ini";
    {
        const file = try std.fs.cwd().createFile(tmp_path, .{});
        defer file.close();
        var buf: [0]u8 = .{};
        var writer = file.writer(&buf);
        try writer.interface.writeAll(
            \\# Global settings
            \\hostname = securemessage.cc
            \\tls_cert = /etc/xmppd/server.pem
            \\
            \\[auth]
            \\rate_max_per_account = 5
            \\rate_max_per_ip = 20
            \\
            \\[oidc]
            \\issuer = https://auth.morante.dev/auth/v1
            \\client_id = xmppd
            \\client_secret = s3cr3t
            \\
        );
    }
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    var cfg = try parse(allocator, tmp_path);
    defer cfg.deinit();

    // Root section
    try std.testing.expectEqualStrings("securemessage.cc", cfg.getRoot("hostname").?);
    try std.testing.expectEqualStrings("/etc/xmppd/server.pem", cfg.getRoot("tls_cert").?);

    // [auth] section
    try std.testing.expectEqualStrings("5", cfg.get("auth", "rate_max_per_account").?);
    try std.testing.expectEqualStrings("20", cfg.get("auth", "rate_max_per_ip").?);

    // [oidc] section
    try std.testing.expectEqualStrings("https://auth.morante.dev/auth/v1", cfg.get("oidc", "issuer").?);
    try std.testing.expectEqualStrings("xmppd", cfg.get("oidc", "client_id").?);
    try std.testing.expectEqualStrings("s3cr3t", cfg.get("oidc", "client_secret").?);

    // Missing key/section
    try std.testing.expect(cfg.get("oidc", "nonexistent") == null);
    try std.testing.expect(cfg.get("nosection", "key") == null);
}

test "parse with comments and empty lines" {
    const allocator = std.testing.allocator;

    const tmp_path = "/tmp/xmppd-config-test2.ini";
    {
        const file = try std.fs.cwd().createFile(tmp_path, .{});
        defer file.close();
        var buf: [0]u8 = .{};
        var writer = file.writer(&buf);
        try writer.interface.writeAll(
            \\; semicolon comment
            \\# hash comment
            \\
            \\key1 = value1
            \\  key2=value2
            \\key3 = value with spaces
            \\
        );
    }
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    var cfg = try parse(allocator, tmp_path);
    defer cfg.deinit();

    try std.testing.expectEqualStrings("value1", cfg.getRoot("key1").?);
    try std.testing.expectEqualStrings("value2", cfg.getRoot("key2").?);
    try std.testing.expectEqualStrings("value with spaces", cfg.getRoot("key3").?);
}
