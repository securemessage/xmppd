//! # xmppctl — User management CLI
//!
//! Administrative tool for managing xmppd user accounts. Operates directly
//! on the user store file (not via IPC). After modifications, send SIGHUP
//! to xmppd-auth to reload.
//!
//! ## Commands
//!
//! ```
//! xmppctl adduser alice@example.com       # prompts for password
//! xmppctl deluser alice@example.com
//! xmppctl passwd  alice@example.com       # change password
//! xmppctl listusers
//! ```

const std = @import("std");
const posix = std.posix;
const UserStore = @import("user_store").UserStore;

const log = std.log.scoped(.xmppctl);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var db_path: []const u8 = "/var/db/xmppd/users.db";

    _ = args.next(); // Skip argv[0]

    // Check for --db option first
    var remaining_args: std.ArrayListUnmanaged([]const u8) = .{};
    defer remaining_args.deinit(allocator);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--db")) {
            db_path = args.next() orelse {
                printErr("--db requires a value\n");
                return error.InvalidArgs;
            };
        } else {
            try remaining_args.append(allocator, arg);
        }
    }

    if (remaining_args.items.len == 0) {
        printUsage();
        return error.InvalidArgs;
    }

    const command = remaining_args.items[0];

    // Open user store
    var store = UserStore.init(allocator, db_path);
    defer store.deinit();
    try store.load();

    if (std.mem.eql(u8, command, "adduser")) {
        if (remaining_args.items.len < 2) {
            printErr("adduser requires a JID argument\n");
            return error.InvalidArgs;
        }
        const jid = remaining_args.items[1];
        const username = extractLocal(jid);

        // Read password from stdin
        const password = try readPassword("Password: ");
        if (password.len < 1) {
            printErr("password cannot be empty\n");
            return error.InvalidArgs;
        }

        // Confirm
        const confirm = try readPassword("Confirm password: ");
        if (!std.mem.eql(u8, password, confirm)) {
            printErr("passwords do not match\n");
            return error.InvalidArgs;
        }

        store.addUser(username, password) catch |err| {
            switch (err) {
                error.UserExists => printErr("user already exists\n"),
                else => {
                    printErr("failed to add user\n");
                    return err;
                },
            }
            return err;
        };
        printOut("User ");
        printOut(jid);
        printOut(" created.\n");
        signalAuthDaemon();
    } else if (std.mem.eql(u8, command, "deluser")) {
        if (remaining_args.items.len < 2) {
            printErr("deluser requires a JID argument\n");
            return error.InvalidArgs;
        }
        const jid = remaining_args.items[1];
        const username = extractLocal(jid);

        store.removeUser(username) catch |err| {
            switch (err) {
                error.UserNotFound => printErr("user not found\n"),
                else => return err,
            }
            return err;
        };
        printOut("User ");
        printOut(jid);
        printOut(" removed.\n");
        signalAuthDaemon();
    } else if (std.mem.eql(u8, command, "passwd")) {
        if (remaining_args.items.len < 2) {
            printErr("passwd requires a JID argument\n");
            return error.InvalidArgs;
        }
        const jid = remaining_args.items[1];
        const username = extractLocal(jid);

        const password = try readPassword("New password: ");
        const confirm = try readPassword("Confirm password: ");
        if (!std.mem.eql(u8, password, confirm)) {
            printErr("passwords do not match\n");
            return error.InvalidArgs;
        }

        store.changePassword(username, password) catch |err| {
            switch (err) {
                error.UserNotFound => printErr("user not found\n"),
                else => return err,
            }
            return err;
        };
        printOut("Password changed for ");
        printOut(jid);
        printOut(".\n");
        signalAuthDaemon();
    } else if (std.mem.eql(u8, command, "listusers")) {
        const users = try store.listUsers(allocator);
        defer allocator.free(users);

        if (users.len == 0) {
            printOut("No users.\n");
        } else {
            for (users) |username| {
                printOut(username);
                printOut("\n");
            }
        }
    } else {
        printErr("unknown command: ");
        printErr(command);
        printErr("\n");
        printUsage();
        return error.InvalidArgs;
    }
}

/// Extract the localpart from a JID (before the @).
/// If there's no @, return the whole string as the username.
fn extractLocal(jid: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, jid, '@')) |at| {
        return jid[0..at];
    }
    return jid;
}

/// Read a password from stdin (with terminal echo disabled if possible).
fn readPassword(prompt: []const u8) ![]const u8 {
    printErr(prompt);

    // Try to disable echo
    const stdin_fd = std.posix.STDIN_FILENO;
    var old_termios: std.c.termios = undefined;
    var termios_saved = false;
    if (std.c.tcgetattr(stdin_fd, &old_termios) == 0) {
        var new_termios = old_termios;
        new_termios.lflag.ECHO = false;
        _ = std.c.tcsetattr(stdin_fd, .NOW, &new_termios);
        termios_saved = true;
    }
    defer {
        if (termios_saved) {
            _ = std.c.tcsetattr(stdin_fd, .NOW, &old_termios);
            printErr("\n");
        }
    }

    var buf: [256]u8 = undefined;
    const n = posix.read(stdin_fd, &buf) catch return error.ReadFailed;
    if (n == 0) return error.ReadFailed;

    // Strip trailing newline
    var end = n;
    if (end > 0 and buf[end - 1] == '\n') end -= 1;
    if (end > 0 and buf[end - 1] == '\r') end -= 1;

    return buf[0..end];
}

/// Try to send SIGHUP to xmppd-auth if a PID file exists.
fn signalAuthDaemon() void {
    const pid_path = "/var/run/xmppd/auth.pid";
    const file = std.fs.cwd().openFile(pid_path, .{}) catch return;
    defer file.close();

    var buf: [32]u8 = undefined;
    const n = file.read(&buf) catch return;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\r\n");
    const pid = std.fmt.parseInt(posix.pid_t, trimmed, 10) catch return;
    _ = std.c.kill(pid, posix.SIG.HUP);
}

fn printOut(msg: []const u8) void {
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(msg) catch {};
}

fn printErr(msg: []const u8) void {
    var buf: [0]u8 = .{};
    var stderr = std.fs.File.stderr().writer(&buf);
    stderr.interface.writeAll(msg) catch {};
}

fn printUsage() void {
    printErr(
        \\Usage: xmppctl [--db PATH] COMMAND [ARGS]
        \\
        \\Commands:
        \\  adduser JID     Create a user account
        \\  deluser JID     Remove a user account
        \\  passwd  JID     Change a user's password
        \\  listusers       List all users
        \\
        \\Options:
        \\  --db PATH       Path to users.db (default: /var/db/xmppd/users.db)
        \\
    );
}

// ============================================================================
// Tests
// ============================================================================

test "extractLocal: JID with domain" {
    try std.testing.expectEqualStrings("alice", extractLocal("alice@example.com"));
}

test "extractLocal: bare username" {
    try std.testing.expectEqualStrings("alice", extractLocal("alice"));
}

test "extractLocal: JID with resource" {
    try std.testing.expectEqualStrings("alice", extractLocal("alice@example.com/phone"));
}
