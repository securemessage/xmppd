//! # xmppctl — User management CLI
//!
//! Administrative tool for managing xmppd user accounts. Operates directly
//! on the storage backend (LMDB by default). After modifications, send SIGHUP
//! to xmppd-auth (no-op for LMDB — it sees changes immediately).
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
const xmppd_log = @import("xmppd_log");
pub const std_options = xmppd_log.std_options;

const posix = std.posix;
const OpBackendType = @import("op_backend").Backend;
const user_store_mod = @import("user_store");
const UserStore = user_store_mod.UserStore(OpBackendType);
const lock_store_mod = @import("lock_store");
const LockStore = lock_store_mod.LockStore(OpBackendType);
const invite_store_mod = @import("invite_store");
const InviteStore = invite_store_mod.InviteStore(OpBackendType);
const ipc_protocol = @import("ipc_protocol");

const log = std.log.scoped(.xmppctl);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var db_path: []const u8 = "/var/db/xmppd";
    var auth_socket: []const u8 = "/var/run/xmppd/auth.sock";
    var cli_password: ?[]const u8 = null;
    var password_file: ?[]const u8 = null;

    _ = args.next(); // Skip argv[0]

    // Check for global options first
    var remaining_args: std.ArrayListUnmanaged([]const u8) = .{};
    defer remaining_args.deinit(allocator);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--db")) {
            db_path = args.next() orelse {
                printErr("--db requires a value\n");
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--auth-socket")) {
            auth_socket = args.next() orelse {
                printErr("--auth-socket requires a value\n");
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--password")) {
            cli_password = args.next() orelse {
                printErr("--password requires a value\n");
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--password-file")) {
            password_file = args.next() orelse {
                printErr("--password-file requires a value\n");
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

    // Try IPC to running auth daemon first for adduser/deluser/passwd.
    // This is required for RocksDB (exclusive lock) and preferred for all backends.
    if (std.mem.eql(u8, command, "adduser") or std.mem.eql(u8, command, "deluser") or std.mem.eql(u8, command, "passwd")) {
        if (tryIpcCommand(command, remaining_args.items, auth_socket, cli_password, password_file)) {
            return; // IPC succeeded
        }
        // Fall through to direct DB access
    }

    // Build auth-specific sub-path: {db_path}/auth
    var auth_path_buf: [1024]u8 = undefined;
    const auth_path = std.fmt.bufPrint(&auth_path_buf, "{s}/auth", .{db_path}) catch {
        printErr("db path too long\n");
        return error.InvalidArgs;
    };

    // Open storage backend
    var backend = try OpBackendType.open(auth_path, .{});
    defer backend.close();
    var store = UserStore.init(&backend);
    var lock_store = LockStore.init(&backend);
    var invite_store = InviteStore.init(&backend);

    if (std.mem.eql(u8, command, "adduser")) {
        if (remaining_args.items.len < 2) {
            printErr("adduser requires a JID argument\n");
            return error.InvalidArgs;
        }
        const jid = remaining_args.items[1];
        const username = extractLocal(jid);

        // Resolve password: --password > --password-file > interactive prompt
        var pass_buf: [256]u8 = undefined;
        var file_buf: [256]u8 = undefined;
        const password = blk: {
            if (cli_password) |p| {
                break :blk p;
            } else if (password_file) |pf| {
                const f = std.fs.cwd().openFile(pf, .{}) catch {
                    printErr("cannot open password file\n");
                    return error.InvalidArgs;
                };
                defer f.close();
                const n = f.read(&file_buf) catch {
                    printErr("cannot read password file\n");
                    return error.InvalidArgs;
                };
                const content = std.mem.trimRight(u8, file_buf[0..n], "\r\n");
                if (content.len == 0) {
                    printErr("password file is empty\n");
                    return error.InvalidArgs;
                }
                break :blk content;
            } else {
                const p = readPassword("Password: ", &pass_buf) catch return error.InvalidArgs;
                if (p.len < 1) {
                    printErr("password cannot be empty\n");
                    return error.InvalidArgs;
                }
                // Confirm
                var confirm_buf: [256]u8 = undefined;
                const confirm = readPassword("Confirm password: ", &confirm_buf) catch return error.InvalidArgs;
                if (!std.mem.eql(u8, p, confirm)) {
                    printErr("passwords do not match\n");
                    return error.InvalidArgs;
                }
                break :blk p;
            }
        };

        store.addUser(allocator, username, password) catch |err| {
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

        store.removeUser(allocator, username) catch |err| {
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

        var pass_buf: [256]u8 = undefined;
        const password = try readPassword("New password: ", &pass_buf);
        var confirm_buf: [256]u8 = undefined;
        const confirm = try readPassword("Confirm password: ", &confirm_buf);
        if (!std.mem.eql(u8, password, confirm)) {
            printErr("passwords do not match\n");
            return error.InvalidArgs;
        }

        store.changePassword(allocator, username, password) catch |err| {
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
        defer {
            for (users) |u| allocator.free(u);
            allocator.free(users);
        }

        if (users.len == 0) {
            printOut("No users.\n");
        } else {
            for (users) |username| {
                printOut(username);
                printOut("\n");
            }
        }
    } else if (std.mem.eql(u8, command, "lock")) {
        if (remaining_args.items.len < 2) {
            printErr("lock requires a JID argument\n");
            return error.InvalidArgs;
        }
        const jid = remaining_args.items[1];
        const username = extractLocal(jid);

        lock_store.lock(username, .permanent) catch |err| {
            printErr("failed to lock account\n");
            return err;
        };
        printOut("Account ");
        printOut(jid);
        printOut(" locked.\n");
        signalAuthDaemon();
    } else if (std.mem.eql(u8, command, "unlock")) {
        if (remaining_args.items.len < 2) {
            printErr("unlock requires a JID argument\n");
            return error.InvalidArgs;
        }
        const jid = remaining_args.items[1];
        const username = extractLocal(jid);

        lock_store.unlock(allocator, username) catch |err| {
            printErr("failed to unlock account\n");
            return err;
        };
        printOut("Account ");
        printOut(jid);
        printOut(" unlocked.\n");
        signalAuthDaemon();
    } else if (std.mem.eql(u8, command, "invite")) {
        if (remaining_args.items.len < 2) {
            printErr("invite requires a subcommand: create, list, revoke\n");
            return error.InvalidArgs;
        }
        const subcmd = remaining_args.items[1];

        if (std.mem.eql(u8, subcmd, "create")) {
            // Parse --max-uses and --expires from remaining args
            var max_uses: u16 = 1;
            var expires: u32 = 0;
            var i: usize = 2;
            while (i < remaining_args.items.len) : (i += 1) {
                const a = remaining_args.items[i];
                if (std.mem.eql(u8, a, "--max-uses") and i + 1 < remaining_args.items.len) {
                    i += 1;
                    max_uses = std.fmt.parseInt(u16, remaining_args.items[i], 10) catch {
                        printErr("--max-uses requires a number\n");
                        return error.InvalidArgs;
                    };
                } else if (std.mem.eql(u8, a, "--expires") and i + 1 < remaining_args.items.len) {
                    i += 1;
                    const hours = std.fmt.parseInt(u32, remaining_args.items[i], 10) catch {
                        printErr("--expires requires hours as a number\n");
                        return error.InvalidArgs;
                    };
                    const now: u32 = @intCast(@as(u64, @bitCast(std.time.timestamp())) & 0xFFFFFFFF);
                    expires = now + hours * 3600;
                }
            }

            var code_buf: [16]u8 = undefined;
            const code = invite_store_mod.generateCode(&code_buf);

            invite_store.create(code, max_uses, expires) catch |err| {
                printErr("failed to create invite\n");
                return err;
            };
            printOut(code);
            printOut("\n");
        } else if (std.mem.eql(u8, subcmd, "list")) {
            const entries = invite_store.list(allocator) catch |err| {
                printErr("failed to list invites\n");
                return err;
            };
            defer InviteStore.freeEntries(allocator, entries);

            if (entries.len == 0) {
                printOut("No invites.\n");
            } else {
                for (entries) |entry| {
                    printOut(entry.code);
                    printOut("\n");
                }
            }
        } else if (std.mem.eql(u8, subcmd, "revoke")) {
            if (remaining_args.items.len < 3) {
                printErr("invite revoke requires a code argument\n");
                return error.InvalidArgs;
            }
            const code = remaining_args.items[2];
            invite_store.revoke(allocator, code) catch |err| {
                printErr("failed to revoke invite\n");
                return err;
            };
            printOut("Invite revoked.\n");
        } else {
            printErr("unknown invite subcommand: ");
            printErr(subcmd);
            printErr("\n");
            return error.InvalidArgs;
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

/// Read a password from stdin into a caller-provided buffer.
/// Returns a slice of `out` containing the password.
fn readPassword(prompt: []const u8, out: *[256]u8) ![]const u8 {
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

    // Read one byte at a time until newline (handles piped input correctly)
    var len: usize = 0;
    while (len < out.len) {
        var byte: [1]u8 = undefined;
        const n = posix.read(stdin_fd, &byte) catch return error.ReadFailed;
        if (n == 0) break; // EOF
        if (byte[0] == '\n') break;
        if (byte[0] == '\r') continue;
        out[len] = byte[0];
        len += 1;
    }

    if (len == 0) return error.ReadFailed;

    return out[0..len];
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

/// Try to execute a management command via IPC to the running auth daemon.
/// Returns true if IPC succeeded, false if daemon is unreachable (fall back to direct DB).
fn tryIpcCommand(
    command: []const u8,
    cmd_args: []const []const u8,
    socket_path: []const u8,
    cli_password: ?[]const u8,
    password_file: ?[]const u8,
) bool {
    // Connect to auth daemon (blocking)
    const sock = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return false;
    defer posix.close(sock);

    var addr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
    addr.family = posix.AF.UNIX;
    if (socket_path.len >= addr.path.len) return false;
    @memcpy(addr.path[0..socket_path.len], socket_path);

    posix.connect(sock, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un)) catch return false;

    if (cmd_args.len < 2) {
        printErr(command);
        printErr(" requires a JID argument\n");
        return true; // Consumed — don't fall through
    }
    const jid = cmd_args[1];
    const username = extractLocal(jid);

    // Build IPC message
    var frame_buf: [4096]u8 = undefined;
    const conn_id: u32 = 0; // xmppctl uses conn_id 0

    if (std.mem.eql(u8, command, "adduser") or std.mem.eql(u8, command, "passwd")) {
        // Resolve password
        var pass_buf: [256]u8 = undefined;
        var file_buf: [256]u8 = undefined;
        const password = blk: {
            if (cli_password) |p| break :blk p;
            if (password_file) |pf| {
                const f = std.fs.cwd().openFile(pf, .{}) catch {
                    printErr("cannot open password file\n");
                    return true;
                };
                defer f.close();
                const n = f.read(&file_buf) catch {
                    printErr("cannot read password file\n");
                    return true;
                };
                const content = std.mem.trimRight(u8, file_buf[0..n], "\r\n");
                if (content.len == 0) {
                    printErr("password file is empty\n");
                    return true;
                }
                break :blk content;
            }
            const p = readPassword("Password: ", &pass_buf) catch return true;
            if (p.len < 1) {
                printErr("password cannot be empty\n");
                return true;
            }
            var confirm_buf: [256]u8 = undefined;
            const confirm = readPassword("Confirm password: ", &confirm_buf) catch return true;
            if (!std.mem.eql(u8, p, confirm)) {
                printErr("passwords do not match\n");
                return true;
            }
            break :blk p;
        };

        const msg: ipc_protocol.Message = if (std.mem.eql(u8, command, "adduser"))
            .{ .register_request = .{ .conn_id = conn_id, .username = username, .password = password, .invite_code = "", .client_ip = "ctl" } }
        else
            .{ .password_change_request = .{ .conn_id = conn_id, .username = username, .new_password = password } };

        const frame_len = ipc_protocol.encode(msg, &frame_buf) catch return false;
        _ = writeAll(sock, frame_buf[0..frame_len]) catch return false;
    } else if (std.mem.eql(u8, command, "deluser")) {
        const msg = ipc_protocol.Message{ .account_delete_request = .{ .conn_id = conn_id, .username = username } };
        const frame_len = ipc_protocol.encode(msg, &frame_buf) catch return false;
        _ = writeAll(sock, frame_buf[0..frame_len]) catch return false;
    } else {
        return false;
    }

    // Read response (blocking). Auth daemon sends MechanismList on connect
    // before our command response, so we must skip non-result frames.
    var recv_buf: [4096]u8 = undefined;
    var recv_len: usize = 0;
    while (recv_len < recv_buf.len) {
        // Try to parse from existing buffer before reading more
        while (ipc_protocol.readFrame(recv_buf[0..recv_len])) |frame| {
            const resp = ipc_protocol.decode(frame.payload) catch {
                printErr("invalid response from auth daemon\n");
                return true;
            };

            switch (resp) {
                .register_result => |r| {
                    if (r.success) {
                        printOut("User ");
                        printOut(jid);
                        printOut(" created.\n");
                    } else {
                        printErr("registration failed: ");
                        printErr(r.reason);
                        printErr("\n");
                    }
                    return true;
                },
                .password_change_result => |r| {
                    if (r.success) {
                        printOut("Password changed for ");
                        printOut(jid);
                        printOut(".\n");
                    } else {
                        printErr("password change failed: ");
                        printErr(r.reason);
                        printErr("\n");
                    }
                    return true;
                },
                .account_delete_result => |r| {
                    if (r.success) {
                        printOut("User ");
                        printOut(jid);
                        printOut(" removed.\n");
                    } else {
                        printErr("deletion failed: ");
                        printErr(r.reason);
                        printErr("\n");
                    }
                    return true;
                },
                else => {
                    // Skip non-result messages (e.g. mechanism_list) and try next frame
                    if (frame.consumed < recv_len) {
                        std.mem.copyForwards(u8, recv_buf[0 .. recv_len - frame.consumed], recv_buf[frame.consumed..recv_len]);
                    }
                    recv_len -= frame.consumed;
                },
            }
        }

        // Need more data
        const n = posix.read(sock, recv_buf[recv_len..]) catch break;
        if (n == 0) break;
        recv_len += n;
    }

    printErr("no response from auth daemon\n");
    return true;
}

/// Blocking write-all helper.
fn writeAll(fd: posix.fd_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const n = posix.write(fd, data[written..]) catch |err| {
            return switch (err) {
                error.WouldBlock => continue,
                else => error.WriteFailed,
            };
        };
        written += n;
    }
}

fn printUsage() void {
    printErr(
        \\Usage: xmppctl [--db PATH] [--auth-socket PATH] COMMAND [ARGS]
        \\
        \\Commands:
        \\  adduser JID     Create a user account
        \\  deluser JID     Remove a user account
        \\  passwd  JID     Change a user's password
        \\  listusers       List all users
        \\  lock JID        Permanently lock an account
        \\  unlock JID      Unlock a locked account
        \\  invite create   Create invitation code [--max-uses N] [--expires HOURS]
        \\  invite list     List all invitation codes
        \\  invite revoke   Revoke an invitation code
        \\
        \\Options:
        \\  --db PATH           Storage directory (default: /var/db/xmppd)
        \\  --auth-socket PATH  Auth daemon IPC socket (default: /var/run/xmppd/auth.sock)
        \\  --password PASS     Provide password on command line (non-interactive)
        \\  --password-file F   Read password from file (first line, trailing newline stripped)
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
