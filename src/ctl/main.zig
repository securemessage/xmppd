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
const backend_mod = @import("backend");
const OpBackendType = @import("op_backend").Backend;
const ArchiveBackendType = @import("archive_backend").Backend;
const user_store_mod = @import("user_store");
const UserStore = user_store_mod.UserStore(OpBackendType);
const lock_store_mod = @import("lock_store");
const LockStore = lock_store_mod.LockStore(OpBackendType);
const invite_store_mod = @import("invite_store");
const InviteStore = invite_store_mod.InviteStore(OpBackendType);
const oidc_ids = @import("oidc_identity_store");
const BindingStore = oidc_ids.Store(OpBackendType);
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

    // Open storage backend (admin tool: generous map, fixed at open: S9
    // forbids runtime resize).
    var backend = try OpBackendType.open(auth_path, .{ .map_size = 256 * 1024 * 1024 });
    defer backend.close();
    var store = UserStore.init(&backend);
    var lock_store = LockStore.init(&backend);
    var invite_store = InviteStore.init(&backend);
    var binding_store = BindingStore.init(&backend);

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
    } else if (std.mem.eql(u8, command, "oidc-link")) {
        if (remaining_args.items.len < 4) {
            printErr("oidc-link requires: <localpart> <issuer> <subject>\n");
            return error.InvalidArgs;
        }
        const lp = remaining_args.items[1];
        const iss = remaining_args.items[2];
        const sub = remaining_args.items[3];
        const claimed = binding_store.bind(iss, sub, lp, .operator, std.time.timestamp()) catch |err| {
            printErr("oidc-link failed\n");
            return err;
        };
        switch (claimed) {
            .bound => {
                printOut("Bound ");
                printOut(lp);
                printOut("\n");
            },
            .localpart_taken => {
                printErr("localpart already bound to another subject\n");
                return error.Conflict;
            },
            .subject_taken => {
                printErr("subject already bound to another localpart\n");
                return error.Conflict;
            },
        }
    } else if (std.mem.eql(u8, command, "oidc-unlink")) {
        if (remaining_args.items.len < 2) {
            printErr("oidc-unlink requires a localpart\n");
            return error.InvalidArgs;
        }
        const removed = binding_store.unbind(allocator, remaining_args.items[1]) catch |err| {
            printErr("oidc-unlink failed\n");
            return err;
        };
        if (removed) {
            printOut("Unbound.\n");
        } else {
            printErr("no binding for that localpart\n");
            return error.NotFound;
        }
    } else if (std.mem.eql(u8, command, "oidc-links")) {
        var it = try binding_store.iterateBindings();
        defer it.deinit();
        while (try it.next()) |b| {
            var line: [1024]u8 = undefined;
            const s = std.fmt.bufPrint(&line, "{s}\t{s}\t{s}\t{s}\t{d}\n", .{
                b.localpart, b.iss, b.sub, @tagName(b.source), b.bound_at,
            }) catch continue;
            printOut(s);
        }
    } else if (std.mem.eql(u8, command, "oidc-link-import")) {
        if (remaining_args.items.len < 2) {
            printErr("oidc-link-import requires a file\n");
            return error.InvalidArgs;
        }
        const content = std.fs.cwd().readFileAlloc(allocator, remaining_args.items[1], 16 * 1024 * 1024) catch |err| {
            printErr("cannot read import file\n");
            return err;
        };
        defer allocator.free(content);
        var ok: usize = 0;
        var failed: usize = 0;
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;
            var fields = std.mem.tokenizeAny(u8, trimmed, " \t");
            const lp = fields.next() orelse {
                failed += 1;
                continue;
            };
            const iss = fields.next() orelse {
                failed += 1;
                continue;
            };
            const sub = fields.rest();
            if (sub.len == 0) {
                failed += 1;
                continue;
            }
            const claimed = binding_store.bind(iss, sub, lp, .operator, std.time.timestamp()) catch {
                failed += 1;
                continue;
            };
            switch (claimed) {
                .bound => ok += 1,
                else => {
                    failed += 1;
                    printErr("conflict linking localpart ");
                    printErr(lp);
                    printErr("\n");
                },
            }
        }
        var sum_buf: [128]u8 = undefined;
        printOut(std.fmt.bufPrint(&sum_buf, "linked {d}, failed {d}\n", .{ ok, failed }) catch "done\n");
        if (failed > 0) return error.PartialFailure;
    } else if (std.mem.eql(u8, command, "oidc-unclaimed")) {
        try cmdOidcUnclaimed(allocator, &binding_store, &backend, db_path);
    } else {
        printErr("unknown command: ");
        printErr(command);
        printErr("\n");
        printUsage();
        return error.InvalidArgs;
    }
}

/// Owner set for oidc-unclaimed: deduped localparts drawn from account
/// namespaces. Bounded so a pathological store cannot grow it forever.
const max_unclaimed_owners = 1_000_000;
const OwnerSet = std.StringHashMapUnmanaged(void);

const ROSTERS_NS = backend_mod.registered("rosters");
const OFFLINE_NS = backend_mod.registered("offline");
const VCARDS_NS = backend_mod.registered("vcards");
const LASTACT_NS = backend_mod.registered("lastact");
const PEP_NS = backend_mod.registered("pep");
const BLOCKLIST_NS = backend_mod.registered("blocklist");
const PENDING_SUB_NS = backend_mod.registered("pending_sub");
const ROOM_AFFIL_NS = backend_mod.registered("room_affiliations");
const MESSAGES_NS = backend_mod.registered("messages");
const BY_CONTACT_NS = backend_mod.registered("by_contact");

fn addOwner(owners: *OwnerSet, allocator: std.mem.Allocator, bare: []const u8) !void {
    const lp = extractLocal(bare);
    if (lp.len == 0 or lp.len > oidc_ids.max_localpart_len) return;
    if (owners.count() >= max_unclaimed_owners) return;
    const copy = try allocator.dupe(u8, lp);
    const gop = try owners.getOrPut(allocator, copy);
    if (gop.found_existing) allocator.free(copy);
}

/// Scan one namespace for owner localparts. Keys are either
/// `owner_bare_jid`-prefixed rows (rosters, offline, vcards, lastact,
/// pep, blocklist, pending_sub, messages, by_contact) where the
/// localpart precedes the first '@', or `room\x00member` rows where the
/// member bare JID follows the first NUL.
fn scanOwners(backend: anytype, ns: []const u8, member_suffix: bool, owners: *OwnerSet, allocator: std.mem.Allocator) !void {
    var it = backend.iterator(ns, "") catch return;
    defer it.deinit();
    while (it.next()) |entry| {
        if (member_suffix) {
            const at = std.mem.indexOfScalar(u8, entry.key, 0) orelse continue;
            try addOwner(owners, allocator, entry.key[at + 1 ..]);
        } else {
            try addOwner(owners, allocator, entry.key);
        }
    }
}

/// `xmppctl oidc-unclaimed`: list localparts that own account data or a
/// provisioned users row but have no OIDC binding row. These are the
/// accounts the first-login rule refuses to auto-claim and must be
/// linked explicitly.
fn cmdOidcUnclaimed(allocator: std.mem.Allocator, binding_store: *BindingStore, auth_backend: *OpBackendType, db_path: []const u8) !void {
    var owners: OwnerSet = .empty;
    defer {
        var it = owners.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        owners.deinit(allocator);
    }

    scanOwners(auth_backend, user_store_mod.NAMESPACE, false, &owners, allocator) catch {};

    var op_path_buf: [1024]u8 = undefined;
    const op_path = try std.fmt.bufPrint(&op_path_buf, "{s}/op", .{db_path});
    var op_be = OpBackendType.open(op_path, .{ .read_only = true, .create = false }) catch |err| blk: {
        if (lock_store_mod.isMissingStoreError(err)) break :blk null;
        return err;
    };
    defer if (op_be) |*b| b.close();
    if (op_be) |*op| {
        const probe_nss = [_][]const u8{
            ROSTERS_NS,    OFFLINE_NS, VCARDS_NS, LASTACT_NS,
            PEP_NS,        BLOCKLIST_NS, PENDING_SUB_NS,
        };
        for (probe_nss) |ns| {
            try scanOwners(op, ns, false, &owners, allocator);
        }
        try scanOwners(op, ROOM_AFFIL_NS, true, &owners, allocator);
    }

    var archive_path_buf: [1024]u8 = undefined;
    const archive_path = try std.fmt.bufPrint(&archive_path_buf, "{s}/archive", .{db_path});
    var arch_be = ArchiveBackendType.open(archive_path, .{ .read_only = true, .create = false }) catch |err| blk: {
        if (lock_store_mod.isMissingStoreError(err)) break :blk null;
        return err;
    };
    defer if (arch_be) |*b| b.close();
    if (arch_be) |*arch| {
        try scanOwners(arch, MESSAGES_NS, false, &owners, allocator);
        try scanOwners(arch, BY_CONTACT_NS, false, &owners, allocator);
    }

    var it = owners.keyIterator();
    while (it.next()) |k| {
        const found = binding_store.lookupLocalpart(allocator, k.*) catch |err| {
            printErr("binding lookup failed\n");
            return err;
        };
        if (found) |b| {
            allocator.free(b.value);
            continue;
        }
        printOut(k.*);
        printOut("\n");
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
        \\  oidc-link LP ISS SUB  Bind an XMPP localpart to an OIDC (iss, sub)
        \\  oidc-unlink LP        Remove an OIDC binding
        \\  oidc-links            List all OIDC bindings
        \\  oidc-unclaimed        List data-owning localparts with no OIDC binding
        \\  oidc-link-import F    Link localparts from a file (LP ISS SUB per line)
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
