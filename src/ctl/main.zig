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
const ArchiveBackendType = @import("archive_backend").Backend;
const migrate_precis = @import("migrate_precis");
const user_store_mod = @import("user_store");
const UserStore = user_store_mod.UserStore(OpBackendType);
const lock_store_mod = @import("lock_store");
const LockStore = lock_store_mod.LockStore(OpBackendType);
const invite_store_mod = @import("invite_store");
const InviteStore = invite_store_mod.InviteStore(OpBackendType);
const ipc_protocol = @import("ipc_protocol");
const precis = @import("precis_username");

threadlocal var ctl_precis_scratch: precis.Scratch = undefined;
const backend_mod = @import("backend");

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
    var apply = false;
    var raw = false;
    var run_dir: []const u8 = "/var/run/xmppd";
    var rename_old: ?[]const u8 = null;
    var rename_new: ?[]const u8 = null;
    var hosted_domains: std.ArrayListUnmanaged([]const u8) = .{};
    defer hosted_domains.deinit(allocator);

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
        } else if (std.mem.eql(u8, arg, "--apply")) {
            apply = true;
        } else if (std.mem.eql(u8, arg, "--raw")) {
            raw = true;
        } else if (std.mem.eql(u8, arg, "--run-dir")) {
            run_dir = args.next() orelse {
                printErr("--run-dir requires a value\n");
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--hosted-domain")) {
            const domain = args.next() orelse {
                printErr("--hosted-domain requires a value\n");
                return error.InvalidArgs;
            };
            try hosted_domains.append(allocator, domain);
        } else if (std.mem.eql(u8, arg, "--rename")) {
            rename_old = args.next() orelse {
                printErr("--rename requires an old and a new localpart\n");
                return error.InvalidArgs;
            };
            rename_new = args.next() orelse {
                printErr("--rename requires an old and a new localpart\n");
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

    const is_db_write = std.mem.eql(u8, command, "adduser") or
        std.mem.eql(u8, command, "deluser") or
        std.mem.eql(u8, command, "passwd") or
        std.mem.eql(u8, command, "lock") or
        std.mem.eql(u8, command, "unlock") or
        std.mem.eql(u8, command, "invite");
    if (is_db_write and try migrate_precis.recoveryPending(allocator, db_path)) {
        printErr("a migrate-precis recovery is pending; finish it with 'xmppctl migrate-precis --apply' before any other write\n");
        return error.RecoveryPending;
    }

    if (std.mem.eql(u8, command, "migrate-precis")) {
        const forced: ?migrate_precis.ForcedRename = if (rename_old != null and rename_new != null)
            .{ .old_localpart = rename_old.?, .new_localpart = rename_new.? }
        else
            null;
        if ((rename_old == null) != (rename_new == null)) {
            printErr("--rename requires an old and a new localpart\n");
            return error.InvalidArgs;
        }
        return runMigratePrecis(allocator, db_path, run_dir, apply, hosted_domains.items, forced);
    }

    if (raw and std.mem.eql(u8, command, "deluser")) {
        if (remaining_args.items.len < 2) {
            printErr("deluser --raw requires an exact stored key\n");
            return error.InvalidArgs;
        }
        if (hosted_domains.items.len == 0) {
            printErr("deluser --raw requires at least one --hosted-domain\n");
            return error.InvalidArgs;
        }
        return runDeleteRaw(allocator, db_path, run_dir, hosted_domains.items, remaining_args.items[1]);
    }

    // Try IPC to running auth daemon first for adduser/deluser/passwd.
    // This is required for RocksDB (exclusive lock) and preferred for all backends.
    if (!raw and (std.mem.eql(u8, command, "adduser") or std.mem.eql(u8, command, "deluser") or std.mem.eql(u8, command, "passwd"))) {
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

        addUserCanonical(&store, allocator, username, password) catch |err| {
            switch (err) {
                error.InvalidAccountName => printErr("invalid account name\n"),
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

        removeUserCanonical(&store, allocator, username) catch |err| {
            switch (err) {
                error.InvalidAccountName => printErr("invalid account name\n"),
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

        changePasswordCanonical(&store, allocator, username, password) catch |err| {
            switch (err) {
                error.InvalidAccountName => printErr("invalid account name\n"),
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
/// Add a new account under its RFC 7622 Section 3.3 localpart: account names
/// are stored and compared in canonical form only, so the direct-DB path
/// agrees with the daemon's IPC registration path and with xmppd lookups.
/// Error set is the store's plus error.InvalidAccountName when the name fails
/// preparation.
fn addUserCanonical(store: anytype, allocator: std.mem.Allocator, raw: []const u8, password: []const u8) !void {
    // Buffer contract of xmppLocalpart: buf 6x input, scratch 3x input each;
    // input past max_input_octets fails the profile itself.
    const canon = try prepareAccountName(raw);
    try store.addUser(allocator, canon, password);
}

fn prepareAccountName(raw: []const u8) ![]const u8 {
    return ctl_precis_scratch.localpart(raw) catch
        return error.InvalidAccountName;
}

fn changePasswordCanonical(store: anytype, allocator: std.mem.Allocator, raw: []const u8, password: []const u8) !void {
    const canon = try prepareAccountName(raw);
    try store.changePassword(allocator, canon, password);
}

fn removeUserCanonical(store: anytype, allocator: std.mem.Allocator, raw: []const u8) !void {
    const canon = try prepareAccountName(raw);
    try store.removeUser(allocator, canon);
}

/// Open an op/auth backend with the LMDB offline lock already held. LMDB
/// backends take the exclusive lock before env open and keep it until close;
/// a second descriptor opened after env open must never be closed (D5).
fn openOpBackendOffline(comptime Backend: type, path: []const u8, opts: backend_mod.OpenOptions) !Backend {
    if (comptime @hasDecl(Backend, "openOffline")) return Backend.openOffline(path, opts);
    var opened = try Backend.open(path, opts);
    errdefer opened.close();
    if (comptime @hasDecl(Backend, "assertNoActiveReaders")) try opened.assertNoActiveReaders();
    return opened;
}

fn reportOfflineOpenError(err: anyerror) void {
    switch (err) {
        error.DaemonsRunning => printErr("an LMDB process holds the DB; stop every daemon and close all clients\n"),
        error.LmdbCheckFailed => printErr("cannot verify the LMDB lock file; check DB path and permissions\n"),
        else => printErr("failed to open the database\n"),
    }
}

fn runDeleteRaw(
    allocator: std.mem.Allocator,
    db_path: []const u8,
    run_dir: []const u8,
    hosted_domains: []const []const u8,
    stored_key: []const u8,
) !void {
    migrate_precis.assertOffline(run_dir) catch |err| {
        printErr("xmppd is running; stop all daemons before deluser --raw\n");
        return err;
    };
    if (try migrate_precis.recoveryPending(allocator, db_path)) {
        printErr("a migrate-precis recovery is pending; finish it before deluser --raw\n");
        return error.RecoveryPending;
    }
    var auth_path_buf: [1024]u8 = undefined;
    const auth_path = try std.fmt.bufPrint(&auth_path_buf, "{s}/auth", .{db_path});
    var op_path_buf: [1024]u8 = undefined;
    const op_path = try std.fmt.bufPrint(&op_path_buf, "{s}/op", .{db_path});
    var archive_path_buf: [1024]u8 = undefined;
    const archive_path = try std.fmt.bufPrint(&archive_path_buf, "{s}/archive", .{db_path});

    var auth = openOpBackendOffline(OpBackendType, auth_path, .{ .create = false, .map_size = 256 * 1024 * 1024 }) catch |err| {
        reportOfflineOpenError(err);
        return err;
    };
    defer auth.close();
    var op = openOpBackendOffline(OpBackendType, op_path, .{ .create = false, .map_size = 256 * 1024 * 1024 }) catch |err| {
        reportOfflineOpenError(err);
        return err;
    };
    defer op.close();
    var archive = try ArchiveBackendType.open(archive_path, .{ .create = false });
    defer archive.close();

    const kind = migrate_precis.deleteRawAccount(allocator, &auth, &op, &archive, hosted_domains, stored_key) catch |err| {
        switch (err) {
            error.UserNotFound => printErr("user not found\n"),
            error.DataRemaining => printErr("account data remains; inspect the DB and rerun\n"),
            else => printErr("failed to delete account data\n"),
        }
        return err;
    };
    switch (kind) {
        .account => {
            printOut("User ");
            printOut(stored_key);
            printOut(" and all matching account data removed.\n");
        },
        .data_only => {
            printOut("data stored under spelling ");
            printOut(stored_key);
            printOut(" removed\n");
        },
    }
}

fn runMigratePrecis(
    allocator: std.mem.Allocator,
    db_path: []const u8,
    run_dir: []const u8,
    apply: bool,
    hosted_domains: []const []const u8,
    forced: ?migrate_precis.ForcedRename,
) !void {
    if (hosted_domains.len == 0) {
        printErr("migrate-precis requires at least one --hosted-domain\n");
        return error.InvalidArgs;
    }
    // The master and its children are detected through their pid files. A dry
    // run is offline too: it must observe a quiescent, complete keyspace.
    migrate_precis.assertOffline(run_dir) catch |err| {
        printErr("xmppd is running; stop all daemons before migrate-precis\n");
        return err;
    };

    var auth_path_buf: [1024]u8 = undefined;
    const auth_path = try std.fmt.bufPrint(&auth_path_buf, "{s}/auth", .{db_path});
    var op_path_buf: [1024]u8 = undefined;
    const op_path = try std.fmt.bufPrint(&op_path_buf, "{s}/op", .{db_path});
    var archive_path_buf: [1024]u8 = undefined;
    const archive_path = try std.fmt.bufPrint(&archive_path_buf, "{s}/archive", .{db_path});

    var auth = openOpBackendOffline(OpBackendType, auth_path, .{ .create = false, .map_size = 256 * 1024 * 1024 }) catch |err| {
        reportOfflineOpenError(err);
        return err;
    };
    defer auth.close();
    var op = openOpBackendOffline(OpBackendType, op_path, .{ .create = false, .map_size = 256 * 1024 * 1024 }) catch |err| {
        reportOfflineOpenError(err);
        return err;
    };
    defer op.close();
    var archive = try ArchiveBackendType.open(archive_path, .{ .create = false });
    defer archive.close();

    if (try migrate_precis.recoveryPending(allocator, db_path)) {
        if (forced != null) {
            printErr("a migrate-precis recovery is pending; rerun --apply without --rename\n");
            return error.RecoveryPending;
        }
        if (!apply) {
            printErr("a migrate-precis recovery is pending; rerun with --apply to finish it\n");
            return error.RecoveryPending;
        }
        const resumed = try migrate_precis.resumeMigration(allocator, &auth, &op, &archive, db_path);
        var resumed_buf: [96]u8 = undefined;
        const resumed_line = try std.fmt.bufPrint(&resumed_buf, "resumed {d} renames\n", .{resumed});
        printOut(resumed_line);
        return;
    }

    var plan = try migrate_precis.planMigration(allocator, &auth, &op, &archive, hosted_domains, forced);
    defer plan.deinit();
    var out_buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&out_buf);
    var err_buf: [0]u8 = .{};
    var stderr = std.fs.File.stderr().writer(&err_buf);
    try printMigrationPlan(allocator, &plan, &stdout.interface, &stderr.interface);
    if (plan.hasBlockingIssues()) {
        printErr("migration blocked; resolve every collision or invalid name and rerun\n");
        return error.MigrationBlocked;
    }
    if (!apply) {
        printOut("dry run: no changes applied (use --apply to migrate)\n");
        return;
    }

    try migrate_precis.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = db_path });
    var count_buf: [96]u8 = undefined;
    const line = try std.fmt.bufPrint(&count_buf, "applied {d} renames\n", .{plan.renames.items.len});
    printOut(line);
}

fn printMigrationPlan(
    allocator: std.mem.Allocator,
    plan: *const migrate_precis.Plan,
    out: *std.Io.Writer,
    errw: *std.Io.Writer,
) !void {
    for (plan.renames.items) |rename| {
        const old_hex = try migrate_precis.hexKey(allocator, rename.old_key);
        defer allocator.free(old_hex);
        const new_hex = try migrate_precis.hexKey(allocator, rename.new_key);
        defer allocator.free(new_hex);
        if (rename.delete_only) {
            try out.writeAll("dedupe-drop ");
        } else if (rename.same_key) {
            try out.writeAll("rewrite-value ");
        } else {
            try out.writeAll("rename ");
        }
        try out.writeAll(@tagName(rename.db));
        try out.writeAll(" ");
        try out.writeAll(rename.namespace);
        try out.writeAll(" ");
        try out.writeAll(old_hex);
        try out.writeAll(" -> ");
        try out.writeAll(new_hex);
        try out.writeAll("\n");
    }
    for (plan.issues.items) |issue| {
        const key_hex = try migrate_precis.hexKey(allocator, issue.key);
        defer allocator.free(key_hex);
        try errw.writeAll(@tagName(issue.kind));
        try errw.writeAll(" ");
        try errw.writeAll(@tagName(issue.db));
        try errw.writeAll(" ");
        try errw.writeAll(issue.namespace);
        try errw.writeAll(" ");
        try errw.writeAll(key_hex);
        if (issue.target.len != 0) {
            const target = try escapeBytesAlloc(allocator, issue.target);
            defer allocator.free(target);
            try errw.writeAll(" -> ");
            try errw.writeAll(target);
        }
        try errw.writeAll("\n");
    }
}

fn escapeBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = "0123456789abcdef";
    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(allocator);
    for (bytes) |byte| {
        if (byte >= 0x20 and byte <= 0x7e and byte != '\\') {
            try out.append(allocator, byte);
        } else {
            try out.appendSlice(allocator, &[_]u8{ '\\', 'x', hex[byte >> 4], hex[byte & 0x0f] });
        }
    }
    return out.toOwnedSlice(allocator);
}

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
        \\  deluser --raw KEY  Offline: delete KEY's data in every namespace
        \\  passwd  JID     Change a user's password
        \\  listusers       List all users
        \\  lock JID        Permanently lock an account
        \\  unlock JID      Unlock a locked account
        \\  migrate-precis  Plan RFC 7622 key renames (dry run unless --apply)
        \\                  Requires --hosted-domain DOMAIN (repeatable)
        \\                  --rename OLD NEW explicitly renames one stored localpart
        \\  invite create   Create invitation code [--max-uses N] [--expires HOURS]
        \\  invite list     List all invitation codes
        \\  invite revoke   Revoke an invitation code
        \\
        \\Options:
        \\  --db PATH           Storage directory (default: /var/db/xmppd)
        \\  --auth-socket PATH  Auth daemon IPC socket (default: /var/run/xmppd/auth.sock)
        \\  --password PASS     Provide password on command line (non-interactive)
        \\  --password-file F   Read password from file (first line, trailing newline stripped)
        \\  --apply             Apply migrate-precis renames (default is a dry run)
        \\  --raw               deluser: exact source localpart; requires --hosted-domain
        \\  --run-dir PATH      Daemon pid-file directory (default: /var/run/xmppd)
        \\  --hosted-domain D   Hosted account domain; repeat for each domain
        \\  --rename OLD NEW    migrate-precis: explicitly rename one localpart
        \\
    );
}

// ============================================================================
// Tests
// ============================================================================

test "xmppctl escapes control bytes in collision targets" {
    const allocator = std.testing.allocator;
    const escaped = try escapeBytesAlloc(allocator, "alice@us.example\x00naplestb@us.example");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("alice@us.example\\x00naplestb@us.example", escaped);
}

test "xmppctl printMigrationPlan escapes NUL in dedupe targets" {
    const allocator = std.testing.allocator;
    var plan = migrate_precis.Plan.init(allocator);
    defer plan.deinit();
    try plan.issues.append(allocator, .{
        .db = .op,
        .namespace = "by_contact",
        .kind = .deduplicated,
        .key = try allocator.dupe(u8, "dedupe-key"),
        .target = try allocator.dupe(u8, "alice@us.example\x00naplestb@us.example"),
    });
    var out_buf: [512]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var err_buf: [512]u8 = undefined;
    var errw: std.Io.Writer = .fixed(&err_buf);
    try printMigrationPlan(allocator, &plan, &out, &errw);
    try std.testing.expect(std.mem.indexOf(u8, errw.buffered(), "alice@us.example\\x00naplestb@us.example") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, errw.buffered(), 0) == null);
}

test "extractLocal: JID with domain" {
    try std.testing.expectEqualStrings("alice", extractLocal("alice@example.com"));
}

test "extractLocal: bare username" {
    try std.testing.expectEqualStrings("alice", extractLocal("alice"));
}

test "extractLocal: JID with resource" {
    try std.testing.expectEqualStrings("alice", extractLocal("alice@example.com/phone"));
}

test "addUserCanonical: stores the PRECIS canonical name" {
    const allocator = std.testing.allocator;
    var db = try backend_mod.MemoryBackend.open("", .{});
    defer db.close();
    var store = user_store_mod.UserStore(backend_mod.MemoryBackend).init(&db);

    // Greek capital ODeltaSigma prepares to omicron-delta-omicron-sigma
    // (U+03A3 folds to U+03C3 unconditionally; no final-sigma rule).
    try addUserCanonical(&store, allocator, "\u{039F}\u{0394}\u{039F}\u{03A3}", "pw");
    try std.testing.expect((try store.lookup(allocator, "\u{03BF}\u{03B4}\u{03BF}\u{03C3}")) != null);
    try std.testing.expect((try store.lookup(allocator, "\u{039F}\u{0394}\u{039F}\u{03A3}")) == null);
}

test "password change and deletion resolve the RFC 7622 account name" {
    const allocator = std.testing.allocator;
    var db = try backend_mod.MemoryBackend.open("", .{});
    defer db.close();
    var store = user_store_mod.UserStore(backend_mod.MemoryBackend).init(&db);

    try addUserCanonical(&store, allocator, "naplestb", "oldpw");
    try changePasswordCanonical(&store, allocator, "NaplesTB", "newpw");
    try removeUserCanonical(&store, allocator, "NAPLESTB");
    try std.testing.expect((try store.lookup(allocator, "naplestb")) == null);

    try store.addUser(allocator, "bad name", "pw");
    try std.testing.expectError(error.InvalidAccountName, changePasswordCanonical(&store, allocator, "bad name", "pw"));
    try std.testing.expectError(error.InvalidAccountName, removeUserCanonical(&store, allocator, "bad name"));
    try std.testing.expect((try store.lookup(allocator, "bad name")) != null);
}

test "addUserCanonical: invalid names refused; conflicts are on the canonical name" {
    const allocator = std.testing.allocator;
    var db = try backend_mod.MemoryBackend.open("", .{});
    defer db.close();
    var store = user_store_mod.UserStore(backend_mod.MemoryBackend).init(&db);

    for ([_][]const u8{ "a b", "\u{2603}", "a@b" }) |bad| {
        try std.testing.expectError(error.InvalidAccountName, addUserCanonical(&store, allocator, bad, "pw"));
    }

    // Case variants of one name collide on the canonical form.
    try addUserCanonical(&store, allocator, "Alice", "pw");
    try std.testing.expectError(error.UserExists, addUserCanonical(&store, allocator, "ALICE", "pw"));

    // The Kelvin sign folds to 'k' (PR #21 account-key semantics).
    try addUserCanonical(&store, allocator, "\u{212A}", "pw");
    try std.testing.expectError(error.UserExists, addUserCanonical(&store, allocator, "k", "pw"));
}
