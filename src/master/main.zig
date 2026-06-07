//! # xmppd — Master supervisor daemon
//!
//! Binds privileged ports (5222, 5223), drops privileges, and spawns/monitors
//! the `xmppd-core` worker process. Handles:
//!
//! - Graceful shutdown on SIGTERM
//! - Auto-restart with exponential backoff on child crash
//! - Signal forwarding (SIGHUP for future config reload)
//!
//! ## Architecture
//!
//! ```
//! xmppd (master, root → xmppd user)
//!   ├── xmppd-auth (authentication daemon)
//!   └── xmppd-core (worker, handles connections)
//! ```
//!
//! The master passes configuration to children via command-line arguments.
//! xmppd-auth must be ready before xmppd-core starts (core connects to
//! the auth IPC socket). In the future, socket fds will be passed via
//! SCM_RIGHTS for proper privilege separation.

const std = @import("std");
const posix = std.posix;
const Supervisor = @import("supervisor.zig").Supervisor;
const event_loop_mod = @import("event_loop");
const EventLoop = event_loop_mod.EventLoop;
const ChangeList = event_loop_mod.ChangeList;
const Event = event_loop_mod.Event;
const config_mod = @import("config");

const log = std.log.scoped(.xmppd);

/// Timer ident for restart backoff.
const RESTART_TIMER_IDENT: usize = 0xBACCF;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command-line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var host: []const u8 = "localhost";
    var port: []const u8 = "5222";
    var cert_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;
    var core_path: []const u8 = "xmppd-core";
    var auth_path: []const u8 = "xmppd-auth";
    var auth_socket: []const u8 = "/var/run/xmppd/auth.sock";
    var db_path: []const u8 = "/var/db/xmppd/users.db";
    var config_path: ?[]const u8 = null;
    var run_user: ?[]const u8 = null;
    var log_file: []const u8 = "/var/log/xmppd/xmppd.log";
    var daemonize: bool = false;

    // Skip argv[0]
    _ = args.next();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--host")) {
            host = args.next() orelse {
                log.err("--host requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            port = args.next() orelse {
                log.err("--port requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--cert")) {
            cert_path = args.next() orelse {
                log.err("--cert requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--key")) {
            key_path = args.next() orelse {
                log.err("--key requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--core-path")) {
            core_path = args.next() orelse {
                log.err("--core-path requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--auth-path")) {
            auth_path = args.next() orelse {
                log.err("--auth-path requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--auth-socket")) {
            auth_socket = args.next() orelse {
                log.err("--auth-socket requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--db")) {
            db_path = args.next() orelse {
                log.err("--db requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            config_path = args.next() orelse {
                log.err("--config requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--log-file")) {
            log_file = args.next() orelse {
                log.err("--log-file requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--background") or std.mem.eql(u8, arg, "-b")) {
            daemonize = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            log.warn("unknown argument: {s}", .{arg});
        }
    }

    // Apply config file defaults (CLI flags take precedence)
    var cfg: ?config_mod.Config = null;
    if (config_path) |cp| {
        cfg = config_mod.parse(allocator, cp) catch |err| {
            log.err("failed to read config file '{s}': {}", .{ cp, err });
            return error.InvalidArgs;
        };
        const c = &cfg.?;

        // [server] section
        if (std.mem.eql(u8, host, "localhost")) {
            if (c.get("server", "hostname")) |v| host = v;
        }
        if (std.mem.eql(u8, port, "5222")) {
            if (c.get("server", "c2s_port")) |v| port = v;
        }
        if (std.mem.eql(u8, db_path, "/var/db/xmppd/users.db")) {
            if (c.get("server", "db_path")) |v| db_path = v;
        }
        if (run_user == null) {
            if (c.get("server", "user")) |v| run_user = v;
        }
        if (std.mem.eql(u8, log_file, "/var/log/xmppd/xmppd.log")) {
            if (c.get("server", "log_file")) |v| log_file = v;
        }

        // [tls] section
        if (cert_path == null) {
            if (c.get("tls", "cert")) |v| cert_path = v;
        }
        if (key_path == null) {
            if (c.get("tls", "key")) |v| key_path = v;
        }

        // [auth] section
        if (std.mem.eql(u8, auth_socket, "/var/run/xmppd/auth.sock")) {
            if (c.get("auth", "socket")) |v| auth_socket = v;
        }

        // [master] section
        if (std.mem.eql(u8, core_path, "xmppd-core")) {
            if (c.get("master", "core_path")) |v| core_path = v;
        }
        if (std.mem.eql(u8, auth_path, "xmppd-auth")) {
            if (c.get("master", "auth_path")) |v| auth_path = v;
        }
    }
    defer if (cfg) |*c| c.deinit();

    // Resolve unprivileged user for child processes
    var child_uid: posix.uid_t = 0;
    var child_gid: posix.gid_t = 0;
    if (run_user) |username| {
        var user_buf: [256]u8 = undefined;
        if (username.len < user_buf.len) {
            @memcpy(user_buf[0..username.len], username);
            user_buf[username.len] = 0;
            const pw = std.c.getpwnam(@ptrCast(&user_buf));
            if (pw) |entry| {
                child_uid = entry.uid;
                child_gid = entry.gid;
                log.info("child processes will run as {s} (uid={d} gid={d})", .{ username, child_uid, child_gid });
            } else {
                log.err("user '{s}' not found — children will run as root", .{username});
            }
        } else {
            log.err("user name too long: {s}", .{username});
        }
    }

    // --- Daemonize if requested ---
    if (daemonize) {
        const fork_pid = try posix.fork();
        if (fork_pid != 0) {
            // Parent exits immediately — child continues as daemon
            std.c._exit(0);
        }
        // Child: become session leader, detach from terminal
        _ = std.c.setsid();

        // Open log file for stderr (append mode) — all children inherit this fd
        const log_fd = blk: {
            break :blk std.fs.cwd().openFile(log_file, .{ .mode = .write_only }) catch {
                // Try to create it
                break :blk std.fs.cwd().createFile(log_file, .{ .truncate = false }) catch {
                    // Last resort: /dev/null
                    break :blk std.fs.cwd().openFile("/dev/null", .{ .mode = .read_write }) catch
                        return error.DaemonizeFailed;
                };
            };
        };
        // Seek to end for append behavior
        log_fd.seekFromEnd(0) catch {};

        const devnull = std.fs.cwd().openFile("/dev/null", .{ .mode = .read_write }) catch
            return error.DaemonizeFailed;
        posix.dup2(devnull.handle, 0) catch {};
        posix.dup2(devnull.handle, 1) catch {};
        posix.dup2(log_fd.handle, 2) catch {};
        if (devnull.handle > 2) devnull.close();
        if (log_fd.handle > 2) log_fd.close();
    }

    log.info("xmppd master starting, host={s} port={s}", .{ host, port });

    // --- Single-instance enforcement via PID file lock ---
    const pidfile_path = "/var/run/xmppd/xmppd.pid";
    const pidfile = std.fs.cwd().openFile(pidfile_path, .{ .mode = .read_write }) catch blk: {
        break :blk std.fs.cwd().createFile(pidfile_path, .{ .read = true }) catch |err| {
            log.err("cannot open/create PID file {s}: {}", .{ pidfile_path, err });
            return error.PidFileFailed;
        };
    };
    defer pidfile.close();

    // Non-blocking exclusive lock — fails immediately if another master holds it
    {
        const LOCK_EX = 0x02;
        const LOCK_NB = 0x04;
        const ret = std.c.flock(pidfile.handle, LOCK_EX | LOCK_NB);
        if (ret != 0) {
            log.err("another xmppd master is already running (PID file locked)", .{});
            return error.AlreadyRunning;
        }
    }

    // Write our PID
    {
        var pid_buf: [20]u8 = undefined;
        const pid_str = std.fmt.bufPrint(&pid_buf, "{d}\n", .{std.c.getpid()}) catch unreachable;
        pidfile.seekTo(0) catch {};
        pidfile.writeAll(pid_str) catch {};
        pidfile.setEndPos(pid_str.len) catch {};
    }

    // --- Orphan child cleanup ---
    // Kill any stale children from a previous master that died ungracefully
    cleanupOrphan("/var/run/xmppd/auth.pid");
    cleanupOrphan("/var/run/xmppd/core.pid");

    // Ensure storage sub-directories exist
    const sub_dirs = [_][]const u8{ "auth", "op", "archive" };
    for (sub_dirs) |sub| {
        var path_buf: [1024]u8 = undefined;
        const sub_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ db_path, sub }) catch {
            log.err("db path too long", .{});
            return error.InvalidArgs;
        };
        std.fs.cwd().makePath(sub_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => {
                log.err("failed to create {s}: {}", .{ sub_path, err });
                return error.StorageSetupFailed;
            },
        };
    }

    // Build child argv: pass --config, --db, --socket to auth and core children
    var auth_args_buf: [6][]const u8 = undefined;
    var auth_argc: usize = 0;
    if (config_path) |cp| {
        auth_args_buf[auth_argc] = "--config";
        auth_argc += 1;
        auth_args_buf[auth_argc] = cp;
        auth_argc += 1;
    }
    auth_args_buf[auth_argc] = "--db";
    auth_argc += 1;
    auth_args_buf[auth_argc] = db_path;
    auth_argc += 1;
    auth_args_buf[auth_argc] = "--socket";
    auth_argc += 1;
    auth_args_buf[auth_argc] = auth_socket;
    auth_argc += 1;

    var core_args_buf: [10][]const u8 = undefined;
    var core_argc: usize = 0;
    if (config_path) |cp| {
        core_args_buf[core_argc] = "--config";
        core_argc += 1;
        core_args_buf[core_argc] = cp;
        core_argc += 1;
    }
    core_args_buf[core_argc] = "--auth-socket";
    core_argc += 1;
    core_args_buf[core_argc] = auth_socket;
    core_argc += 1;
    if (cert_path) |cp| {
        core_args_buf[core_argc] = "--cert";
        core_argc += 1;
        core_args_buf[core_argc] = cp;
        core_argc += 1;
    }
    if (key_path) |kp| {
        core_args_buf[core_argc] = "--key";
        core_argc += 1;
        core_args_buf[core_argc] = kp;
        core_argc += 1;
    }

    // Initialize supervisors for both children
    var auth_sup = if (child_uid != 0)
        Supervisor.initWithUser(auth_path, auth_args_buf[0..auth_argc], child_uid, child_gid)
    else
        Supervisor.init(auth_path, auth_args_buf[0..auth_argc]);
    var core_sup = if (child_uid != 0)
        Supervisor.initWithUser(core_path, core_args_buf[0..core_argc], child_uid, child_gid)
    else
        Supervisor.init(core_path, core_args_buf[0..core_argc]);

    log.info("config: auth_socket={s} db={s} cert={s} key={s}", .{
        auth_socket,
        db_path,
        cert_path orelse "(none)",
        key_path orelse "(none)",
    });

    // Initialize event loop
    var loop = try EventLoop.init(allocator, 8);
    defer loop.deinit();

    // Register signals (automatic masking)
    try loop.addSignal(posix.SIG.TERM);
    try loop.addSignal(posix.SIG.INT);
    try loop.addSignal(posix.SIG.HUP);

    // Spawn xmppd-auth first (must be ready before core connects)
    const auth_pid = try auth_sup.spawnChild();
    try loop.addProcess(auth_pid);
    writeChildPid("/var/run/xmppd/auth.pid", auth_pid);
    log.info("auth daemon started, waiting for socket", .{});

    // Brief delay for auth daemon to bind its socket
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Spawn xmppd-core
    const core_pid = try core_sup.spawnChild();
    try loop.addProcess(core_pid);
    writeChildPid("/var/run/xmppd/core.pid", core_pid);

    // Timer idents for restart backoff
    const AUTH_UDATA: usize = 1;
    const CORE_UDATA: usize = 2;

    // Supervisor event loop
    var running = true;
    while (running) {
        const events = loop.poll(null) catch |err| {
            log.err("event loop poll failed: {}", .{err});
            break;
        };

        for (events) |ev| {
            switch (ev) {
                .process_exit => |p| {
                    if (auth_sup.child_pid != null and p.pid == auth_sup.child_pid.?) {
                        _ = auth_sup.waitChild() catch {};
                        const should_restart = auth_sup.handleChildExit(p.status);
                        if (should_restart) {
                            log.info("restarting auth daemon in {d}ms", .{auth_sup.backoffMs()});
                            loop.addTimer(AUTH_UDATA, auth_sup.backoffMs(), true) catch {};
                        } else {
                            running = false;
                        }
                    } else if (core_sup.child_pid != null and p.pid == core_sup.child_pid.?) {
                        _ = core_sup.waitChild() catch {};
                        const should_restart = core_sup.handleChildExit(p.status);
                        if (should_restart) {
                            log.info("restarting core in {d}ms", .{core_sup.backoffMs()});
                            loop.addTimer(CORE_UDATA, core_sup.backoffMs(), true) catch {};
                        } else {
                            running = false;
                        }
                    }
                },
                .timer => |t| {
                    if (t.ident == AUTH_UDATA) {
                        const new_pid = auth_sup.spawnChild() catch |err| {
                            log.err("failed to respawn auth daemon: {}", .{err});
                            running = false;
                            continue;
                        };
                        loop.addProcess(new_pid) catch {};
                    } else if (t.ident == CORE_UDATA) {
                        const new_pid = core_sup.spawnChild() catch |err| {
                            log.err("failed to respawn core: {}", .{err});
                            running = false;
                            continue;
                        };
                        loop.addProcess(new_pid) catch {};
                    }
                },
                .signal => |s| {
                    if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                        log.info("received signal {d}, shutting down", .{s.signo});
                        core_sup.shutdown();
                        _ = core_sup.waitChild() catch {};
                        auth_sup.shutdown();
                        _ = auth_sup.waitChild() catch {};
                        running = false;
                    } else if (s.signo == posix.SIG.HUP) {
                        log.info("received SIGHUP, forwarding to auth daemon", .{});
                        auth_sup.forwardSignal(@intCast(s.signo));
                    }
                },
                else => {},
            }
        }
    }

    // Clean up child PID files on graceful shutdown
    removeChildPid("/var/run/xmppd/auth.pid");
    removeChildPid("/var/run/xmppd/core.pid");

    log.info("xmppd master shutdown complete", .{});
}

/// Write a child PID to a file for orphan detection on restart.
fn writeChildPid(path: []const u8, pid: posix.pid_t) void {
    const file = std.fs.cwd().createFile(path, .{}) catch return;
    defer file.close();
    var buf: [20]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d}\n", .{pid}) catch return;
    file.writeAll(s) catch {};
}

/// Remove a child PID file (called during clean shutdown).
fn removeChildPid(path: []const u8) void {
    std.fs.cwd().deleteFile(path) catch {};
}

/// Check for an orphaned child process from a previous master instance.
/// If the PID file exists and the process is still alive, terminate it.
fn cleanupOrphan(path: []const u8) void {
    const file = std.fs.cwd().openFile(path, .{}) catch return;
    defer file.close();

    var buf: [20]u8 = undefined;
    const n = posix.read(file.handle, &buf) catch return;
    if (n == 0) return;

    const trimmed = std.mem.trimRight(u8, buf[0..n], "\n \t\r");
    const pid = std.fmt.parseInt(posix.pid_t, trimmed, 10) catch return;
    if (pid <= 1) return;

    // Check if process exists
    const ret = std.c.kill(pid, 0);
    if (ret != 0) {
        // Process doesn't exist — clean up stale PID file
        std.fs.cwd().deleteFile(path) catch {};
        return;
    }

    // Process exists — send SIGTERM, wait briefly, then SIGKILL
    log.warn("killing orphaned child pid={d} from {s}", .{ pid, path });
    _ = std.c.kill(pid, posix.SIG.TERM);
    std.Thread.sleep(2 * std.time.ns_per_s);

    // Check again
    const ret2 = std.c.kill(pid, 0);
    if (ret2 == 0) {
        log.warn("orphan pid={d} did not exit, sending SIGKILL", .{pid});
        _ = std.c.kill(pid, posix.SIG.KILL);
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    std.fs.cwd().deleteFile(path) catch {};
}

fn printUsage() void {
    const usage =
        \\Usage: xmppd [OPTIONS]
        \\
        \\Options:
        \\  --host HOST        XMPP server hostname (default: localhost)
        \\  --port PORT        STARTTLS port (default: 5222)
        \\  --cert PATH        TLS certificate file (PEM)
        \\  --key PATH         TLS private key file (PEM)
        \\  --core-path PATH   Path to xmppd-core binary (default: xmppd-core)
        \\  --auth-path PATH   Path to xmppd-auth binary (default: xmppd-auth)
        \\  --auth-socket PATH IPC socket path (default: /var/run/xmppd/auth.sock)
        \\  --db PATH          User database path (default: /var/db/xmppd/users.db)
        \\  --config PATH, -c  Config file path (passed to children)
        \\  --log-file PATH    Log file path (default: /var/log/xmppd/xmppd.log)
        \\  --background, -b   Daemonize (fork, detach from terminal)
        \\  --help, -h         Show this help
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}
