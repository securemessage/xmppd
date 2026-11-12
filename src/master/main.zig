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
//!   ├── xmppd-s2s  (federation daemon)
//!   └── xmppd-core (worker, handles connections)
//! ```
//!
//! The master passes configuration to children via command-line arguments.
//! xmppd-auth must be ready before xmppd-core starts (core connects to
//! the auth IPC socket). In the future, socket fds will be passed via
//! SCM_RIGHTS for proper privilege separation.

const std = @import("std");
const xmppd_log = @import("xmppd_log");
const root_allocator = @import("root_allocator");
pub const std_options = xmppd_log.std_options;

const posix = std.posix;
const Supervisor = @import("supervisor.zig").Supervisor;
const procinfo = @import("procinfo.zig");
const net = @import("net");
const runtime_mod = @import("runtime.zig");
const Runtime = runtime_mod.Runtime;
const ChildCtl = runtime_mod.ChildCtl;
const config_mod = @import("config");

const log = std.log.scoped(.xmppd);

// Test decls are collected only from files reachable through analyzed
// decls, and main() is never analyzed under `zig test`: pull the imported
// files in so procinfo and runtime tests run under master-tests.
comptime {
    _ = procinfo;
    _ = Runtime;
}

pub fn main() !void {
    var root = root_allocator.Root.init();
    defer root.deinit();
    const allocator = root.allocator();

    // Parse command-line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var host: []const u8 = "localhost";
    var port: []const u8 = "5222";
    var bind_address: []const u8 = "0.0.0.0";
    var s2s_bind_address: ?[]const u8 = null;
    var cert_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;
    var core_path: []const u8 = "xmppd-core";
    var auth_path: []const u8 = "xmppd-auth";
    var s2s_path: []const u8 = "xmppd-s2s";
    var auth_socket: []const u8 = "/var/run/xmppd/auth.sock";
    var s2s_socket: []const u8 = "/var/run/xmppd/s2s.sock";
    var s2s_port: []const u8 = "5269";
    var s2s_enabled: bool = true;
    var db_path: []const u8 = "/var/db/xmppd/users.db";
    var config_path: ?[]const u8 = null;
    var muc_host_cfg: ?[]const u8 = null;
    var run_user: ?[]const u8 = null;
    var log_file: []const u8 = "/var/log/xmppd/xmppd.log";
    var run_dir: []const u8 = "/var/run/xmppd";
    var daemonize: bool = false;
    var workers: u16 = 0; // 0 = auto-detect CPU count

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
        } else if (std.mem.eql(u8, arg, "--bind")) {
            bind_address = args.next() orelse {
                log.err("--bind requires a value", .{});
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
        } else if (std.mem.eql(u8, arg, "--s2s-path")) {
            s2s_path = args.next() orelse {
                log.err("--s2s-path requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--no-s2s")) {
            s2s_enabled = false;
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
        } else if (std.mem.eql(u8, arg, "--run-dir")) {
            run_dir = args.next() orelse {
                log.err("--run-dir requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--background") or std.mem.eql(u8, arg, "-b")) {
            daemonize = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            printVersion();
            return;
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
        if (std.mem.eql(u8, bind_address, "0.0.0.0")) {
            if (c.get("server", "bind_address")) |v| bind_address = v;
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

        // [s2s] section
        if (std.mem.eql(u8, s2s_socket, "/var/run/xmppd/s2s.sock")) {
            if (c.get("s2s", "socket")) |v| s2s_socket = v;
        }
        if (std.mem.eql(u8, s2s_port, "5269")) {
            if (c.get("s2s", "port")) |v| s2s_port = v;
        }
        if (c.get("s2s", "bind_address")) |v| s2s_bind_address = v;

        // [muc] section (s2s federation to= served-host check)
        if (c.get("muc", "host")) |v| muc_host_cfg = v;

        // [core] section — workers
        if (workers == 0) {
            if (c.get("core", "workers")) |v| {
                workers = std.fmt.parseInt(u16, v, 10) catch 0;
            }
        }

        // [master] section
        if (std.mem.eql(u8, core_path, "xmppd-core")) {
            if (c.get("master", "core_path")) |v| core_path = v;
        }
        if (std.mem.eql(u8, auth_path, "xmppd-auth")) {
            if (c.get("master", "auth_path")) |v| auth_path = v;
        }
        if (std.mem.eql(u8, s2s_path, "xmppd-s2s")) {
            if (c.get("master", "s2s_path")) |v| s2s_path = v;
        }
    }
    defer if (cfg) |*c| c.deinit();

    // Resolve the unprivileged user for child processes. A root master
    // without a run user would start every child as root, and a run user
    // that resolves to uid 0 does not drop privileges: refuse both.
    const euid = posix.geteuid();
    const ids = decideRunUser(run_user, euid) catch |err| {
        switch (err) {
            error.RunUserRequired => log.err("running as root requires a run user; refusing to start", .{}),
            error.RunUserIsRoot => log.err("run user '{s}' resolves to root; refusing to start", .{run_user orelse ""}),
            error.RunUserNotFound => log.err("user '{s}' not found: refusing to start; children must not run as root", .{run_user orelse ""}),
            error.RunUserTooLong => log.err("user name too long: {s}", .{run_user orelse ""}),
        }
        return err;
    };
    const child_uid = ids.uid;
    const child_gid = ids.gid;
    if (run_user) |username| {
        log.info("child processes will run as {s} (uid={d} gid={d})", .{ username, child_uid, child_gid });
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
    var pidfile_path_buf: [4096]u8 = undefined;
    const pidfile_path = std.fmt.bufPrint(&pidfile_path_buf, "{s}/xmppd.pid", .{run_dir}) catch return error.PathTooLong;
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
    // Kill any stale children from a previous master that died ungracefully.
    // The exe basename ride-along keeps us from ever SIGKILLing a pid that
    // was recycled by an unrelated process (T259).
    {
        var orphan_buf: [4096]u8 = undefined;
        const orphan_spec = [_]struct { file: []const u8, exe: []const u8 }{
            .{ .file = "auth.pid", .exe = "xmppd-auth" },
            .{ .file = "s2s.pid", .exe = "xmppd-s2s" },
            .{ .file = "core.pid", .exe = "xmppd-core" },
        };
        for (orphan_spec) |spec| {
            const p = std.fmt.bufPrint(&orphan_buf, "{s}/{s}", .{ run_dir, spec.file }) catch continue;
            procinfo.cleanupOrphan(p, spec.exe);
        }
    }

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

    // --- Resolve worker count ---
    // 0 = auto-detect from hw.ncpu sysctl (FreeBSD) or fallback to 1
    if (workers == 0) {
        workers = detectCpuCount();
    }
    if (workers < 1) workers = 1;
    if (workers > 64) workers = 64;
    log.info("worker threads: {d}", .{workers});

    // --- Bind privileged ports while still root ---
    // Create N C2S sockets with SO_REUSEPORT (one per worker thread), and
    // the S2S listener. Children receive them remapped to fds 3.. on exec
    // (Supervisor.applyFdPass, T356/S7): the --listen-fd list is therefore
    // always the deterministic 3,4,...,3+N-1.
    const MAX_WORKERS = 64;
    var c2s_listen_fds: [MAX_WORKERS]posix.fd_t = .{-1} ** MAX_WORKERS;
    var c2s_fd_count: u16 = 0;
    var s2s_listen_fd: posix.fd_t = -1;
    {
        const c2s_port_num = std.fmt.parseInt(u16, port, 10) catch 5222;
        var i: u16 = 0;
        while (i < workers) : (i += 1) {
            c2s_listen_fds[i] = bindC2s(bind_address, c2s_port_num) catch |err| {
                log.err("failed to bind C2S {s}:{s} (socket {d}): {}", .{ bind_address, port, i, err });
                return error.BindFailed;
            };
            c2s_fd_count += 1;
        }
        log.info("bound {d} C2S listener sockets on {s}:{s} (SO_REUSEPORT_LB)", .{ c2s_fd_count, bind_address, port });
    }
    if (s2s_enabled) {
        const s2s_port_num = std.fmt.parseInt(u16, s2s_port, 10) catch 5269;
        const s2s_addr = s2s_bind_address orelse bind_address;
        s2s_listen_fd = bindS2s(s2s_addr, s2s_port_num) catch |err| {
            log.err("failed to bind S2S {s}:{s}: {}", .{ s2s_addr, s2s_port, err });
            return error.BindFailed;
        };
        log.info("bound S2S listener fd={d} {s}:{s}", .{ s2s_listen_fd, s2s_addr, s2s_port });
    }
    defer {
        var i: u16 = 0;
        while (i < c2s_fd_count) : (i += 1) {
            if (c2s_listen_fds[i] >= 0) posix.close(c2s_listen_fds[i]);
        }
    }
    defer if (s2s_listen_fd >= 0) posix.close(s2s_listen_fd);

    // Deterministic fd list: applyFdPass remaps the sockets to 3,4,5,...
    var c2s_fd_str_buf: [256]u8 = undefined;
    var c2s_fd_str_len: usize = 0;
    {
        var i: u16 = 0;
        while (i < c2s_fd_count) : (i += 1) {
            if (i > 0) {
                c2s_fd_str_buf[c2s_fd_str_len] = ',';
                c2s_fd_str_len += 1;
            }
            const written = std.fmt.bufPrint(c2s_fd_str_buf[c2s_fd_str_len..], "{d}", .{3 + i}) catch break;
            c2s_fd_str_len += written.len;
        }
    }
    const c2s_fd_str = c2s_fd_str_buf[0..c2s_fd_str_len];
    const s2s_fd_str = "3"; // the single remapped s2s listener slot

    // Build child argv: pass --config, --db, --socket to auth, s2s, and core children
    var auth_args_buf: [6][]const u8 = undefined;
    var auth_argc: usize = 0;
    if (config_path) |cp| {
        auth_args_buf[auth_argc] = "--config";
        auth_argc += 1;
        auth_args_buf[auth_argc] = cp;
        auth_argc += 1;
    }
    // All auth backends get --db: xmppd-auth uses it for credentials AND
    // locks; xmppd-auth-oidc reads only the shared lock table (S3:
    // without it the OIDC daemon opened a fresh store and found nothing).
    auth_args_buf[auth_argc] = "--db";
    auth_argc += 1;
    auth_args_buf[auth_argc] = db_path;
    auth_argc += 1;
    auth_args_buf[auth_argc] = "--socket";
    auth_argc += 1;
    auth_args_buf[auth_argc] = auth_socket;
    auth_argc += 1;

    var s2s_args_buf: [16][]const u8 = undefined;
    var s2s_argc: usize = 0;
    if (config_path) |cp| {
        s2s_args_buf[s2s_argc] = "--config";
        s2s_argc += 1;
        s2s_args_buf[s2s_argc] = cp;
        s2s_argc += 1;
    }
    s2s_args_buf[s2s_argc] = "--host";
    s2s_argc += 1;
    s2s_args_buf[s2s_argc] = host;
    s2s_argc += 1;
    s2s_args_buf[s2s_argc] = "--port";
    s2s_argc += 1;
    s2s_args_buf[s2s_argc] = s2s_port;
    s2s_argc += 1;
    s2s_args_buf[s2s_argc] = "--core-socket";
    s2s_argc += 1;
    s2s_args_buf[s2s_argc] = s2s_socket;
    s2s_argc += 1;
    // Served MUC host for the s2s to= check; defaults to conference.<host>.
    var muc_host_buf: [512]u8 = undefined;
    const muc_host: []const u8 = muc_host_cfg orelse
        (std.fmt.bufPrint(&muc_host_buf, "conference.{s}", .{host}) catch "conference");
    s2s_args_buf[s2s_argc] = "--muc-host";
    s2s_argc += 1;
    s2s_args_buf[s2s_argc] = muc_host;
    s2s_argc += 1;
    if (cert_path) |cp| {
        s2s_args_buf[s2s_argc] = "--cert";
        s2s_argc += 1;
        s2s_args_buf[s2s_argc] = cp;
        s2s_argc += 1;
    }
    if (key_path) |kp| {
        s2s_args_buf[s2s_argc] = "--key";
        s2s_argc += 1;
        s2s_args_buf[s2s_argc] = kp;
        s2s_argc += 1;
    }
    if (s2s_listen_fd >= 0) {
        s2s_args_buf[s2s_argc] = "--listen-fd";
        s2s_argc += 1;
        s2s_args_buf[s2s_argc] = s2s_fd_str;
        s2s_argc += 1;
    }

    var core_args_buf: [14][]const u8 = undefined;
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
    if (s2s_enabled) {
        core_args_buf[core_argc] = "--s2s-socket";
        core_argc += 1;
        core_args_buf[core_argc] = s2s_socket;
        core_argc += 1;
    }
    core_args_buf[core_argc] = "--listen-fd";
    core_argc += 1;
    core_args_buf[core_argc] = c2s_fd_str;
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

    // Initialize supervisors for all children
    var auth_sup = try initSupervisor(auth_path, auth_args_buf[0..auth_argc], child_uid, child_gid, euid);
    var s2s_sup = try initSupervisor(s2s_path, s2s_args_buf[0..s2s_argc], child_uid, child_gid, euid);
    var core_sup = try initSupervisor(core_path, core_args_buf[0..core_argc], child_uid, child_gid, euid);

    // Per-child fd contract (S7): core gets the C2S listeners, s2s the S2S
    // listener, auth nothing; everything else in the master's table closes.
    core_sup.pass_fds = c2s_listen_fds[0..c2s_fd_count];
    // Hoisted: pass_fds points at it at spawn AND every respawn (S7).
    var s2s_pass_fds: [1]posix.fd_t = undefined;
    if (s2s_listen_fd >= 0) {
        s2s_pass_fds[0] = s2s_listen_fd;
        s2s_sup.pass_fds = s2s_pass_fds[0..1];
    }

    log.info("config: auth_socket={s} s2s={any} s2s_socket={s} db={s} cert={s} key={s}", .{
        auth_socket,
        s2s_enabled,
        s2s_socket,
        db_path,
        cert_path orelse "(none)",
        key_path orelse "(none)",
    });

    // Spawn order is the child table order (dependencies first); shutdown
    // signals every child at once. s2s sits between auth and core when
    // enabled. auth and s2s gate the sequence on their IPC socket: core
    // must not spawn until each accepts connects. Only auth (both
    // backends) handles SIGHUP; core and s2s would die on a forwarded one.
    var children_buf: [3]ChildCtl = undefined;
    var child_count: usize = 0;
    children_buf[child_count] = .{ .name = "auth", .pid_file = "auth.pid", .exe_base = "xmppd-auth", .ready_socket = auth_socket, .forward_hup = true, .sup = &auth_sup };
    child_count += 1;
    if (s2s_enabled) {
        children_buf[child_count] = .{ .name = "s2s", .pid_file = "s2s.pid", .exe_base = "xmppd-s2s", .ready_socket = s2s_socket, .sup = &s2s_sup };
        child_count += 1;
    }
    children_buf[child_count] = .{ .name = "core", .pid_file = "core.pid", .exe_base = "xmppd-core", .sup = &core_sup };
    child_count += 1;

    var rt = try Runtime.init(allocator, children_buf[0..child_count], run_dir, .{});
    defer rt.deinit();

    try rt.start();
    rt.run();

    // Reaped children lose their pid files; a survivor keeps its file
    // for the next master's orphan cleanup.
    rt.removeReapedPidFiles();

    if (rt.start_failed) return error.StartupFailed;
    if (rt.runtime_failed) return error.SupervisionFailed;
    log.info("xmppd master shutdown complete", .{});
}

/// Build a supervisor for one child. A root process without a run user is
/// refused by the Supervisor itself; log that refusal at err here so a
/// disagreement between decideRunUser and the Supervisor is not silent.
fn initSupervisor(
    exe_path: []const u8,
    args: []const []const u8,
    uid: posix.uid_t,
    gid: posix.gid_t,
    euid: posix.uid_t,
) !Supervisor {
    if (uid != 0) {
        return Supervisor.initWithUser(exe_path, args, uid, gid, euid) catch |err| {
            if (err == error.RunUserRequired) {
                log.err("running as root requires a run user; refusing to start", .{});
            }
            return err;
        };
    }
    return Supervisor.init(exe_path, args, euid) catch |err| {
        if (err == error.RunUserRequired) {
            log.err("running as root requires a run user; refusing to start", .{});
        }
        return err;
    };
}

/// The uid and gid a child runs as.
const RunUserIds = struct { uid: posix.uid_t, gid: posix.gid_t };

/// Passwd lookup used by decideRunUser; injectable for tests.
const RunUserLookup = *const fn ([]const u8) (error{ RunUserNotFound, RunUserTooLong }!RunUserIds);

/// Resolve the run user's uid and gid. A missing user or an unusable name
/// is a startup failure: falling back to uid 0 would run the children as
/// root (C5). Logging belongs to the caller.
fn resolveRunUser(username: []const u8) (error{ RunUserNotFound, RunUserTooLong }!RunUserIds) {
    var user_buf: [256]u8 = undefined;
    if (username.len >= user_buf.len) return error.RunUserTooLong;
    @memcpy(user_buf[0..username.len], username);
    user_buf[username.len] = 0;
    const pw = std.c.getpwnam(@ptrCast(&user_buf)) orelse return error.RunUserNotFound;
    return .{ .uid = pw.uid, .gid = pw.gid };
}

/// Decide the uid/gid child processes run as. A master started as root
/// must name an unprivileged run user; a run user that resolves to uid 0
/// does not drop privileges and is refused. Without root and without a
/// run user the children inherit the master's identity (0/0 means
/// "inherit" at the supervisor call sites).
fn decideRunUser(username: ?[]const u8, euid: posix.uid_t) (error{ RunUserRequired, RunUserIsRoot, RunUserNotFound, RunUserTooLong }!RunUserIds) {
    return decideRunUserWith(username, euid, &resolveRunUser);
}

/// The decision with an injectable lookup: the refusal compares the
/// resolved uid, so any name that resolves to uid 0 is refused.
fn decideRunUserWith(username: ?[]const u8, euid: posix.uid_t, lookup: RunUserLookup) (error{ RunUserRequired, RunUserIsRoot, RunUserNotFound, RunUserTooLong }!RunUserIds) {
    const name = username orelse {
        if (euid == 0) return error.RunUserRequired;
        return .{ .uid = 0, .gid = 0 };
    };
    const ids = try lookup(name);
    if (ids.uid == 0) return error.RunUserIsRoot;
    return ids;
}


fn printUsage() void {
    const usage =
        \\Usage: xmppd [OPTIONS]
        \\
        \\Options:
        \\  --host HOST        XMPP server hostname (default: localhost)
        \\  --port PORT        STARTTLS port (default: 5222)
        \\  --bind ADDR        c2s/s2s listen address literal (default: 0.0.0.0)
        \\  --cert PATH        TLS certificate file (PEM)
        \\  --key PATH         TLS private key file (PEM)
        \\  --core-path PATH   Path to xmppd-core binary (default: xmppd-core)
        \\  --auth-path PATH   Path to xmppd-auth binary (default: xmppd-auth)
        \\  --s2s-path PATH    Path to xmppd-s2s binary (default: xmppd-s2s)
        \\  --no-s2s           Disable S2S federation
        \\  --auth-socket PATH IPC socket path (default: /var/run/xmppd/auth.sock)
        \\  --db PATH          User database path (default: /var/db/xmppd/users.db)
        \\  --config PATH, -c  Config file path (passed to children)
        \\  --log-file PATH    Log file path (default: /var/log/xmppd/xmppd.log)
        \\  --run-dir PATH     Runtime dir for PID files (default: /var/run/xmppd)
        \\  --background, -b   Daemonize (fork, detach from terminal)
        \\  --version, -v      Print version and exit
        \\  --help, -h         Show this help
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}

fn printVersion() void {
    const build_options = @import("build_options");
    var line_buf: [64]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "xmppd {s}\n", .{build_options.version}) catch return;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(line) catch {};
}

/// c2s listeners share lib/net's bindTcp (V16): bind_address literals and
/// IPv6 are honored, REUSEPORT_LB load-balances accepts across workers.
fn bindC2s(address: []const u8, bind_port: u16) !posix.fd_t {
    return net.bindTcp(&.{ .address = address, .port = bind_port, .reuse_port_lb = true });
}

/// One s2s listener per master: no REUSEPORT_LB.
fn bindS2s(address: []const u8, bind_port: u16) !posix.fd_t {
    return net.bindTcp(&.{ .address = address, .port = bind_port, .reuse_port_lb = false });
}

/// Detect the number of CPU cores available.
/// Uses hw.ncpu sysctl on FreeBSD, falls back to 1.
fn detectCpuCount() u16 {
    // sysctlbyname("hw.ncpu")
    var ncpu: c_int = 1;
    var len: usize = @sizeOf(c_int);
    const name = "hw.ncpu";
    const ret = std.c.sysctlbyname(
        @ptrCast(name.ptr),
        @ptrCast(&ncpu),
        &len,
        null,
        0,
    );
    if (ret == 0 and ncpu > 0) {
        return @intCast(@min(ncpu, 64));
    }
    return 1;
}

test "resolveRunUser: a missing user is a startup failure, not a root fallback (C5)" {
    try std.testing.expectError(error.RunUserNotFound, resolveRunUser("xmppd-no-such-user"));
    var too_long: [256]u8 = @splat('x');
    try std.testing.expectError(error.RunUserTooLong, resolveRunUser(&too_long));
}

test "resolveRunUser: a configured user resolves to its passwd entry (C5)" {
    const ids = try resolveRunUser("root");
    try std.testing.expectEqual(@as(posix.uid_t, 0), ids.uid);
    try std.testing.expectEqual(@as(posix.gid_t, 0), ids.gid);
}

test "initSupervisor logs a root refusal at err" {
    const fds = try posix.pipe();
    const pid = try posix.fork();
    if (pid == 0) {
        _ = posix.close(fds[0]);
        posix.dup2(fds[1], 2) catch std.c._exit(125);
        _ = posix.close(fds[1]);
        const result = initSupervisor("/unused", &.{}, 0, 0, 0);
        std.c._exit(if (result) |_| 1 else |err| if (err == error.RunUserRequired) 0 else 2);
    }
    _ = posix.close(fds[1]);
    var buf: [512]u8 = undefined;
    const n = try posix.read(fds[0], &buf);
    _ = posix.close(fds[0]);
    const res = posix.waitpid(pid, 0);
    try std.testing.expect(posix.W.IFEXITED(res.status));
    try std.testing.expectEqual(@as(u8, 0), posix.W.EXITSTATUS(res.status));
    try std.testing.expect(std.mem.indexOf(
        u8,
        buf[0..n],
        "(err): running as root requires a run user; refusing to start",
    ) != null);
}

test "decideRunUser: root without a run user is refused" {
    try std.testing.expectError(error.RunUserRequired, decideRunUser(null, 0));
}

test "decideRunUser: a run user that resolves to root is refused" {
    try std.testing.expectError(error.RunUserIsRoot, decideRunUser("root", 0));
}

test "decideRunUser: non-root without a run user inherits" {
    const ids = try decideRunUser(null, @as(posix.uid_t, 1001));
    try std.testing.expectEqual(@as(posix.uid_t, 0), ids.uid);
    try std.testing.expectEqual(@as(posix.gid_t, 0), ids.gid);
}

test "decideRunUser: an unprivileged run user resolves to its passwd entry" {
    const expected = try resolveRunUser("nobody");
    const ids = try decideRunUser("nobody", 0);
    try std.testing.expectEqual(expected.uid, ids.uid);
    try std.testing.expectEqual(expected.gid, ids.gid);
    try std.testing.expect(ids.uid != 0);
}

/// Any non-empty name resolves to uid 0, like the conventional toor alias.
fn lookupUidZero(name: []const u8) (error{ RunUserNotFound, RunUserTooLong }!RunUserIds) {
    if (name.len == 0) return error.RunUserNotFound;
    return .{ .uid = 0, .gid = 0 };
}

test "decideRunUser: a uid-0 alias is refused by uid, not by name" {
    // A name comparison against "root" would admit any alias that resolves
    // to uid 0. The stub keeps the test independent of the host passwd
    // database.
    try std.testing.expectError(error.RunUserIsRoot, decideRunUserWith("toor", 0, &lookupUidZero));
    try std.testing.expectError(error.RunUserIsRoot, decideRunUserWith("alias", 0, &lookupUidZero));

    // The real lookup agrees when the host carries the conventional toor
    // alias; hosts without it skip this half.
    const ids = resolveRunUser("toor") catch return;
    if (ids.uid == 0) {
        try std.testing.expectError(error.RunUserIsRoot, decideRunUser("toor", 0));
    }
}

fn boundFamily(fd: posix.fd_t) posix.sa_family_t {
    var ss: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(@TypeOf(ss));
    posix.getsockname(fd, @ptrCast(&ss), &len) catch return 0;
    return ss.family;
}

test "bindC2s/bindS2s honor the address literal, including IPv6" {
    const c2s4 = try bindC2s("127.0.0.1", 0);
    defer posix.close(c2s4);
    try std.testing.expectEqual(@as(posix.sa_family_t, posix.AF.INET), boundFamily(c2s4));

    const s2s4 = try bindS2s("127.0.0.1", 0);
    defer posix.close(s2s4);
    try std.testing.expectEqual(@as(posix.sa_family_t, posix.AF.INET), boundFamily(s2s4));

    const c2s6 = bindC2s("::1", 0) catch return error.SkipZigTest;
    defer posix.close(c2s6);
    try std.testing.expectEqual(@as(posix.sa_family_t, posix.AF.INET6), boundFamily(c2s6));

    // The old helper ignored its address argument: a DNS name must be
    // rejected, not resolved.
    try std.testing.expectError(error.InvalidAddress, bindC2s("example.invalid", 0));
}
