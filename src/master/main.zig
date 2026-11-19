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
//! The master forwards the resolved configuration to core and s2s over
//! a sealed config fd (ADR-9); their argv carries only the CLI-only
//! fields a blob cannot express, like the inherited listen-fd slots.
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
const conf = @import("conf");
const schema = @import("schema");
const Allocator = std.mem.Allocator;
const MasterLoader = schema.MasterLoader;

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

    // Configuration: lib/conf applies default < file < CLI and records
    // provenance. The config path is scanned out of argv first because
    // the file must load before the CLI applies. An unknown argument,
    // unknown file key, or bad value is a startup error with the Diag.
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // argv[0]
    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(allocator);
    while (args.next()) |arg| try argv.append(allocator, arg);

    var diag: conf.Diag = .{};
    var loaded = MasterLoader.load(allocator, .{
        .path = schema.configPathArg(argv.items),
        .args = argv.items,
    }, &diag) catch |err| {
        log.err("{f}", .{&diag});
        return err;
    };
    defer loaded.deinit();
    const v = &loaded.values;

    if (v.meta.version) {
        printVersion();
        return;
    }
    if (v.meta.help) {
        try printUsage(allocator);
        return;
    }

    const host = v.server.hostname;
    const bind_address = v.server.bind_address;
    const s2s_bind_address: ?[]const u8 =
        if (v.s2s.bind_address.len != 0) v.s2s.bind_address else null;
    const cert_path: ?[]const u8 = if (v.tls.cert.len != 0) v.tls.cert else null;
    const key_path: ?[]const u8 = if (v.tls.key.len != 0) v.tls.key else null;
    const core_path = v.master.core_path;
    const auth_path = v.master.auth_path;
    const s2s_path = v.master.s2s_path;
    const auth_socket = v.auth.socket;
    const s2s_socket = v.s2s.socket;
    const s2s_enabled = v.s2s.enabled;
    const db_path = v.server.db_path;
    const run_user: ?[]const u8 = if (v.server.user.len != 0) v.server.user else null;
    const log_file = v.server.log_file;
    const run_dir = v.master.run_dir;
    const daemonize = v.master.background;
    var workers: u16 = switch (v.core.workers) {
        .kw => 0, // auto: resolved to the CPU count below
        .num => |n| n,
    };

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

    log.info("xmppd master starting, host={s} port={d}", .{ host, v.server.c2s_port });

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
        var i: u16 = 0;
        while (i < workers) : (i += 1) {
            c2s_listen_fds[i] = bindC2s(bind_address, v.server.c2s_port) catch |err| {
                log.err("failed to bind C2S {s}:{d} (socket {d}): {}", .{ bind_address, v.server.c2s_port, i, err });
                return error.BindFailed;
            };
            c2s_fd_count += 1;
        }
        log.info("bound {d} C2S listener sockets on {s}:{d} (SO_REUSEPORT_LB)", .{ c2s_fd_count, bind_address, v.server.c2s_port });
    }
    if (s2s_enabled) {
        const s2s_addr = s2s_bind_address orelse bind_address;
        s2s_listen_fd = bindS2s(s2s_addr, v.s2s.port) catch |err| {
            log.err("failed to bind S2S {s}:{d}: {}", .{ s2s_addr, v.s2s.port, err });
            return error.BindFailed;
        };
        log.info("bound S2S listener fd={d} {s}:{d}", .{ s2s_listen_fd, s2s_addr, v.s2s.port });
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

    // The resolved config is serialized once into the sealed blob core
    // and s2s inherit through their pass_fds remap slot (ADR-9); SIGHUP
    // rebuilds it so a respawned child reads fresh values. Child argv
    // then carries only CLI-only fields: the listen-fd remap slots and
    // the conf-fd slot itself. auth keeps resolved values on argv until
    // part 2b.
    var conf_arena = std.heap.ArenaAllocator.init(allocator);
    defer conf_arena.deinit();
    var fwd_diag: conf.Diag = .{};
    const conf_blob = loaded.forwardBlob(conf_arena.allocator(), &fwd_diag) catch |err| {
        log.err("cannot serialize the forwarded config: {f}", .{&fwd_diag});
        return err;
    };
    var conf_fd = conf.ConfFd.create(conf_blob) catch |err| {
        log.err("cannot create the forwarded config fd: {}", .{err});
        return error.ConfFdFailed;
    };
    defer conf_fd.deinit();

    // The conf fd lands on the remap slot right after each child's
    // listeners: core's at 3+c2s_fd_count, s2s' at 4.
    var core_conf_buf: [8]u8 = undefined;
    const core_conf_slot = std.fmt.bufPrint(&core_conf_buf, "{d}", .{3 + c2s_fd_count}) catch unreachable;

    var argv_arena = std.heap.ArenaAllocator.init(allocator);
    defer argv_arena.deinit();
    const child_argv = try buildChildArgv(argv_arena.allocator(), v, .{
        .s2s_listen = s2s_listen_fd >= 0,
        .c2s_fd_str = c2s_fd_str,
        .s2s_fd_str = s2s_fd_str,
        .core_conf_fd = core_conf_slot,
        .s2s_conf_fd = "4",
    });

    // Initialize supervisors for all children
    var auth_sup = try initSupervisor(auth_path, child_argv.auth, child_uid, child_gid, euid);
    var s2s_sup = try initSupervisor(s2s_path, child_argv.s2s, child_uid, child_gid, euid);
    var core_sup = try initSupervisor(core_path, child_argv.core, child_uid, child_gid, euid);

    // Per-child fd contract (S7): core gets the C2S listeners then the
    // conf fd on the next slot, s2s its listener then the conf fd, auth
    // nothing; everything else in the master's table closes.
    var core_pass_fds: [MAX_WORKERS + 1]posix.fd_t = undefined;
    @memcpy(core_pass_fds[0..c2s_fd_count], c2s_listen_fds[0..c2s_fd_count]);
    core_pass_fds[c2s_fd_count] = conf_fd.fd;
    core_sup.pass_fds = core_pass_fds[0 .. c2s_fd_count + 1];
    // Hoisted: pass_fds points at it at spawn AND every respawn (S7).
    var s2s_pass_fds: [2]posix.fd_t = undefined;
    if (s2s_listen_fd >= 0) {
        s2s_pass_fds = .{ s2s_listen_fd, conf_fd.fd };
        s2s_sup.pass_fds = s2s_pass_fds[0..2];
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

    // SIGHUP rebuilds the forwarded blob before the runtime forwards
    // the signal; the pass_fds tail slots move to the new fd so the
    // next spawned core or s2s reads the reloaded values.
    var conf_tails_buf: [2]*posix.fd_t = undefined;
    var conf_tails_len: usize = 0;
    conf_tails_buf[conf_tails_len] = &core_pass_fds[c2s_fd_count];
    conf_tails_len += 1;
    if (s2s_listen_fd >= 0) {
        conf_tails_buf[conf_tails_len] = &s2s_pass_fds[1];
        conf_tails_len += 1;
    }
    var reloader = ConfReloader{
        .gpa = allocator,
        .argv = argv.items,
        .conf_fd = &conf_fd,
        .tails = conf_tails_buf[0..conf_tails_len],
    };
    rt.hup_hook = reloader.hook();

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

/// --help is generated from the schema: every master_cli spelling plus
/// the shared file keys and their defaults. A fresh loader is used so
/// the defaults shown come from the schema initializers, not the
/// resolved values of this run.
fn printUsage(allocator: Allocator) std.Io.Writer.Error!void {
    var gen = MasterLoader.init(allocator);
    defer gen.deinit();
    var buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buf);
    try writeUsage(&stdout.interface, &gen);
    try stdout.interface.flush();
}

fn writeUsage(w: *std.Io.Writer, gen: *const MasterLoader) std.Io.Writer.Error!void {
    try w.writeAll("Usage: xmppd [OPTIONS]\n\n");
    try gen.writeHelp(w);
}

/// The argv each child is spawned with. Slices borrow the loaded values
/// and arena: they must outlive the children's spawn, not their exec.
const ChildArgv = struct {
    auth: []const []const u8,
    s2s: []const []const u8,
    core: []const []const u8,
};

fn buildChildArgv(arena: Allocator, v: *const schema.Sections, rt: struct {
    /// s2s gets its fd pair only when the master bound its listener.
    s2s_listen: bool,
    /// Remapped fd slots for the C2S listeners, comma-separated.
    c2s_fd_str: []const u8,
    /// The single remapped s2s listener slot.
    s2s_fd_str: []const u8,
    /// Remap slot of core's sealed config fd (after its listeners).
    core_conf_fd: []const u8,
    /// Remap slot of s2s' sealed config fd (after its listener).
    s2s_conf_fd: []const u8,
}) error{OutOfMemory}!ChildArgv {
    const config_path: ?[]const u8 =
        if (v.meta.config_path.len != 0) v.meta.config_path else null;

    var auth = std.ArrayList([]const u8).empty;
    if (config_path) |cp| try auth.appendSlice(arena, &.{ "--config", cp });
    // All auth backends get --db: xmppd-auth uses it for credentials AND
    // locks; xmppd-auth-oidc reads only the shared lock table (S3:
    // without it the OIDC daemon opened a fresh store and found nothing).
    try auth.appendSlice(arena, &.{ "--db", v.server.db_path, "--socket", v.auth.socket });

    // core and s2s read the resolved values from the sealed conf fd;
    // their argv carries only the CLI-only fields a blob cannot
    // express (ADR-9): the listen-fd remap slots and the conf-fd slot.
    var s2s = std.ArrayList([]const u8).empty;
    if (rt.s2s_listen) {
        try s2s.appendSlice(arena, &.{ "--listen-fd", rt.s2s_fd_str, "--conf-fd", rt.s2s_conf_fd });
    }

    var core = std.ArrayList([]const u8).empty;
    try core.appendSlice(arena, &.{ "--listen-fd", rt.c2s_fd_str, "--conf-fd", rt.core_conf_fd });

    return .{
        .auth = try auth.toOwnedSlice(arena),
        .s2s = try s2s.toOwnedSlice(arena),
        .core = try core.toOwnedSlice(arena),
    };
}

/// Reloads the shared config on SIGHUP and reseals the forwarded blob,
/// so the next spawned core or s2s inherits the new values. A failed
/// reload keeps the previous blob; the pass_fds tail slots move to the
/// new fd only after the rebuild succeeds.
const ConfReloader = struct {
    gpa: Allocator,
    /// The master's own argv: reload reapplies file then CLI so an
    /// override keeps winning in the forwarded blob.
    argv: []const []const u8,
    conf_fd: *conf.ConfFd,
    /// Tail slots of the child pass_fds arrays that carry the conf fd.
    tails: []const *posix.fd_t,
    /// False once a reload fails; tests read it.
    last_ok: bool = true,

    fn reload(self: *ConfReloader) void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        var diag: conf.Diag = .{};
        var rel = MasterLoader.load(arena.allocator(), .{
            .path = schema.configPathArg(self.argv),
            .args = self.argv,
        }, &diag) catch {
            self.last_ok = false;
            log.warn("config reload failed; keeping the previous forwarded config: {f}", .{&diag});
            return;
        };
        defer rel.deinit();
        const blob = rel.forwardBlob(arena.allocator(), &diag) catch {
            self.last_ok = false;
            log.warn("config reload failed; keeping the previous forwarded config: {f}", .{&diag});
            return;
        };
        self.conf_fd.rebuild(blob) catch |err| {
            self.last_ok = false;
            log.warn("config reload failed; keeping the previous forwarded config: {}", .{err});
            return;
        };
        for (self.tails) |tail| tail.* = self.conf_fd.fd;
        self.last_ok = true;
        log.info("reloaded configuration into the forwarded config blob", .{});
    }

    fn hookEntry(ctx: *anyopaque) void {
        const self: *ConfReloader = @ptrCast(@alignCast(ctx));
        self.reload();
    }

    fn hook(self: *ConfReloader) runtime_mod.HupHook {
        return .{ .ctx = self, .run = hookEntry };
    }
};

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

// ============================================================================
// lib/conf loading tests (X4 part 1, ADR-9)
// ============================================================================

/// Writes `content` to a temp file and returns its absolute path in `buf`.
fn writeTempConfig(dir: *std.fs.Dir, name: []const u8, content: []const u8, buf: []u8) ![]const u8 {
    const f = try dir.createFile(name, .{});
    defer f.close();
    try f.writeAll(content);
    return try dir.realpath(name, buf);
}

test "master config: precedence default < file < CLI with provenance" {
    // Goal: a CLI flag wins over the file, the file wins over the
    // schema default, and each field's provenance says where it landed.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "t.ini",
        \\[server]
        \\hostname = file.test
        \\c2s_port = 6000
        \\
    , &path_buf);

    var diag: conf.Diag = .{};
    var l = try MasterLoader.load(std.testing.allocator, .{
        .path = path,
        .args = &.{ "--port", "6001" },
    }, &diag);
    defer l.deinit();

    try std.testing.expectEqual(@as(u16, 6001), l.values.server.c2s_port);
    try std.testing.expectEqual(.cli, l.provenanceOf("server", "c2s_port"));
    try std.testing.expectEqualStrings("file.test", l.values.server.hostname);
    try std.testing.expectEqual(.file, l.provenanceOf("server", "hostname"));
    try std.testing.expectEqual(@as(u32, 2), l.lineOf("server", "hostname"));
    try std.testing.expectEqualStrings("/var/db/xmppd/users.db", l.values.server.db_path);
    try std.testing.expectEqual(.default, l.provenanceOf("server", "db_path"));
}

test "master config: the shared file parses keys belonging to other daemons" {
    // Goal: the one file serves every daemon; the master accepts sections
    // and keys it does not consume itself (auth, oidc, ctl-free grammar)
    // instead of erroring on another daemon's configuration.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "shared.ini",
        \\[server]
        \\hostname = shared.test
        \\lmdb_map_size_mb = 16384
        \\[auth]
        \\rate_max_per_account = 7
        \\ip_lockout_threshold = 30
        \\users_scan_limit = 5000
        \\[oidc]
        \\issuer = https://idp.example
        \\idp_threads = 4
        \\idp_timeout_ms = 8000
        \\localpart_claim = email
        \\localpart_auto_suffix = true
        \\[core]
        \\max_sessions = 8192
        \\workers = auto
        \\
    , &path_buf);

    var diag: conf.Diag = .{};
    var l = try MasterLoader.load(std.testing.allocator, .{ .path = path }, &diag);
    defer l.deinit();

    try std.testing.expectEqualStrings("shared.test", l.values.server.hostname);
    try std.testing.expectEqual(@as(usize, 16384), l.values.server.lmdb_map_size_mb);
    try std.testing.expectEqual(@as(u32, 7), l.values.auth.max_per_account);
    try std.testing.expectEqual(@as(u16, 30), l.values.auth.ip_lockout_threshold);
    try std.testing.expectEqual(@as(usize, 5000), l.values.auth.users_scan_limit);
    try std.testing.expectEqualStrings("https://idp.example", l.values.oidc.issuer);
    try std.testing.expectEqual(@as(u8, 4), l.values.oidc.idp_threads);
    try std.testing.expectEqual(@as(u32, 8000), l.values.oidc.idp_timeout_ms);
    try std.testing.expect(l.values.oidc.localpart_auto_suffix);
    try std.testing.expectEqual(@as(usize, 8192), l.values.core.max_sessions);
    switch (l.values.core.workers) {
        .kw => |k| try std.testing.expectEqual(.auto, k),
        .num => return error.TestUnexpectedResult,
    }
}

test "master config: an unknown key fails with file:line in the diag" {
    // Goal: a misspelled or foreign key is a startup error naming the
    // file and line, never a silent skip.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "bad.ini", "[server]\nhostname = ok.test\nhostnam = typo.test\n", &path_buf);

    var diag: conf.Diag = .{};
    var l = MasterLoader.init(std.testing.allocator);
    defer l.deinit();
    try std.testing.expectError(error.UnknownKey, l.loadFile(path, &diag));
    try std.testing.expectEqual(@as(u32, 3), diag.line);
    try std.testing.expectEqualStrings("hostnam", diag.key);
    try std.testing.expect(std.mem.indexOf(u8, diag.path, "bad.ini") != null);
}

test "master config: a bad value fails with the key and value in the diag" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "badval.ini", "[server]\nc2s_port = notaport\n", &path_buf);

    var diag: conf.Diag = .{};
    var l = MasterLoader.init(std.testing.allocator);
    defer l.deinit();
    try std.testing.expectError(error.BadValue, l.loadFile(path, &diag));
    try std.testing.expectEqual(@as(u32, 2), diag.line);
    try std.testing.expectEqualStrings("c2s_port", diag.key);
    try std.testing.expectEqualStrings("notaport", diag.value);
}

test "master --help lists every CLI spelling from the schema" {
    // Goal: usage is generated, so every master_cli name and alias must
    // appear; a hand-written string could silently miss a spelling.
    var gen = MasterLoader.init(std.testing.allocator);
    defer gen.deinit();

    var buf: [16384]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeUsage(&w, &gen);
    const help = w.buffered();

    inline for (schema.master_cli) |c| {
        try std.testing.expect(std.mem.indexOf(u8, help, "--" ++ c.name) != null);
        inline for (c.aliases) |a| {
            try std.testing.expect(std.mem.indexOf(u8, help, ", -" ++ a) != null);
        }
    }
    inline for (schema.file_spec) |f| {
        if (!f.in_file) continue;
        const key = if (f.key.len != 0) f.key else f.field;
        try std.testing.expect(std.mem.indexOf(u8, help, key) != null);
    }
}

test "master config: --config path is scanned from argv in every spelling" {
    try std.testing.expectEqualStrings("a.ini", schema.configPathArg(&.{ "--config", "a.ini" }).?);
    try std.testing.expectEqualStrings("b.ini", schema.configPathArg(&.{ "-c", "b.ini" }).?);
    try std.testing.expectEqualStrings("c.ini", schema.configPathArg(&.{"--config=c.ini"}).?);
    try std.testing.expectEqualStrings("d.ini", schema.configPathArg(&.{"-c=d.ini"}).?);
    try std.testing.expect(schema.configPathArg(&.{ "--", "--config", "x.ini" }) == null);
    try std.testing.expect(schema.configPathArg(&.{ "--host", "h.test" }) == null);
    // No value: the loader reports the missing value itself.
    try std.testing.expect(schema.configPathArg(&.{"--config"}) == null);
}

test "conf fd slot is scanned from argv in every spelling" {
    try std.testing.expectEqual(@as(i32, 7), schema.confFdArg(&.{ "--conf-fd", "7" }).?);
    try std.testing.expectEqual(@as(i32, 9), schema.confFdArg(&.{"--conf-fd=9"}).?);
    try std.testing.expect(schema.confFdArg(&.{ "--", "--conf-fd", "3" }) == null);
    try std.testing.expect(schema.confFdArg(&.{ "--conf-fd", "notanfd" }) == null);
    try std.testing.expect(schema.confFdArg(&.{"--conf-fd"}) == null);
    try std.testing.expect(schema.confFdArg(&.{ "--host", "h.test" }) == null);
}

/// The value argv carries for a two-token option; null when absent.
fn argvValue(argv: []const []const u8, opt: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 1 < argv.len) : (i += 1) {
        if (std.mem.eql(u8, argv[i], opt)) return argv[i + 1];
    }
    return null;
}

/// Asserts the blob carries a canonical "--key=value\n" line.
fn expectBlobLine(blob: []const u8, key: []const u8, value: []const u8) !void {
    var buf: [4096]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "--{s}={s}\n", .{ key, value });
    try std.testing.expect(std.mem.indexOf(u8, blob, line) != null);
}

test "master child argv: core and s2s carry only CLI-only keys; resolved values ride the blob" {
    // Goal: `xmppd -c conf --host X --db Y` still overrides in the
    // children (ADR-9), now through the sealed blob instead of argv.
    // Their argv keeps only what the schema marks CLI-only: the
    // listen-fd slots and the conf-fd slot.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "conf.ini", "[server]\nhostname = file-host.test\ndb_path = /file/db\n", &path_buf);

    var diag: conf.Diag = .{};
    var l = try MasterLoader.load(std.testing.allocator, .{
        .path = path,
        .args = &.{ "--host", "cli-host.test", "--db", "/cli/db", "--config", "conf.ini" },
    }, &diag);
    defer l.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const argv = try buildChildArgv(arena.allocator(), &l.values, .{
        .s2s_listen = true,
        .c2s_fd_str = "3,4",
        .s2s_fd_str = "3",
        .core_conf_fd = "5",
        .s2s_conf_fd = "4",
    });

    // auth keeps resolved values on argv until part 2b.
    try std.testing.expectEqualStrings("/cli/db", argvValue(argv.auth, "--db").?);
    try std.testing.expectEqualStrings("conf.ini", argvValue(argv.auth, "--config").?);
    try std.testing.expectEqualStrings("/var/run/xmppd/auth.sock", argvValue(argv.auth, "--socket").?);

    // core and s2s argv is exactly the CLI-only pair.
    try std.testing.expectEqualDeep(&[_][]const u8{ "--listen-fd", "3,4", "--conf-fd", "5" }, argv.core);
    try std.testing.expectEqualDeep(&[_][]const u8{ "--listen-fd", "3", "--conf-fd", "4" }, argv.s2s);

    // The resolved values the argv used to carry are in the blob:
    // the CLI hostname and db override the file's for every consumer.
    const blob = try l.forwardBlob(arena.allocator(), &diag);
    try expectBlobLine(blob, "server.hostname", "cli-host.test");
    try expectBlobLine(blob, "server.db_path", "/cli/db");
    // An unset MUC host forwards empty; the child resolves
    // conference.<hostname> itself.
    try expectBlobLine(blob, "muc.host", "");
}

test "master child argv: file values reach the blob; s2s without a listener gets no fd args" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "conf.ini", "[server]\nhostname = file-host.test\ndb_path = /file/db\n" ++
        "[s2s]\nport = 5270\nsocket = /run/s2s.sock\n" ++
        "[muc]\nhost = muc.file.test\n", &path_buf);

    var diag: conf.Diag = .{};
    var l = try MasterLoader.load(std.testing.allocator, .{
        .path = path,
        .args = &.{ "--config", "conf.ini" },
    }, &diag);
    defer l.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const argv = try buildChildArgv(arena.allocator(), &l.values, .{
        .s2s_listen = false,
        .c2s_fd_str = "3",
        .s2s_fd_str = "3",
        .core_conf_fd = "4",
        .s2s_conf_fd = "4",
    });

    try std.testing.expectEqualStrings("/file/db", argvValue(argv.auth, "--db").?);
    // No listener bound: the s2s child is never spawned and its argv
    // carries no fd slots at all.
    try std.testing.expectEqual(@as(usize, 0), argv.s2s.len);
    try std.testing.expectEqualDeep(&[_][]const u8{ "--listen-fd", "3", "--conf-fd", "4" }, argv.core);

    const blob = try l.forwardBlob(arena.allocator(), &diag);
    try expectBlobLine(blob, "server.hostname", "file-host.test");
    try expectBlobLine(blob, "s2s.port", "5270");
    try expectBlobLine(blob, "s2s.socket", "/run/s2s.sock");
    try expectBlobLine(blob, "muc.host", "muc.file.test");
}

test "master child argv: --no-s2s forwards s2s.enabled=false in the blob" {
    var diag: conf.Diag = .{};
    var l = try MasterLoader.load(std.testing.allocator, .{
        .args = &.{"--no-s2s"},
    }, &diag);
    defer l.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const blob = try l.forwardBlob(arena.allocator(), &diag);
    try expectBlobLine(blob, "s2s.enabled", "false");
    try expectBlobLine(blob, "server.hostname", "localhost");
}

test "master conf reloader: a rebuild changes what the next spawned child reads" {
    // Goal: after SIGHUP the pass_fds tail slots point at a new sealed
    // blob and a child loading through its own loader sees the reloaded
    // value with .forwarded provenance (ADR-9).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "conf.ini", "[server]\nhostname = first.test\n", &path_buf);

    const argv = [_][]const u8{ "--config", path };
    var diag: conf.Diag = .{};
    var l = try MasterLoader.load(std.testing.allocator, .{
        .path = schema.configPathArg(&argv),
        .args = &argv,
    }, &diag);
    defer l.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const blob = try l.forwardBlob(arena.allocator(), &diag);
    var cfd = try conf.ConfFd.create(blob);
    defer cfd.deinit();
    const orig_fd = cfd.fd;

    // Two child pass_fds tails like the core and s2s arrays in main.
    var tail_core: posix.fd_t = cfd.fd;
    var tail_s2s: posix.fd_t = cfd.fd;
    const tails = [_]*posix.fd_t{ &tail_core, &tail_s2s };
    var rel = ConfReloader{
        .gpa = std.testing.allocator,
        .argv = &argv,
        .conf_fd = &cfd,
        .tails = &tails,
    };

    // Rewrite the file, then reload as the SIGHUP hook does.
    {
        const f = try tmp.dir.createFile("conf.ini", .{});
        defer f.close();
        try f.writeAll("[server]\nhostname = second.test\n");
    }
    rel.reload();
    try std.testing.expect(rel.last_ok);
    try std.testing.expect(cfd.fd != orig_fd);
    try std.testing.expectEqual(cfd.fd, tail_core);
    try std.testing.expectEqual(cfd.fd, tail_s2s);

    // A newly spawned child: dup the tail slot like the fd remap does,
    // load through the child loader, and the reloaded value wins over
    // the schema default with .forwarded provenance.
    var diag2: conf.Diag = .{};
    var child = try schema.CoreLoader.load(std.testing.allocator, .{
        .conf_fd = try posix.dup(tail_core),
    }, &diag2);
    defer child.deinit();
    try std.testing.expectEqualStrings("second.test", child.values.server.hostname);
    try std.testing.expectEqual(.forwarded, child.provenanceOf("server", "hostname"));
}

test "master conf reloader: a failed reload keeps the previous blob" {
    // Goal: an unloadable file after SIGHUP must not wedge the children:
    // the old sealed blob stays and the tail slots keep pointing at it.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "conf.ini", "[server]\nhostname = first.test\n", &path_buf);

    const argv = [_][]const u8{ "--config", path };
    var diag: conf.Diag = .{};
    var l = try MasterLoader.load(std.testing.allocator, .{
        .path = schema.configPathArg(&argv),
        .args = &argv,
    }, &diag);
    defer l.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const blob = try l.forwardBlob(arena.allocator(), &diag);
    var cfd = try conf.ConfFd.create(blob);
    defer cfd.deinit();
    const orig_fd = cfd.fd;

    var tail_core: posix.fd_t = cfd.fd;
    const tails = [_]*posix.fd_t{&tail_core};
    var rel = ConfReloader{
        .gpa = std.testing.allocator,
        .argv = &argv,
        .conf_fd = &cfd,
        .tails = &tails,
    };

    // Break the file, reload, then confirm the blob is unchanged.
    {
        const f = try tmp.dir.createFile("conf.ini", .{});
        defer f.close();
        try f.writeAll("[server]\nbogus_key = 1\n");
    }
    rel.reload();
    try std.testing.expect(!rel.last_ok);
    try std.testing.expectEqual(orig_fd, cfd.fd);
    try std.testing.expectEqual(orig_fd, tail_core);

    var diag2: conf.Diag = .{};
    var child = try schema.CoreLoader.load(std.testing.allocator, .{
        .conf_fd = try posix.dup(tail_core),
    }, &diag2);
    defer child.deinit();
    try std.testing.expectEqualStrings("first.test", child.values.server.hostname);
}
