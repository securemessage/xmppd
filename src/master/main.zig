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
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            log.warn("unknown argument: {s}", .{arg});
        }
    }

    log.info("xmppd master starting, host={s} port={s}", .{ host, port });

    // Initialize supervisors for both children
    var auth_sup = Supervisor.init(auth_path, &.{});
    var core_sup = Supervisor.init(core_path, &.{});

    // Block SIGTERM and SIGINT for delivery via kqueue
    var mask = posix.sigemptyset();
    posix.sigaddset(&mask, posix.SIG.TERM);
    posix.sigaddset(&mask, posix.SIG.INT);
    posix.sigaddset(&mask, posix.SIG.HUP);
    posix.sigprocmask(posix.SIG.BLOCK, &mask, null);

    // Create kqueue for supervision
    const kq = try posix.kqueue();
    defer posix.close(kq);

    var event_buf: [8]posix.Kevent = undefined;

    log.info("config: auth_socket={s} db={s} cert={s} key={s}", .{
        auth_socket,
        db_path,
        cert_path orelse "(none)",
        key_path orelse "(none)",
    });

    // Spawn xmppd-auth first (must be ready before core connects)
    const auth_pid = try auth_sup.spawnChild();
    log.info("auth daemon started, waiting for socket", .{});

    // Brief delay for auth daemon to bind its socket
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Spawn xmppd-core
    const core_pid = try core_sup.spawnChild();

    // Register both children + signals
    const AUTH_UDATA: usize = 1;
    const CORE_UDATA: usize = 2;

    var changes: [4]posix.Kevent = .{
        makeKevent(@intCast(auth_pid), std.c.EVFILT.PROC, std.c.EV.ADD | std.c.EV.ONESHOT, AUTH_UDATA),
        makeKevent(@intCast(core_pid), std.c.EVFILT.PROC, std.c.EV.ADD | std.c.EV.ONESHOT, CORE_UDATA),
        makeKevent(@intCast(posix.SIG.TERM), std.c.EVFILT.SIGNAL, std.c.EV.ADD | std.c.EV.ENABLE, 0),
        makeKevent(@intCast(posix.SIG.INT), std.c.EVFILT.SIGNAL, std.c.EV.ADD | std.c.EV.ENABLE, 0),
    };
    changes[0].fflags = std.c.NOTE.EXIT;
    changes[1].fflags = std.c.NOTE.EXIT;

    _ = posix.kevent(kq, &changes, &event_buf, null) catch |err| {
        log.err("kevent setup failed: {}", .{err});
        return err;
    };

    // Supervisor event loop
    const AUTH_RESTART_TIMER: usize = 0xBACCA;
    const CORE_RESTART_TIMER: usize = 0xBACCF;

    var running = true;
    while (running) {
        const count = posix.kevent(kq, &.{}, &event_buf, null) catch |err| {
            log.err("kevent wait failed: {}", .{err});
            break;
        };

        for (event_buf[0..count]) |ev| {
            if (ev.filter == std.c.EVFILT.PROC) {
                const status = ev.fflags;

                if (ev.udata == AUTH_UDATA) {
                    _ = auth_sup.waitChild() catch {};
                    const should_restart = auth_sup.handleChildExit(status);
                    if (should_restart) {
                        log.info("restarting auth daemon in {d}ms", .{auth_sup.backoffMs()});
                        var timer_change = [_]posix.Kevent{
                            makeKevent(AUTH_RESTART_TIMER, std.c.EVFILT.TIMER, std.c.EV.ADD | std.c.EV.ONESHOT, AUTH_UDATA),
                        };
                        timer_change[0].data = @intCast(auth_sup.backoffMs());
                        _ = posix.kevent(kq, &timer_change, &.{}, null) catch {};
                    } else {
                        running = false;
                    }
                } else if (ev.udata == CORE_UDATA) {
                    _ = core_sup.waitChild() catch {};
                    const should_restart = core_sup.handleChildExit(status);
                    if (should_restart) {
                        log.info("restarting core in {d}ms", .{core_sup.backoffMs()});
                        var timer_change = [_]posix.Kevent{
                            makeKevent(CORE_RESTART_TIMER, std.c.EVFILT.TIMER, std.c.EV.ADD | std.c.EV.ONESHOT, CORE_UDATA),
                        };
                        timer_change[0].data = @intCast(core_sup.backoffMs());
                        _ = posix.kevent(kq, &timer_change, &.{}, null) catch {};
                    } else {
                        running = false;
                    }
                }
            } else if (ev.filter == std.c.EVFILT.TIMER) {
                if (ev.udata == AUTH_UDATA) {
                    const new_pid = auth_sup.spawnChild() catch |err| {
                        log.err("failed to respawn auth daemon: {}", .{err});
                        running = false;
                        continue;
                    };
                    var proc_change = [_]posix.Kevent{
                        makeKevent(@intCast(new_pid), std.c.EVFILT.PROC, std.c.EV.ADD | std.c.EV.ONESHOT, AUTH_UDATA),
                    };
                    proc_change[0].fflags = std.c.NOTE.EXIT;
                    _ = posix.kevent(kq, &proc_change, &.{}, null) catch {};
                } else if (ev.udata == CORE_UDATA) {
                    const new_pid = core_sup.spawnChild() catch |err| {
                        log.err("failed to respawn core: {}", .{err});
                        running = false;
                        continue;
                    };
                    var proc_change = [_]posix.Kevent{
                        makeKevent(@intCast(new_pid), std.c.EVFILT.PROC, std.c.EV.ADD | std.c.EV.ONESHOT, CORE_UDATA),
                    };
                    proc_change[0].fflags = std.c.NOTE.EXIT;
                    _ = posix.kevent(kq, &proc_change, &.{}, null) catch {};
                }
            } else if (ev.filter == std.c.EVFILT.SIGNAL) {
                const signo: u8 = @intCast(ev.ident);
                if (signo == posix.SIG.TERM or signo == posix.SIG.INT) {
                    log.info("received signal {d}, shutting down", .{signo});
                    core_sup.shutdown();
                    _ = core_sup.waitChild() catch {};
                    auth_sup.shutdown();
                    _ = auth_sup.waitChild() catch {};
                    running = false;
                } else if (signo == posix.SIG.HUP) {
                    log.info("received SIGHUP, forwarding to auth daemon", .{});
                    auth_sup.forwardSignal(signo);
                }
            }
        }
    }

    log.info("xmppd master shutdown complete", .{});
}

fn makeKevent(ident: usize, filter: i16, flags: u16, udata: usize) posix.Kevent {
    return .{
        .ident = ident,
        .filter = filter,
        .flags = flags,
        .fflags = 0,
        .data = 0,
        .udata = udata,
    };
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
        \\  --help, -h         Show this help
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}
