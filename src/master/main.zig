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
    log.info("auth daemon started, waiting for socket", .{});

    // Brief delay for auth daemon to bind its socket
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Spawn xmppd-core
    const core_pid = try core_sup.spawnChild();
    try loop.addProcess(core_pid);

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

    log.info("xmppd master shutdown complete", .{});
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
