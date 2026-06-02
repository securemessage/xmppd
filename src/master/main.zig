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
//!   └── xmppd-core (worker, handles connections)
//! ```
//!
//! In Phase 5, the master passes the hostname, port, and cert/key paths
//! to xmppd-core via command-line arguments. In the future, socket fds
//! will be passed via SCM_RIGHTS for proper privilege separation.

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
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            log.warn("unknown argument: {s}", .{arg});
        }
    }

    log.info("xmppd master starting, host={s} port={s}", .{ host, port });

    // Initialize supervisor
    var sup = Supervisor.init(core_path, &.{});

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

    // Spawn the first child
    const child_pid = try sup.spawnChild();

    // Register child process monitoring + signals
    var changes: [3]posix.Kevent = .{
        makeKevent(@intCast(child_pid), std.c.EVFILT.PROC, std.c.EV.ADD | std.c.EV.ONESHOT, 0),
        makeKevent(@intCast(posix.SIG.TERM), std.c.EVFILT.SIGNAL, std.c.EV.ADD | std.c.EV.ENABLE, 0),
        makeKevent(@intCast(posix.SIG.INT), std.c.EVFILT.SIGNAL, std.c.EV.ADD | std.c.EV.ENABLE, 0),
    };
    changes[0].fflags = std.c.NOTE.EXIT;

    _ = posix.kevent(kq, &changes, &event_buf, null) catch |err| {
        log.err("kevent setup failed: {}", .{err});
        return err;
    };

    // Supervisor event loop
    var running = true;
    while (running) {
        const count = posix.kevent(kq, &.{}, &event_buf, null) catch |err| {
            log.err("kevent wait failed: {}", .{err});
            break;
        };

        for (event_buf[0..count]) |ev| {
            if (ev.filter == std.c.EVFILT.PROC) {
                // Child exited
                const status = ev.fflags;
                _ = sup.waitChild() catch {};

                const should_restart = sup.handleChildExit(status);
                if (should_restart) {
                    log.info("restarting child in {d}ms", .{sup.backoffMs()});
                    // Register a restart timer
                    var timer_change = [_]posix.Kevent{
                        makeKevent(RESTART_TIMER_IDENT, std.c.EVFILT.TIMER, std.c.EV.ADD | std.c.EV.ONESHOT, 0),
                    };
                    timer_change[0].data = @intCast(sup.backoffMs());
                    _ = posix.kevent(kq, &timer_change, &.{}, null) catch {};
                } else {
                    running = false;
                }
            } else if (ev.filter == std.c.EVFILT.TIMER and ev.ident == RESTART_TIMER_IDENT) {
                // Restart timer fired
                const new_pid = sup.spawnChild() catch |err| {
                    log.err("failed to respawn child: {}", .{err});
                    running = false;
                    continue;
                };

                // Re-register EVFILT_PROC for new child
                var proc_change = [_]posix.Kevent{
                    makeKevent(@intCast(new_pid), std.c.EVFILT.PROC, std.c.EV.ADD | std.c.EV.ONESHOT, 0),
                };
                proc_change[0].fflags = std.c.NOTE.EXIT;
                _ = posix.kevent(kq, &proc_change, &.{}, null) catch {};
            } else if (ev.filter == std.c.EVFILT.SIGNAL) {
                const signo: u8 = @intCast(ev.ident);
                if (signo == posix.SIG.TERM or signo == posix.SIG.INT) {
                    log.info("received signal {d}, shutting down", .{signo});
                    sup.shutdown();
                    _ = sup.waitChild() catch {};
                    running = false;
                } else if (signo == posix.SIG.HUP) {
                    log.info("received SIGHUP, forwarding to child", .{});
                    sup.forwardSignal(signo);
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
        \\  --help, -h         Show this help
        \\
    ;
    _ = posix.write(posix.STDOUT_FILENO, usage) catch {};
}
