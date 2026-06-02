//! # xmppd-auth — Authentication daemon
//!
//! Separate process that handles SASL authentication exchanges over a Unix
//! domain socket IPC channel. Loads user credentials from a flat-file store
//! and processes SCRAM-SHA-256 and PLAIN authentication requests.
//!
//! ## Usage
//!
//! ```
//! xmppd-auth --db /var/db/xmppd/users.db --socket /var/run/xmppd/auth.sock
//! ```
//!
//! ## Signals
//!
//! - SIGHUP: reload user store from disk
//! - SIGTERM: graceful shutdown

const std = @import("std");
const posix = std.posix;
const IpcServer = @import("ipc_server").IpcServer;
const IpcConn = @import("ipc_server").IpcConn;
const AuthHandler = @import("handler").AuthHandler;
const UserStore = @import("user_store").UserStore;
const protocol = @import("ipc_protocol");

const log = std.log.scoped(.xmppd_auth);

/// Sentinel value for the listener fd in kqueue udata.
const LISTENER_UDATA: usize = std.math.maxInt(usize);

/// Base udata for IPC client connections.
const CLIENT_UDATA_BASE: usize = 0x10000;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var db_path: []const u8 = "/var/db/xmppd/users.db";
    var socket_path: []const u8 = "/var/run/xmppd/auth.sock";

    _ = args.next(); // Skip argv[0]

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--db")) {
            db_path = args.next() orelse {
                log.err("--db requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--socket")) {
            socket_path = args.next() orelse {
                log.err("--socket requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            log.warn("unknown argument: {s}", .{arg});
        }
    }

    log.info("xmppd-auth starting, db={s} socket={s}", .{ db_path, socket_path });

    // Load user store
    var store = UserStore.init(allocator, db_path);
    defer store.deinit();
    try store.load();

    // Initialize auth handler
    var handler = AuthHandler.init(allocator, &store);
    defer handler.deinit();

    // Start IPC server
    var ipc = IpcServer{};
    defer ipc.deinit();
    try ipc.listen(socket_path);

    // Block signals for kqueue delivery
    var mask = posix.sigemptyset();
    posix.sigaddset(&mask, posix.SIG.TERM);
    posix.sigaddset(&mask, posix.SIG.INT);
    posix.sigaddset(&mask, posix.SIG.HUP);
    posix.sigprocmask(posix.SIG.BLOCK, &mask, null);

    // Create kqueue
    const kq = try posix.kqueue();
    defer posix.close(kq);

    var event_buf: [32]posix.Kevent = undefined;

    // Register listener + signals
    var initial_changes = [_]posix.Kevent{
        makeKevent(@intCast(ipc.listen_fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, LISTENER_UDATA),
        makeKevent(@intCast(posix.SIG.TERM), std.c.EVFILT.SIGNAL, std.c.EV.ADD | std.c.EV.ENABLE, 0),
        makeKevent(@intCast(posix.SIG.INT), std.c.EVFILT.SIGNAL, std.c.EV.ADD | std.c.EV.ENABLE, 0),
        makeKevent(@intCast(posix.SIG.HUP), std.c.EVFILT.SIGNAL, std.c.EV.ADD | std.c.EV.ENABLE, 0),
    };

    _ = try posix.kevent(kq, &initial_changes, &event_buf, null);

    // Main event loop
    var running = true;
    while (running) {
        const count = posix.kevent(kq, &.{}, &event_buf, null) catch |err| {
            log.err("kevent failed: {}", .{err});
            break;
        };

        for (event_buf[0..count]) |ev| {
            if (ev.filter == std.c.EVFILT.SIGNAL) {
                const signo: u8 = @intCast(ev.ident);
                if (signo == posix.SIG.TERM or signo == posix.SIG.INT) {
                    log.info("received signal {d}, shutting down", .{signo});
                    running = false;
                } else if (signo == posix.SIG.HUP) {
                    log.info("received SIGHUP, reloading user store", .{});
                    store.load() catch |err| {
                        log.err("failed to reload user store: {}", .{err});
                    };
                }
            } else if (ev.filter == std.c.EVFILT.READ) {
                if (ev.udata == LISTENER_UDATA) {
                    // New IPC client connection
                    if (ipc.accept() catch null) |slot| {
                        const conn = ipc.getClient(slot) orelse continue;
                        var add_ev = [_]posix.Kevent{
                            makeKevent(@intCast(conn.fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, CLIENT_UDATA_BASE + slot),
                        };
                        _ = posix.kevent(kq, &add_ev, &.{}, null) catch {};
                    }
                } else if (ev.udata >= CLIENT_UDATA_BASE) {
                    const slot = ev.udata - CLIENT_UDATA_BASE;
                    handleIpcClient(&ipc, &handler, slot, kq);
                }
            } else if (ev.filter == std.c.EVFILT.WRITE) {
                if (ev.udata >= CLIENT_UDATA_BASE) {
                    const slot = ev.udata - CLIENT_UDATA_BASE;
                    flushIpcClient(&ipc, slot, kq);
                }
            }
        }
    }

    log.info("xmppd-auth shutdown complete", .{});
}

fn handleIpcClient(ipc: *IpcServer, handler: *AuthHandler, slot: usize, kq: posix.fd_t) void {
    const conn = ipc.getClient(slot) orelse return;

    const n = conn.recv() catch {
        ipc.closeClient(slot);
        return;
    };

    if (n == 0) {
        ipc.closeClient(slot);
        return;
    }

    // Process all complete messages
    while (true) {
        const msg = conn.nextMessage() catch {
            ipc.closeClient(slot);
            return;
        };

        if (msg == null) break;

        if (handler.handleMessage(msg.?)) |response| {
            conn.queueSend(response) catch {
                ipc.closeClient(slot);
                return;
            };

            // Clean up SCRAM session after sending success/failure
            switch (response) {
                .auth_success => |s| handler.cleanupSession(s.conn_id),
                .auth_failure => |f| handler.cleanupSession(f.conn_id),
                else => {},
            }

            // Register for write if we have data to send
            if (conn.hasPendingSend()) {
                var add_ev = [_]posix.Kevent{
                    makeKevent(@intCast(conn.fd), std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT, CLIENT_UDATA_BASE + slot),
                };
                _ = posix.kevent(kq, &add_ev, &.{}, null) catch {};
            }
        }
    }
}

fn flushIpcClient(ipc: *IpcServer, slot: usize, kq: posix.fd_t) void {
    const conn = ipc.getClient(slot) orelse return;

    _ = conn.flush() catch {
        ipc.closeClient(slot);
        return;
    };

    // Re-arm write if more data pending
    if (conn.hasPendingSend()) {
        var add_ev = [_]posix.Kevent{
            makeKevent(@intCast(conn.fd), std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT, CLIENT_UDATA_BASE + slot),
        };
        _ = posix.kevent(kq, &add_ev, &.{}, null) catch {};
    }
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
        \\Usage: xmppd-auth [OPTIONS]
        \\
        \\Options:
        \\  --db PATH       Path to users.db (default: /var/db/xmppd/users.db)
        \\  --socket PATH   IPC socket path (default: /var/run/xmppd/auth.sock)
        \\  --help, -h      Show this help
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}
