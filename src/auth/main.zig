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
const event_loop_mod = @import("event_loop");
const EventLoop = event_loop_mod.EventLoop;
const ChangeList = event_loop_mod.ChangeList;
const Event = event_loop_mod.Event;

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

    // Initialize event loop
    var loop = try EventLoop.init(allocator, 32);
    defer loop.deinit();

    // Register listener + signals (signal masking is automatic)
    try loop.addFd(ipc.listen_fd, .read, LISTENER_UDATA);
    try loop.addSignal(posix.SIG.TERM);
    try loop.addSignal(posix.SIG.INT);
    try loop.addSignal(posix.SIG.HUP);

    // Scratch buffer for batching changes
    var scratch: [16]posix.Kevent = undefined;

    // Main event loop
    var running = true;
    while (running) {
        const events = loop.poll(null) catch |err| {
            log.err("event loop poll failed: {}", .{err});
            break;
        };

        var batch = ChangeList.init(&scratch);

        for (events) |ev| {
            switch (ev) {
                .signal => |s| {
                    if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                        log.info("received signal {d}, shutting down", .{s.signo});
                        running = false;
                    } else if (s.signo == posix.SIG.HUP) {
                        log.info("received SIGHUP, reloading user store", .{});
                        store.load() catch |err| {
                            log.err("failed to reload user store: {}", .{err});
                        };
                    }
                },
                .fd_readable => |e| {
                    if (e.udata == LISTENER_UDATA) {
                        // New IPC client connection
                        if (ipc.accept() catch null) |slot| {
                            const conn = ipc.getClient(slot) orelse continue;
                            batch.addRead(conn.fd, CLIENT_UDATA_BASE + slot) catch break;
                        }
                    } else if (e.udata >= CLIENT_UDATA_BASE) {
                        const slot = e.udata - CLIENT_UDATA_BASE;
                        handleIpcClient(&ipc, &handler, &batch, slot);
                    }
                },
                .fd_writable => |e| {
                    if (e.udata >= CLIENT_UDATA_BASE) {
                        const slot = e.udata - CLIENT_UDATA_BASE;
                        flushIpcClient(&ipc, &batch, slot);
                    }
                },
                else => {},
            }
        }

        // Submit accumulated changes
        if (batch.count() > 0) {
            _ = loop.submitAndPoll(batch.slice(), 0) catch {};
        }
    }

    log.info("xmppd-auth shutdown complete", .{});
}

fn handleIpcClient(ipc: *IpcServer, handler: *AuthHandler, batch: *ChangeList, slot: usize) void {
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

            // One-shot write notification for pending data
            if (conn.hasPendingSend()) {
                batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {};
            }
        }
    }
}

fn flushIpcClient(ipc: *IpcServer, batch: *ChangeList, slot: usize) void {
    const conn = ipc.getClient(slot) orelse return;

    _ = conn.flush() catch {
        ipc.closeClient(slot);
        return;
    };

    // Re-arm write if more data pending
    if (conn.hasPendingSend()) {
        batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {};
    }
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
