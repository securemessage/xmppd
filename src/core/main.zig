//! # xmppd-core — XMPP connection handler daemon
//!
//! This is the worker process that handles XMPP client connections.
//! It can be run in two modes:
//!
//! - **Supervised**: spawned by the `xmppd` master, receives listening sockets
//!   via command-line fd numbers.
//! - **Standalone (dev mode)**: binds its own sockets on high ports. Useful
//!   for development and testing without root.
//!
//! ## Usage
//!
//! ```sh
//! # Dev mode — bind high port, no TLS
//! ./xmppd-core --host localhost --port 15222
//!
//! # Dev mode — with TLS
//! ./xmppd-core --host localhost --port 15222 --cert server.pem --key server.key
//!
//! # Supervised mode (called by xmppd master)
//! ./xmppd-core --host example.com --fd 3 --cert /etc/xmppd/server.pem --key /etc/xmppd/server.key
//! ```

const std = @import("std");
const Server = @import("server.zig").Server;
const generic_roster = @import("roster_store");
const GenericRosterStore = generic_roster.RosterStore(OpBackendType);
const generic_offline = @import("generic_offline_store");
const GenericOfflineStore = generic_offline.GenericOfflineStore;
const archive_store_mod = @import("archive_store");
const vcard_store_mod = @import("vcard_store");
const OpBackendMod = @import("op_backend");
const OpBackendType = OpBackendMod.Backend;
const ArchiveBackendMod = @import("archive_backend");
const ArchiveBackendType = ArchiveBackendMod.Backend;
const GenericVCardStore = vcard_store_mod.VCardStore(OpBackendType);

const log = std.log.scoped(.@"xmppd-core");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command-line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var host: []const u8 = "localhost";
    var address: []const u8 = "127.0.0.1";
    var port: u16 = 15222;
    var cert_path: ?[:0]const u8 = null;
    var key_path: ?[:0]const u8 = null;
    var auth_socket: ?[]const u8 = null;
    var s2s_socket: ?[]const u8 = null;
    var db_path: ?[]const u8 = null;

    // Skip argv[0]
    _ = args.next();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--host")) {
            host = args.next() orelse {
                log.err("--host requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--address") or std.mem.eql(u8, arg, "--bind")) {
            address = args.next() orelse {
                log.err("--address requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            const val = args.next() orelse {
                log.err("--port requires a value", .{});
                return error.InvalidArgs;
            };
            port = std.fmt.parseInt(u16, val, 10) catch {
                log.err("invalid port: {s}", .{val});
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
        } else if (std.mem.eql(u8, arg, "--auth-socket")) {
            auth_socket = args.next() orelse {
                log.err("--auth-socket requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--s2s-socket")) {
            s2s_socket = args.next() orelse {
                log.err("--s2s-socket requires a value", .{});
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

    log.info("starting xmppd-core host={s} address={s} port={d}", .{ host, address, port });

    var server = try Server.init(host, address, port, allocator);
    defer server.deinit();

    // Configure TLS if cert and key are provided
    if (cert_path) |cert| {
        const key = key_path orelse {
            log.err("--cert requires --key", .{});
            return error.InvalidArgs;
        };
        try server.configureTls(cert, key);
        log.info("TLS configured: cert={s} key={s}", .{ cert, key });
    }

    // Connect to auth daemon if socket path is provided
    if (auth_socket) |socket_path| {
        server.configureAuth(socket_path) catch {
            log.warn("auth daemon not available, SASL auth will fail", .{});
        };
    }

    // Connect to S2S daemon if socket path is provided
    if (s2s_socket) |socket_path| {
        server.configureS2s(socket_path) catch {
            log.warn("S2S daemon not available, remote delivery will bounce", .{});
        };
    }

    // Open operational stores at {db_path}/op
    var op_backend: ?OpBackendType = null;
    var roster_store: ?GenericRosterStore = null;
    var offline_store: ?GenericOfflineStore(OpBackendType) = null;
    var vcard_store: ?GenericVCardStore = null;
    if (db_path) |db| {
        var op_path_buf: [1024]u8 = undefined;
        const op_path = std.fmt.bufPrint(&op_path_buf, "{s}/op", .{db}) catch {
            log.err("db path too long", .{});
            return error.InvalidArgs;
        };
        op_backend = OpBackendType.open(op_path, .{}) catch |err| {
            log.err("failed to open operational DB at {s}: {}", .{ op_path, err });
            return error.StorageOpenFailed;
        };
        roster_store = GenericRosterStore.init(&op_backend.?);
        server.configureRoster(&roster_store.?);
        offline_store = GenericOfflineStore(OpBackendType).init(&op_backend.?, allocator);
        vcard_store = GenericVCardStore.init(&op_backend.?);
        server.configureVcard(&vcard_store.?);
    }
    defer if (op_backend) |*b| b.close();

    // Open archive store at {db_path}/archive (separate backend)
    var archive_backend: ?ArchiveBackendType = null;
    var archive_store: ?archive_store_mod.ArchiveStore(ArchiveBackendType) = null;
    if (db_path) |db| {
        var archive_path_buf: [1024]u8 = undefined;
        const archive_path = std.fmt.bufPrint(&archive_path_buf, "{s}/archive", .{db}) catch {
            log.err("db path too long", .{});
            return error.InvalidArgs;
        };
        archive_backend = ArchiveBackendType.open(archive_path, .{}) catch |err| {
            log.err("failed to open archive DB at {s}: {}", .{ archive_path, err });
            return error.StorageOpenFailed;
        };
        archive_store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&archive_backend.?, allocator);
        if (offline_store != null) {
            server.configureOffline(&offline_store.?, &archive_store.?);
        }
    }
    defer if (archive_backend) |*b| b.close();

    log.info("listening on {s}:{d}", .{ address, port });
    try server.run();
    log.info("shutdown complete", .{});
}

fn printUsage() void {
    const usage =
        \\Usage: xmppd-core [OPTIONS]
        \\
        \\Options:
        \\  --host HOST      XMPP server hostname (default: localhost)
        \\  --address ADDR   Bind address (default: 127.0.0.1)
        \\  --port PORT      TCP port (default: 15222)
        \\  --cert PATH      TLS certificate file (PEM)
        \\  --key PATH       TLS private key file (PEM)
        \\  --auth-socket PATH  Auth daemon IPC socket
        \\  --s2s-socket PATH   S2S federation daemon IPC socket
        \\  --db PATH        User database path (roster stored alongside)
        \\  --help, -h       Show this help
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}
