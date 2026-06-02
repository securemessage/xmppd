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
        \\  --help, -h       Show this help
        \\
    ;
    _ = std.posix.write(std.posix.STDOUT_FILENO, usage) catch {};
}
