//! # xmppd-auth-oidc — OIDC authentication daemon
//!
//! Separate process that handles OAUTHBEARER and PLAIN (via ROPC) authentication
//! against an external Identity Provider. Reads [oidc] config from xmppd.conf.
//!
//! ## Usage
//!
//! ```
//! xmppd-auth-oidc --config /usr/local/etc/xmppd/xmppd.conf --socket /var/run/xmppd/auth.sock
//! ```
//!
//! ## Mechanisms Offered
//!
//! Sends [OAUTHBEARER, PLAIN] as its MechanismList on IPC connect.
//! SCRAM-SHA-256 is not supported (IdP doesn't expose stored_key/server_key).

const std = @import("std");
const posix = std.posix;
const IpcServer = @import("ipc_server").IpcServer;
const handler_mod = @import("handler");
const OidcStore = @import("oidc").OidcStore;
const OidcConfig = @import("oidc").OidcConfig;
const AuthHandler = handler_mod.AuthHandler(OidcStore);
const protocol = @import("ipc_protocol");
const event_loop_mod = @import("event_loop");
const EventLoop = event_loop_mod.EventLoop;
const ChangeList = event_loop_mod.ChangeList;
const config_mod = @import("config");
const RateLimiter = @import("rate_limiter").RateLimiter;
const RatePolicy = @import("rate_limiter").RatePolicy;

const log = std.log.scoped(.xmppd_auth_oidc);

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

    var socket_path: []const u8 = "/var/run/xmppd/auth.sock";
    var config_path: []const u8 = "/usr/local/etc/xmppd/xmppd.conf";

    _ = args.next(); // Skip argv[0]

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            config_path = args.next() orelse {
                log.err("--config requires a value", .{});
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

    // Parse config file
    var cfg = config_mod.parse(allocator, config_path) catch |err| {
        log.err("failed to read config file '{s}': {}", .{ config_path, err });
        return error.InvalidArgs;
    };
    defer cfg.deinit();

    // Read [oidc] section
    const issuer = cfg.get("oidc", "issuer") orelse {
        log.err("missing required config: [oidc] issuer", .{});
        return error.InvalidArgs;
    };
    const client_id = cfg.get("oidc", "client_id") orelse {
        log.err("missing required config: [oidc] client_id", .{});
        return error.InvalidArgs;
    };
    const client_secret = cfg.get("oidc", "client_secret") orelse {
        log.err("missing required config: [oidc] client_secret", .{});
        return error.InvalidArgs;
    };
    const token_endpoint = cfg.get("oidc", "token_endpoint") orelse {
        log.err("missing required config: [oidc] token_endpoint", .{});
        return error.InvalidArgs;
    };
    const jwks_uri = cfg.get("oidc", "jwks_uri") orelse {
        log.err("missing required config: [oidc] jwks_uri", .{});
        return error.InvalidArgs;
    };
    const ca_file = cfg.get("oidc", "ca_file");
    const introspection_endpoint = cfg.get("oidc", "introspection_endpoint");

    // Override socket path from config if present
    if (cfg.get("oidc", "socket")) |s| {
        socket_path = s;
    }

    log.info("xmppd-auth-oidc starting", .{});
    log.info("  issuer: {s}", .{issuer});
    log.info("  client_id: {s}", .{client_id});
    log.info("  token_endpoint: {s}", .{token_endpoint});
    log.info("  jwks_uri: {s}", .{jwks_uri});
    log.info("  socket: {s}", .{socket_path});

    // Initialize OIDC store
    var oidc_store = OidcStore.init(allocator, OidcConfig{
        .issuer = issuer,
        .client_id = client_id,
        .client_secret = client_secret,
        .token_endpoint = token_endpoint,
        .jwks_uri = jwks_uri,
        .introspection_endpoint = introspection_endpoint,
        .ca_file = ca_file,
    });
    defer oidc_store.deinit();

    // Initialize rate limiter
    var rate_policy = RatePolicy{};
    if (cfg.get("oidc", "rate_max_per_account")) |v| {
        rate_policy.max_per_account = std.fmt.parseInt(u32, v, 10) catch 5;
    }
    if (cfg.get("oidc", "rate_max_per_ip")) |v| {
        rate_policy.max_per_ip = std.fmt.parseInt(u32, v, 10) catch 20;
    }
    var rate_limiter = RateLimiter.init(rate_policy);

    // Initialize auth handler (generic over OidcStore)
    var handler = AuthHandler.init(allocator, &oidc_store);
    handler.setRateLimiter(&rate_limiter);
    defer handler.deinit();

    // Start IPC server
    var ipc = IpcServer{};
    defer ipc.deinit();
    try ipc.listen(socket_path);

    // Initialize event loop
    var loop = try EventLoop.init(allocator, 32);
    defer loop.deinit();

    // Register listener + signals
    try loop.addFd(ipc.listen_fd, .read, LISTENER_UDATA);
    try loop.addSignal(posix.SIG.TERM);
    try loop.addSignal(posix.SIG.INT);
    try loop.addSignal(posix.SIG.HUP);

    var scratch: [16]posix.Kevent = undefined;
    var batch = ChangeList.init(&scratch);

    // Main event loop
    var running = true;
    while (running) {
        const events = loop.submitAndPoll(batch.slice(), null) catch |err| {
            log.err("event loop poll failed: {}", .{err});
            break;
        };
        batch.reset();

        for (events) |ev| {
            switch (ev) {
                .signal => |s| {
                    if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                        log.info("received signal {d}, shutting down", .{s.signo});
                        running = false;
                    } else if (s.signo == posix.SIG.HUP) {
                        log.info("received SIGHUP (no-op for OIDC backend)", .{});
                    }
                },
                .fd_readable => |e| {
                    if (e.udata == LISTENER_UDATA) {
                        // New IPC client connection
                        if (ipc.accept() catch null) |slot| {
                            const conn = ipc.getClient(slot) orelse continue;
                            batch.addRead(conn.fd, CLIENT_UDATA_BASE + slot) catch break;

                            // Send MechanismList: OAUTHBEARER + PLAIN
                            const mechs = [_]protocol.MechanismId{ .oauthbearer, .plain };
                            const ml_msg = protocol.Message{ .mechanism_list = protocol.MechanismList.init(&mechs) };
                            conn.queueSend(ml_msg) catch {
                                ipc.closeClient(slot);
                                continue;
                            };
                            if (conn.hasPendingSend()) {
                                batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {};
                            }
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
    }

    log.info("xmppd-auth-oidc shutdown complete", .{});
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

            // Clean up session after sending success/failure
            switch (response) {
                .auth_success => |s| handler.cleanupSession(s.conn_id),
                .auth_failure => |f| handler.cleanupSession(f.conn_id),
                else => {},
            }

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

    if (conn.hasPendingSend()) {
        batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {};
    }
}

fn printUsage() void {
    const usage =
        \\Usage: xmppd-auth-oidc [OPTIONS]
        \\
        \\Options:
        \\  --config PATH     Config file path (default: /usr/local/etc/xmppd/xmppd.conf)
        \\  --socket PATH     IPC socket path (default: /var/run/xmppd/auth.sock)
        \\  --help, -h        Show this help
        \\
        \\Required config [oidc] section:
        \\  issuer            OIDC issuer URL
        \\  client_id         OAuth2 client ID
        \\  client_secret     OAuth2 client secret
        \\  token_endpoint    Token endpoint URL (for ROPC)
        \\  jwks_uri          JWKS endpoint URL
        \\
        \\Optional config [oidc] section:
        \\  ca_file           CA bundle path (default: system)
        \\  socket            Override IPC socket path
        \\  rate_max_per_account  Rate limit per account (default: 5)
        \\  rate_max_per_ip       Rate limit per IP (default: 20)
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}
