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
const config_mod = @import("config");
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
const room_registry_mod = @import("room_registry");
const RoomRegistry = room_registry_mod.RoomRegistry;
const shared_registry_mod = @import("shared_registry");
const SharedSessionRegistry = shared_registry_mod.SharedSessionRegistry;
const delivery_queue_mod = @import("delivery_queue");
const DeliverySystem = delivery_queue_mod.DeliverySystem;

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
    var muc_host_arg: ?[]const u8 = null;
    var config_path: ?[]const u8 = null;
    var listen_fd_str: ?[]const u8 = null;
    var max_sessions: usize = @import("server.zig").DEFAULT_MAX_SESSIONS;
    var fan_out_batch_size: u8 = @import("fanout.zig").DEFAULT_BATCH_SIZE;

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
        } else if (std.mem.eql(u8, arg, "--listen-fd")) {
            listen_fd_str = args.next() orelse {
                log.err("--listen-fd requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--db")) {
            db_path = args.next() orelse {
                log.err("--db requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--muc-host")) {
            muc_host_arg = args.next() orelse {
                log.err("--muc-host requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            config_path = args.next() orelse {
                log.err("--config requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            log.warn("unknown argument: {s}", .{arg});
        }
    }

    // Apply config file defaults (CLI flags above take precedence)
    var cfg: ?config_mod.Config = null;
    if (config_path) |cp| {
        cfg = config_mod.parse(allocator, cp) catch |err| {
            log.err("failed to read config file '{s}': {}", .{ cp, err });
            return error.InvalidArgs;
        };
        const c = &cfg.?;

        // [server] section
        if (host.len == 0 or std.mem.eql(u8, host, "localhost")) {
            if (c.get("server", "hostname")) |v| host = v;
        }
        if (std.mem.eql(u8, address, "127.0.0.1")) {
            if (c.get("server", "bind_address")) |v| address = v;
        }
        if (port == 15222) {
            if (c.get("server", "c2s_port")) |v| {
                port = std.fmt.parseInt(u16, v, 10) catch 15222;
            }
        }
        if (db_path == null) {
            if (c.get("server", "db_path")) |v| db_path = v;
        }

        // [tls] section — cert/key are sentinel-terminated (C API requirement),
        // config values are not null-terminated. TLS is typically set via CLI or
        // passed by the master supervisor. Skip config for TLS paths.

        // [auth] section
        if (auth_socket == null) {
            if (c.get("auth", "socket")) |v| auth_socket = v;
        }

        // [s2s] section
        if (s2s_socket == null) {
            if (c.get("s2s", "socket")) |v| s2s_socket = v;
        }

        // [muc] section
        if (muc_host_arg == null) {
            if (c.get("muc", "host")) |v| muc_host_arg = v;
        }

        // [core] section
        if (c.get("core", "max_sessions")) |v| {
            max_sessions = std.fmt.parseInt(usize, v, 10) catch @import("server.zig").DEFAULT_MAX_SESSIONS;
        }
        if (c.get("core", "fan_out_batch_size")) |v| {
            fan_out_batch_size = std.fmt.parseInt(u8, v, 10) catch @import("fanout.zig").DEFAULT_BATCH_SIZE;
        }
    }
    defer if (cfg) |*c| c.deinit();

    // Parse listen fd list (comma-separated)
    const MAX_LISTEN_FDS = 64;
    var listen_fds: [MAX_LISTEN_FDS]std.posix.fd_t = undefined;
    var listen_fd_count: usize = 0;

    if (listen_fd_str) |fd_str| {
        var iter = std.mem.splitScalar(u8, fd_str, ',');
        while (iter.next()) |part| {
            if (listen_fd_count >= MAX_LISTEN_FDS) break;
            listen_fds[listen_fd_count] = std.fmt.parseInt(std.posix.fd_t, part, 10) catch {
                log.err("invalid fd number in list: {s}", .{part});
                return error.InvalidArgs;
            };
            listen_fd_count += 1;
        }
    }

    // Per-worker session quota
    const worker_count: usize = if (listen_fd_count > 0) listen_fd_count else 1;
    const per_worker_sessions = max_sessions / worker_count;

    log.info("starting xmppd-core host={s} address={s} port={d} workers={d} sessions_per_worker={d}", .{
        host, address, port, worker_count, per_worker_sessions,
    });

    // Open storage backends (shared across workers — backends are thread-safe)
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
        offline_store = GenericOfflineStore(OpBackendType).init(&op_backend.?, allocator);
        vcard_store = GenericVCardStore.init(&op_backend.?);
    }
    defer if (op_backend) |*b| b.close();

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
    }
    defer if (archive_backend) |*b| b.close();

    // MUC host resolution
    var muc_host_buf: [256]u8 = undefined;
    var room_registry: ?RoomRegistry = null;
    const effective_muc_host: ?[]const u8 = if (muc_host_arg) |h| h else blk: {
        const muc_default = std.fmt.bufPrint(&muc_host_buf, "conference.{s}", .{host}) catch null;
        break :blk muc_default;
    };
    if (effective_muc_host) |_| {
        room_registry = RoomRegistry.init(allocator);
    }
    defer if (room_registry) |*reg| reg.deinit();

    // Shared session registry — allocated only when workers > 1
    var shared_reg: ?SharedSessionRegistry = null;
    if (worker_count > 1) {
        shared_reg = SharedSessionRegistry.init(allocator, @intCast(max_sessions)) catch |err| {
            log.err("failed to allocate shared session registry: {}", .{err});
            return error.RegistryInitFailed;
        };
        log.info("shared session registry allocated: {d} slots", .{max_sessions});
    }
    defer if (shared_reg) |*sr| sr.deinit();

    // Delivery system (MPSC queues + wake pipes) — allocated only when workers > 1
    var delivery_sys: ?DeliverySystem = null;
    if (worker_count > 1) {
        delivery_sys = DeliverySystem.init(allocator, @intCast(worker_count)) catch |err| {
            log.err("failed to allocate delivery system: {}", .{err});
            return error.DeliverySystemInitFailed;
        };
        log.info("delivery system allocated: {d} worker queues", .{worker_count});
    }
    defer if (delivery_sys) |*ds| ds.deinit();

    // Worker context shared across threads
    var ctx = WorkerCtx{
        .host = host,
        .cert_path = cert_path,
        .key_path = key_path,
        .auth_socket = auth_socket,
        .s2s_socket = s2s_socket,
        .per_worker_sessions = per_worker_sessions,
        .fan_out_batch_size = fan_out_batch_size,
        .roster = if (roster_store != null) &roster_store.? else null,
        .offline = if (offline_store != null) &offline_store.? else null,
        .archive = if (archive_store != null) &archive_store.? else null,
        .vcard = if (vcard_store != null) &vcard_store.? else null,
        .room_registry = if (room_registry != null) &room_registry.? else null,
        .muc_host = effective_muc_host,
        .shared_registry = if (shared_reg) |*sr| sr else null,
        .delivery_system = if (delivery_sys) |*ds| ds else null,
        .allocator = allocator,
    };

    // Single-fd (legacy / dev mode): run directly on main thread
    if (listen_fd_count <= 1) {
        var server = if (listen_fd_count == 1)
            try Server.initFromFd(host, listen_fds[0], allocator, per_worker_sessions)
        else
            try Server.initWithMaxSessions(host, address, port, allocator, per_worker_sessions);
        server.fanout_queue.batch_size = fan_out_batch_size;
        defer server.deinit();

        configureServer(&server, &ctx, 0);

        log.info("listening on {s}:{d} (single worker)", .{ address, port });
        try server.run();
        log.info("shutdown complete", .{});
        return;
    }

    // Multi-fd: spawn N-1 threads, main thread takes the last fd
    var threads: [MAX_LISTEN_FDS]std.Thread = undefined;
    var worker_args: [MAX_LISTEN_FDS]WorkerArgs = undefined;

    var spawned: usize = 0;
    var i: usize = 0;
    while (i < listen_fd_count - 1) : (i += 1) {
        worker_args[i] = .{ .fd = listen_fds[i], .worker_id = i, .ctx = &ctx };
        threads[i] = std.Thread.spawn(.{}, workerThread, .{&worker_args[i]}) catch |err| {
            log.err("failed to spawn worker thread {d}: {}", .{ i, err });
            break;
        };
        spawned += 1;
    }

    // Main thread runs the last worker
    log.info("main thread running worker {d}", .{listen_fd_count - 1});
    {
        var server = try Server.initFromFd(host, listen_fds[listen_fd_count - 1], allocator, per_worker_sessions);
        server.fanout_queue.batch_size = fan_out_batch_size;
        defer server.deinit();
        configureServer(&server, &ctx, @intCast(listen_fd_count - 1));
        server.run() catch |err| {
            log.err("main worker error: {}", .{err});
        };
    }

    // Join all spawned threads
    i = 0;
    while (i < spawned) : (i += 1) {
        threads[i].join();
    }

    log.info("shutdown complete ({d} workers)", .{worker_count});
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
        \\  --listen-fd N[,N...]  Pre-bound listener fd(s) from master (comma-separated for multi-worker)
        \\  --db PATH        User database path (roster stored alongside)
        \\  --muc-host HOST  MUC service hostname (default: conference.{host})
        \\  --help, -h       Show this help
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}

/// Worker context struct (defined at file scope for thread function signature).
const WorkerCtx = struct {
    host: []const u8,
    cert_path: ?[:0]const u8,
    key_path: ?[:0]const u8,
    auth_socket: ?[]const u8,
    s2s_socket: ?[]const u8,
    per_worker_sessions: usize,
    fan_out_batch_size: u8,
    roster: ?*GenericRosterStore,
    offline: ?*GenericOfflineStore(OpBackendType),
    archive: ?*archive_store_mod.ArchiveStore(ArchiveBackendType),
    vcard: ?*GenericVCardStore,
    room_registry: ?*RoomRegistry,
    muc_host: ?[]const u8,
    shared_registry: ?*SharedSessionRegistry,
    delivery_system: ?*DeliverySystem,
    allocator: std.mem.Allocator,
};

/// Worker thread arguments.
const WorkerArgs = struct {
    fd: std.posix.fd_t,
    worker_id: usize,
    ctx: *WorkerCtx,
};

/// Configure a Server instance with TLS, auth, S2S, roster, offline, archive, vcard, MUC, and shared registry.
fn configureServer(server: *Server, ctx: *WorkerCtx, worker_id: u16) void {
    server.worker_id = worker_id;
    server.session_id_base = @as(u32, worker_id) * @as(u32, @intCast(ctx.per_worker_sessions));
    if (ctx.shared_registry) |sr| {
        server.shared_registry = sr;
    }
    if (ctx.delivery_system) |ds| {
        server.delivery_system = ds;
    }
    if (ctx.cert_path) |cert| {
        const key = ctx.key_path orelse {
            log.err("--cert requires --key", .{});
            return;
        };
        server.configureTls(cert, key) catch {
            log.err("TLS configuration failed", .{});
            return;
        };
    }

    if (ctx.auth_socket) |socket_path| {
        server.configureAuth(socket_path) catch {
            log.warn("auth daemon not available, SASL auth will fail", .{});
        };
    }

    if (ctx.s2s_socket) |socket_path| {
        server.configureS2s(socket_path) catch {
            log.warn("S2S daemon not available, remote delivery will bounce", .{});
        };
    }

    if (ctx.roster) |r| server.configureRoster(r);
    if (ctx.vcard) |v| server.configureVcard(v);
    if (ctx.offline != null and ctx.archive != null) {
        server.configureOffline(ctx.offline.?, ctx.archive.?);
    }

    if (ctx.room_registry) |reg| {
        server.room_registry = reg;
        server.muc_host = ctx.muc_host;
    }
}

/// Thread entry point for worker threads. Each thread owns its own Server
/// with its own kqueue and listener fd.
fn workerThread(args: *WorkerArgs) void {
    log.info("worker {d} starting (fd={d})", .{ args.worker_id, args.fd });

    var server = Server.initFromFd(
        args.ctx.host,
        args.fd,
        args.ctx.allocator,
        args.ctx.per_worker_sessions,
    ) catch |err| {
        log.err("worker {d} init failed: {}", .{ args.worker_id, err });
        return;
    };
    server.fanout_queue.batch_size = args.ctx.fan_out_batch_size;
    defer server.deinit();

    configureServer(&server, args.ctx, @intCast(args.worker_id));

    server.run() catch |err| {
        log.err("worker {d} error: {}", .{ args.worker_id, err });
    };

    log.info("worker {d} stopped", .{args.worker_id});
}
