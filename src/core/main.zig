//! # xmppd-core: XMPP connection handler daemon
//!
//! This is the worker process that handles XMPP client connections.
//! It can be run in two modes:
//!
//! - **Supervised**: spawned by the `xmppd` master, receives listening
//!   sockets and the sealed config blob via inherited fd numbers.
//! - **Standalone (dev mode)**: binds its own sockets and reads its
//!   --config file directly. Useful for development and testing.
//!
//! ## Usage
//!
//! ```sh
//! # Dev mode: bind the schema defaults with no TLS
//! ./xmppd-core --host localhost --port 15222 --no-tls
//!
//! # Dev mode: with TLS and a config file
//! ./xmppd-core --config /etc/xmppd/xmppd.conf --cert server.pem --key server.key
//!
//! # Supervised mode (called by xmppd master)
//! ./xmppd-core --listen-fd 3 --conf-fd 4
//! ```

const std = @import("std");
const xmppd_log = @import("xmppd_log");
const root_allocator = @import("root_allocator");
pub const std_options = xmppd_log.std_options;

const Server = @import("worker/worker.zig").Server;
const conf = @import("conf");
const schema = @import("schema");
const generic_roster = @import("roster_store");
const GenericRosterStore = generic_roster.RosterStore(OpBackendType);
const generic_offline = @import("generic_offline_store");
const GenericOfflineStore = generic_offline.GenericOfflineStore;
const archive_store_mod = @import("archive_store");
const archive_queue_mod = @import("archive_queue");
const ArchiveWriteQueue = archive_queue_mod.ArchiveWriteQueue;
const vcard_store_mod = @import("vcard_store");
const OpBackendMod = @import("op_backend");
const OpBackendType = OpBackendMod.Backend;
const ArchiveBackendMod = @import("archive_backend");
const ArchiveBackendType = ArchiveBackendMod.Backend;
const GenericVCardStore = vcard_store_mod.VCardStore(OpBackendType);
const room_registry_mod = @import("room_registry");
const muc_actor = @import("muc/actor.zig");
const RoomRegistry = room_registry_mod.RoomRegistry;
const room_store_mod = @import("room_store");
const GenericRoomStore = room_store_mod.RoomStore(OpBackendType);
const RoomConfig = room_store_mod.RoomConfig;
const block_store_mod = @import("block_store");
const GenericBlockStore = block_store_mod.BlockStore(OpBackendType);
const pep_store_mod = @import("pep_store");
const GenericPepStore = pep_store_mod.PepStore(OpBackendType);
const session_map_mod = @import("session_map");
const SessionMap = session_map_mod.SessionMap;
const delivery_queue_mod = @import("delivery_queue");
const DeliverySystem = delivery_queue_mod.DeliverySystem;
const metrics = @import("worker/metrics.zig");

const log = std.log.scoped(.@"xmppd-core");

pub fn main() !void {
    // M1: block SIGUSR1 before any thread exists so every spawned thread
    // inherits the mask. A process-directed USR1 can then never take its
    // default terminate on an unblocked thread; each worker's
    // EVFILT_SIGNAL knote still records it and dumps its counters.
    metrics.blockUsr1();

    var root = root_allocator.Root.init();
    defer root.deinit();
    const allocator = root.allocator();

    // Configuration: lib/conf applies default < file < forwarded < CLI
    // with per-field provenance (ADR-9). --conf-fd and --config are
    // prescanned because the fd must be read and the file loaded before
    // the CLI applies. Unknown arguments, unknown file keys and bad
    // values are startup errors with the Diag.
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // argv[0]
    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(allocator);
    while (args.next()) |arg| try argv.append(allocator, arg);

    // The resolved loader and its diagnostics are heap-owned: the loader's
    // Sections plus provenance and the Diag's copy buffers each exceed the
    // 4 KB in-place rule, and main's frame persists for the worker loop's
    // whole life.
    const Cfg = struct {
        diag: conf.Diag,
        loader: schema.CoreLoader,
    };
    const cfg = try allocator.create(Cfg);
    cfg.diag = .{};
    loadCoreConfig(&cfg.loader, allocator, argv.items, &cfg.diag) catch |err| {
        log.err("{f}", .{&cfg.diag});
        allocator.destroy(cfg);
        return err;
    };
    defer {
        cfg.loader.deinit();
        allocator.destroy(cfg);
    }
    const v = &cfg.loader.values;

    if (v.meta.help) {
        try printUsage(allocator);
        return;
    }

    const host = v.server.hostname;
    const address = v.server.bind_address;
    const port = v.server.c2s_port;
    const db_path = v.server.db_path;
    const auth_socket = v.auth.socket;
    // The s2s socket connects only when federation is enabled.
    const s2s_socket: ?[]const u8 = if (v.s2s.enabled) v.s2s.socket else null;
    const max_sessions = v.core.max_sessions;
    const fan_out_batch_size = v.core.fan_out_batch_size;
    const max_resources_per_account = v.core.max_resources_per_account;
    const oidc_import_avatar = v.oidc.import_avatar;

    // cert/key arrive sentinel-terminated for the C TLS API; the file's
    // [tls] section is honored now (ADR-9).
    const tls = resolveTls(cfg.loader.arena_state.allocator(), v) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.TlsIncomplete => {
            log.err("tls.cert and tls.key must be set together", .{});
            return error.InvalidArgs;
        },
    };
    const cert_path = tls.cert;
    const key_path = tls.key;
    const skip_tls = tls.skip_tls;

    // Inherited listener fds (comma list parsed by the loader already).
    const MAX_LISTEN_FDS = 64;
    comptime {
        // One worker per listen fd; a worker id past these bounds would
        // drop counters and room delivery into threadlocal fallbacks the
        // SIGUSR1 dump never reads (gate R5).
        std.debug.assert(MAX_LISTEN_FDS <= metrics.MAX_WORKERS);
        std.debug.assert(MAX_LISTEN_FDS <= room_registry_mod.MAX_WORKERS);
    }
    var listen_fds: [MAX_LISTEN_FDS]std.posix.fd_t = undefined;
    var listen_fd_count: usize = 0;

    for (v.core.listen_fd) |fd_str| {
        if (listen_fd_count >= MAX_LISTEN_FDS) break;
        listen_fds[listen_fd_count] = std.fmt.parseInt(std.posix.fd_t, fd_str, 10) catch {
            log.err("invalid fd number in --listen-fd list: {s}", .{fd_str});
            return error.InvalidArgs;
        };
        listen_fd_count += 1;
    }

    // Per-worker session quota
    const worker_count: usize = if (listen_fd_count > 0) listen_fd_count else 1;
    const per_worker_sessions = max_sessions / worker_count;

    log.info("starting xmppd-core host={s} address={s} port={d} workers={d} sessions_per_worker={d}", .{
        host, address, port, worker_count, per_worker_sessions,
    });

    if (try @import("backend").migrationPending(db_path)) {
        log.err("an interrupted migrate-precis recovery is pending; rerun 'xmppctl migrate-precis --apply' before starting xmppd-core", .{});
        return error.MigrationPending;
    }

    // Open storage backends (shared across workers — backends are thread-safe)
    var op_backend: ?OpBackendType = null;
    var roster_store: ?GenericRosterStore = null;
    var offline_store: ?GenericOfflineStore(OpBackendType) = null;
    var vcard_store: ?GenericVCardStore = null;
    var rs: ?GenericRoomStore = null;
    var block_store_val: ?GenericBlockStore = null;
    var pep_store_val: ?GenericPepStore = null;
    {
        var op_path_buf: [1024]u8 = undefined;
        const op_path = std.fmt.bufPrint(&op_path_buf, "{s}/op", .{db_path}) catch {
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
        rs = GenericRoomStore.init(&op_backend.?, allocator);
        block_store_val = GenericBlockStore.init(&op_backend.?);
        pep_store_val = GenericPepStore.init(&op_backend.?);
    }
    defer if (op_backend) |*b| b.close();

    var archive_backend: ?ArchiveBackendType = null;
    var archive_store: ?archive_store_mod.ArchiveStore(ArchiveBackendType) = null;
    {
        var archive_path_buf: [1024]u8 = undefined;
        const archive_path = std.fmt.bufPrint(&archive_path_buf, "{s}/archive", .{db_path}) catch {
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

    // T87: single archive writer thread — workers enqueue, it alone calls
    // store(). Compaction stalls no longer freeze an event loop.
    var archive_queue: ?ArchiveWriteQueue = null;
    var archive_writer_thread: ?std.Thread = null;
    if (archive_store != null) {
        archive_queue = ArchiveWriteQueue.init() catch |err| blk: {
            log.err("archive write queue init failed: {} — archiving stays inline", .{err});
            break :blk null;
        };
        if (archive_queue) |*q| {
            archive_writer_thread = std.Thread.spawn(.{}, archiveWriterMain, .{ q, &archive_store.? }) catch |err| blk: {
                log.err("archive writer thread spawn failed: {} — archiving stays inline", .{err});
                q.deinit();
                archive_queue = null;
                break :blk null;
            };
            if (archive_writer_thread != null) {
                log.info("archive writer thread started (queue cap {d}, batch {d})", .{ ArchiveWriteQueue.MAX_JOBS, ARCHIVE_WRITER_BATCH });
            }
        }
    }
    // Runs before the backend close deferred above (LIFO): stop, join, free.
    defer {
        if (archive_queue) |*q| {
            if (archive_writer_thread) |t| {
                q.stopping.store(true, .release);
                _ = std.posix.write(q.pipe_wr, "\x00") catch {};
                t.join();
            }
            q.deinit();
        }
    }

    // MUC host resolution — each worker creates its own RoomRegistry in configureServer
    var muc_host_buf: [256]u8 = undefined;
    const effective_muc_host: ?[]const u8 = if (v.muc.host.len != 0) v.muc.host else blk: {
        const muc_default = std.fmt.bufPrint(&muc_host_buf, "conference.{s}", .{host}) catch null;
        break :blk muc_default;
    };

    // Session map — single JID-keyed routing table (multi_worker flag gates lock overhead)
    var session_map = SessionMap.init(allocator, worker_count > 1, max_resources_per_account);
    defer session_map.deinit();
    log.info("session map allocated (multi_worker={s})", .{if (worker_count > 1) "true" else "false"});

    // Delivery system (MPSC queues + wake pipes) — allocated only when workers > 1
    var delivery_sys: ?DeliverySystem = null;
    if (worker_count > 1) {
        delivery_sys = DeliverySystem.init(allocator, @intCast(worker_count)) catch |err| {
            log.err("failed to allocate delivery system: {}", .{err});
            return error.DeliverySystemInitFailed;
        };
        delivery_sys.?.envelope_hook = &metrics.noteEnvelope;
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
        .skip_tls = skip_tls,
        .roster = if (roster_store != null) &roster_store.? else null,
        .offline = if (offline_store != null) &offline_store.? else null,
        .archive = if (archive_store != null) &archive_store.? else null,
        .archive_queue = if (archive_queue != null) &archive_queue.? else null,
        .vcard = if (vcard_store != null) &vcard_store.? else null,
        .muc_enabled = (effective_muc_host != null),
        .room_store = if (rs != null) &rs.? else null,
        .block_store = if (block_store_val != null) &block_store_val.? else null,
        .pep_store = if (pep_store_val != null) &pep_store_val.? else null,
        .muc_host = effective_muc_host,
        .session_map = &session_map,
        .delivery_system = if (delivery_sys) |*ds| ds else null,
        .oidc_import_avatar = oidc_import_avatar,
        .allocator = allocator,
    };

    // Single-fd (legacy / dev mode): run directly on main thread
    if (listen_fd_count <= 1) {
        var server: Server = undefined;
        if (listen_fd_count == 1)
            try server.initFromFdOpts(host, listen_fds[0], allocator, per_worker_sessions, ctx.skip_tls)
        else
            try server.initWithMaxSessions(host, address, port, allocator, per_worker_sessions);
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
        var server: Server = undefined;
        try server.initFromFdOpts(host, listen_fds[listen_fd_count - 1], allocator, per_worker_sessions, ctx.skip_tls);
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

/// Loads the core configuration through the shared loader (ADR-9):
/// the inherited --conf-fd blob is prescanned alongside --config, so a
/// supervised child gets file < forwarded < CLI and a manual run gets
/// default < file < CLI. The caller owns `loaded`; on error it is
/// already deinitialized. noinline keeps the parser's locals out of
/// main's long-lived frame in optimized builds.
noinline fn loadCoreConfig(loaded: *schema.CoreLoader, gpa: std.mem.Allocator, argv: []const []const u8, diag: *conf.Diag) conf.Error!void {
    loaded.* = schema.CoreLoader.init(gpa);
    errdefer loaded.deinit();
    try loaded.loadInto(.{
        .conf_fd = schema.confFdArg(argv),
        .path = schema.configPathArg(argv),
        .args = argv,
    }, diag);
}

/// Resolved TLS inputs for one worker: cert and key are valid only as a
/// pair and are sentinel-terminated for the C TLS API; disabled or
/// certless TLS yields null paths and skip_tls.
const TlsConfig = struct {
    cert: ?[:0]const u8,
    key: ?[:0]const u8,
    skip_tls: bool,
};

fn resolveTls(arena: std.mem.Allocator, v: *const schema.Sections) error{ OutOfMemory, TlsIncomplete }!TlsConfig {
    if ((v.tls.cert.len == 0) != (v.tls.key.len == 0)) return error.TlsIncomplete;
    const on = v.tls.enabled and v.tls.cert.len != 0;
    return .{
        .cert = if (on) try arena.dupeZ(u8, v.tls.cert) else null,
        .key = if (on) try arena.dupeZ(u8, v.tls.key) else null,
        .skip_tls = !on,
    };
}

/// --help is generated from the schema: every core_cli spelling plus
/// the shared file keys and their defaults. A fresh loader is used so
/// the defaults shown come from the schema initializers, not the
/// resolved values of this run.
fn printUsage(allocator: std.mem.Allocator) std.Io.Writer.Error!void {
    var gen = schema.CoreLoader.init(allocator);
    defer gen.deinit();
    var buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buf);
    try stdout.interface.writeAll("Usage: xmppd-core [OPTIONS]\n\n");
    try gen.writeHelp(&stdout.interface);
    try stdout.interface.flush();
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
    skip_tls: bool,
    roster: ?*GenericRosterStore,
    offline: ?*GenericOfflineStore(OpBackendType),
    archive: ?*archive_store_mod.ArchiveStore(ArchiveBackendType),
    archive_queue: ?*ArchiveWriteQueue,
    vcard: ?*GenericVCardStore,
    muc_enabled: bool,
    room_store: ?*GenericRoomStore,
    block_store: ?*GenericBlockStore,
    pep_store: ?*GenericPepStore,
    muc_host: ?[]const u8,
    session_map: *SessionMap,
    delivery_system: ?*DeliverySystem,
    oidc_import_avatar: bool,
    allocator: std.mem.Allocator,
};

/// Worker thread arguments.
const WorkerArgs = struct {
    fd: std.posix.fd_t,
    worker_id: usize,
    ctx: *WorkerCtx,
};

/// T87 writer-thread batch size per drain iteration.
const ARCHIVE_WRITER_BATCH: usize = 128;

/// T87: archive writer thread — drains the shared queue into the store.
fn archiveWriterMain(queue: *ArchiveWriteQueue, store: *archive_store_mod.ArchiveStore(ArchiveBackendType)) void {
    log.info("archive writer thread starting", .{});
    queue.writerLoop(store, ARCHIVE_WRITER_BATCH);
    log.info("archive writer thread exiting", .{});
}

/// Configure a Server instance with TLS, auth, S2S, roster, offline, archive, vcard, MUC, and session map.
fn configureServer(server: *Server, ctx: *WorkerCtx, worker_id: u16) void {
    server.worker_id = worker_id;
    server.session_map = ctx.session_map;
    const caps = @import("worker/worker.zig").caps_mod;
    server.server_caps = caps.computeServerCaps();
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
    server.oidc_import_avatar = ctx.oidc_import_avatar;
    if (ctx.offline != null and ctx.archive != null) {
        server.configureOffline(ctx.offline.?, ctx.archive.?);
    }
    if (ctx.archive_queue) |q| server.configureArchiveWriter(q);

    if (ctx.block_store) |bs| server.configureBlockStore(bs);
    if (ctx.pep_store) |ps| server.configurePepStore(ps);

    if (ctx.muc_enabled) {
        const reg = ctx.allocator.create(RoomRegistry) catch return;
        reg.* = RoomRegistry.init(ctx.allocator);
        server.room_registry = reg;
        server.room_store = ctx.room_store;
        server.muc_host = ctx.muc_host;

        // Load persistent rooms from store (T105), only rooms owned by
        // this worker (S19).
        if (ctx.room_store) |store| {
            const loaded = room_registry_mod.loadPersistentRooms(reg, store, muc_actor.getWorkerCount(server), worker_id);
            if (loaded > 0) {
                log.info("worker {d}: loaded {d} persistent rooms", .{ worker_id, loaded });
            }
        }
    }
}

/// Thread entry point for worker threads. Each thread owns its own Server
/// with its own kqueue and listener fd.
fn workerThread(args: *WorkerArgs) void {
    log.info("worker {d} starting (fd={d})", .{ args.worker_id, args.fd });

    var server: Server = undefined;
    server.initFromFdOpts(
        args.ctx.host,
        args.fd,
        args.ctx.allocator,
        args.ctx.per_worker_sessions,
        args.ctx.skip_tls,
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

// ============================================================================
// lib/conf loading tests (X4 part 2a, ADR-9)
// ============================================================================

const testing = std.testing;

fn writeTempConfig(dir: *std.fs.Dir, name: []const u8, content: []const u8, buf: []u8) ![]const u8 {
    const f = try dir.createFile(name, .{});
    defer f.close();
    try f.writeAll(content);
    return try dir.realpath(name, buf);
}

test "core config: the file's [tls] section reaches the TLS setup" {
    // Goal: cert and key set in the file configure TLS (the ADR-9 bug
    // had core skipping [tls] entirely). resolveTls sees the pair,
    // terminates it for the C API, and clears skip_tls.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "core.ini",
        \\[server]
        \\hostname = file.test
        \\[tls]
        \\cert = /x/cert.pem
        \\key = /x/key.pem
        \\
    , &path_buf);

    var diag: conf.Diag = .{};
    var l: schema.CoreLoader = undefined;
    try loadCoreConfig(&l, testing.allocator, &.{ "--config", path }, &diag);
    defer l.deinit();
    try testing.expectEqualStrings("/x/cert.pem", l.values.tls.cert);
    try testing.expectEqualStrings("/x/key.pem", l.values.tls.key);
    try testing.expect(l.values.tls.enabled);
    try testing.expectEqual(.file, l.provenanceOf("tls", "cert"));

    const tls = try resolveTls(l.arena_state.allocator(), &l.values);
    try testing.expect(!tls.skip_tls);
    try testing.expectEqualStrings("/x/cert.pem", tls.cert.?);
    try testing.expectEqualStrings("/x/key.pem", tls.key.?);
}

test "core config: --no-tls wins over a file [tls] pair" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "core.ini",
        \\[tls]
        \\cert = /x/cert.pem
        \\key = /x/key.pem
        \\
    , &path_buf);

    var diag: conf.Diag = .{};
    var l: schema.CoreLoader = undefined;
    try loadCoreConfig(&l, testing.allocator, &.{ "--config", path, "--no-tls" }, &diag);
    defer l.deinit();
    try testing.expect(!l.values.tls.enabled);

    const tls = try resolveTls(l.arena_state.allocator(), &l.values);
    try testing.expect(tls.skip_tls);
    try testing.expect(tls.cert == null);
    try testing.expect(tls.key == null);
}

test "core config: cert without key is a startup error" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "core.ini", "[tls]\ncert = /x/cert.pem\n", &path_buf);

    var diag: conf.Diag = .{};
    var l: schema.CoreLoader = undefined;
    try loadCoreConfig(&l, testing.allocator, &.{ "--config", path }, &diag);
    defer l.deinit();
    try testing.expectError(error.TlsIncomplete, resolveTls(l.arena_state.allocator(), &l.values));
}

test "core config: a child without --conf-fd loads its --config file" {
    // Goal: a manual or dev run keeps working exactly like today: the
    // file supplies values with .file provenance and the defaults
    // fill the rest.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "core.ini",
        \\[server]
        \\hostname = manual.test
        \\[core]
        \\max_sessions = 64
        \\
    , &path_buf);

    var diag: conf.Diag = .{};
    var l: schema.CoreLoader = undefined;
    try loadCoreConfig(&l, testing.allocator, &.{ "--config", path }, &diag);
    defer l.deinit();
    try testing.expectEqualStrings("manual.test", l.values.server.hostname);
    try testing.expectEqual(.file, l.provenanceOf("server", "hostname"));
    try testing.expectEqual(@as(usize, 64), l.values.core.max_sessions);
    try testing.expectEqual(.file, l.provenanceOf("core", "max_sessions"));
    try testing.expectEqual(@as(usize, 256), l.values.core.max_resources_per_account);
    try testing.expectEqual(.default, l.provenanceOf("core", "max_resources_per_account"));
}

test "core config: an unknown argument is a startup error, not a warning" {
    var diag: conf.Diag = .{};
    var l: schema.CoreLoader = undefined;
    try testing.expectError(error.UnknownArgument, loadCoreConfig(&l, testing.allocator, &.{"--bogus-arg"}, &diag));
    try testing.expectEqualStrings("--bogus-arg", diag.key);
}
