//! Shared xmppd configuration schema (ADR-9).
//!
//! One Sections struct and one field table describe every key the shared
//! config file may carry, so a single file serves every daemon: each daemon
//! loads the full table through lib/conf and consumes only its own fields.
//! A key or section the schema does not name is a startup error, never a
//! silent ignore.
//!
//! Defaults live only in these field initializers. Precedence is
//! default < file < forwarded < CLI with per-field provenance in the
//! loader. Per-daemon CLI tables map each accepted spelling onto fields;
//! the same file key may be --socket to one daemon and --auth-socket to
//! another.
//!
//! Consumption map for the master:
//!   server.hostname    -> forwarded to core and s2s through the ConfFd
//!   server.c2s_port    -> privileged C2S binds
//!   server.bind_address-> C2S and S2S binds (s2s.bind_address overrides)
//!   server.db_path     -> forwarded to auth and core, plus subdirs
//!   server.user        -> unprivileged run user for children
//!   server.log_file    -> stderr target under --background
//!   tls.cert/key       -> forwarded to s2s and core
//!   auth.socket        -> auth --socket, core --auth-socket, readiness
//!   s2s.socket         -> s2s --core-socket, core --s2s-socket, readiness
//!   s2s.port/enabled   -> forwarded s2s port and whether the child spawns
//!   muc.host           -> forwarded (empty: conference.{hostname} in child)
//!   core.workers       -> C2S listener count (auto: CPU count)
//!   master.*_path      -> child executable paths
//!   master.run_dir, master.background, meta.* -> CLI only (in_file=false)
//!
//! The master serializes the resolved values once into a sealed ConfFd
//! passed to core and s2s on a remapped slot named by --conf-fd. Their
//! argv then carries only the CLI-only fields the schema cannot forward:
//! the inherited listen fds and the conf fd slot itself. xmppctl has no
//! master: it reads its --config file through the same loader.

const std = @import("std");
const conf = @import("conf");

pub const Sections = struct {
    server: struct {
        hostname: []const u8 = "localhost",
        bind_address: []const u8 = "0.0.0.0",
        c2s_port: u16 = 5222,
        db_path: []const u8 = "/var/db/xmppd/users.db",
        lmdb_map_size_mb: usize = 8192,
        user: []const u8 = "",
        log_file: []const u8 = "/var/log/xmppd/xmppd.log",
        pidfile: []const u8 = "/var/run/xmppd/xmppd.pid",
    } = .{},
    tls: struct {
        cert: []const u8 = "",
        key: []const u8 = "",
        enabled: bool = true,
    } = .{},
    auth: struct {
        socket: []const u8 = "/var/run/xmppd/auth.sock",
        max_per_account: u32 = 60,
        max_per_ip: u32 = 200,
        window_seconds: u32 = 120,
        lockout_duration: conf.Duration = .{ .ms = 300_000 },
        lockout_threshold: u16 = 10,
        ip_lockout_threshold: u16 = 20,
        users_scan_limit: usize = 100_000,
        rate_limit: bool = true,
        crypto_threads: u32 = 0,
        registration: bool = false,
        require_invite: bool = true,
    } = .{},
    s2s: struct {
        socket: []const u8 = "/var/run/xmppd/s2s.sock",
        port: u16 = 5269,
        enabled: bool = true,
        /// Empty follows server.bind_address.
        bind_address: []const u8 = "",
        /// Remap slot of the inherited s2s listener; -1 means none.
        listen_fd: i32 = -1,
    } = .{},
    muc: struct {
        /// Empty resolves to conference.{server.hostname} when forwarded.
        host: []const u8 = "",
    } = .{},
    core: struct {
        max_sessions: usize = 4096,
        fan_out_batch_size: u8 = 32,
        max_resources_per_account: usize = 256,
        workers: conf.IntOr(enum { auto }, u16) = .{ .kw = .auto },
        listen_fd: [][]const u8 = &.{},
        log_level: enum { debug, info, warn, err } = .info,
    } = .{},
    oidc: struct {
        issuer: []const u8 = "",
        client_id: []const u8 = "",
        client_secret: []const u8 = "",
        token_endpoint: []const u8 = "",
        jwks_uri: []const u8 = "",
        ca_file: []const u8 = "",
        introspection_endpoint: []const u8 = "",
        user_domain: []const u8 = "",
        socket: []const u8 = "/var/run/xmppd/oidc.sock",
        max_per_account: u32 = 60,
        max_per_ip: u32 = 200,
        rate_limit: bool = true,
        import_avatar: bool = false,
        idp_threads: u8 = 8,
        idp_max_outstanding: u16 = 256,
        idp_connect_timeout_ms: u32 = 3000,
        idp_timeout_ms: u32 = 10000,
        localpart_claim: []const u8 = "preferred_username",
        localpart_claim_prefix: []const u8 = "",
        localpart_auto_suffix: bool = false,
    } = .{},
    master: struct {
        core_path: []const u8 = "xmppd-core",
        auth_path: []const u8 = "xmppd-auth",
        s2s_path: []const u8 = "xmppd-s2s",
        run_dir: []const u8 = "/var/run/xmppd",
        background: bool = false,
    } = .{},
    ctl: struct {
        password: []const u8 = "",
        password_file: []const u8 = "",
        max_uses: u16 = 1,
        expires_hours: u32 = 0,
        apply: bool = false,
        raw: bool = false,
    } = .{},
    meta: struct {
        config_path: []const u8 = "",
        help: bool = false,
        version: bool = false,
        /// Remap slot of the inherited sealed config blob; -1 none.
        conf_fd: i32 = -1,
    } = .{},
};

/// Every key the shared file may carry. CLI-only fields are marked
/// in_file = false: a file key that names one is an unknown-key error.
pub const file_spec = [_]conf.FieldSpec{
    .{ .section = "server", .field = "hostname", .help = "XMPP server hostname" },
    .{ .section = "server", .field = "bind_address", .help = "listen address literal" },
    .{ .section = "server", .field = "c2s_port", .help = "c2s listen port" },
    .{ .section = "server", .field = "db_path", .help = "user database path" },
    .{ .section = "server", .field = "lmdb_map_size_mb", .help = "LMDB map size in MiB" },
    .{ .section = "server", .field = "user", .help = "unprivileged user for children" },
    .{ .section = "server", .field = "log_file", .help = "log file path" },
    .{ .section = "server", .field = "pidfile", .help = "pid file path" },
    .{ .section = "tls", .field = "cert", .help = "TLS certificate chain" },
    .{ .section = "tls", .field = "key", .help = "TLS private key" },
    .{ .section = "tls", .field = "enabled", .help = "enable STARTTLS" },
    .{ .section = "auth", .field = "socket", .help = "auth IPC socket" },
    .{ .section = "auth", .field = "max_per_account", .aliases = &.{"rate_max_per_account"}, .help = "auth attempts per account per window" },
    .{ .section = "auth", .field = "max_per_ip", .aliases = &.{"rate_max_per_ip"}, .help = "auth attempts per IP per window" },
    .{ .section = "auth", .field = "window_seconds", .help = "rate window in seconds" },
    .{ .section = "auth", .field = "lockout_duration", .help = "lockout duration" },
    .{ .section = "auth", .field = "lockout_threshold", .help = "failures before lockout" },
    .{ .section = "auth", .field = "ip_lockout_threshold", .help = "IP failures before lock" },
    .{ .section = "auth", .field = "users_scan_limit", .help = "startup users scan bound" },
    .{ .section = "auth", .field = "rate_limit", .help = "enable rate limiting" },
    .{ .section = "auth", .field = "crypto_threads", .help = "password hash threads" },
    .{ .section = "auth", .field = "registration", .help = "enable registration" },
    .{ .section = "auth", .field = "require_invite", .help = "registration needs invite" },
    .{ .section = "s2s", .field = "socket", .help = "s2s IPC socket" },
    .{ .section = "s2s", .field = "port", .help = "s2s listen port" },
    .{ .section = "s2s", .field = "enabled", .help = "enable s2s" },
    .{ .section = "s2s", .field = "bind_address", .help = "s2s listen address literal" },
    .{ .section = "s2s", .field = "listen_fd", .in_file = false, .help = "inherited listen fd" },
    .{ .section = "muc", .field = "host", .help = "MUC service host" },
    .{ .section = "core", .field = "max_sessions", .help = "session cap" },
    .{ .section = "core", .field = "fan_out_batch_size", .help = "fan-out batch" },
    .{ .section = "core", .field = "max_resources_per_account", .help = "resource cap" },
    .{ .section = "core", .field = "workers", .help = "worker count" },
    .{ .section = "core", .field = "listen_fd", .in_file = false, .help = "inherited listen fd" },
    .{ .section = "core", .field = "log_level", .help = "log verbosity" },
    .{ .section = "oidc", .field = "issuer" },
    .{ .section = "oidc", .field = "client_id" },
    .{ .section = "oidc", .field = "client_secret" },
    .{ .section = "oidc", .field = "token_endpoint" },
    .{ .section = "oidc", .field = "jwks_uri" },
    .{ .section = "oidc", .field = "ca_file" },
    .{ .section = "oidc", .field = "introspection_endpoint" },
    .{ .section = "oidc", .field = "user_domain" },
    .{ .section = "oidc", .field = "socket" },
    .{ .section = "oidc", .field = "max_per_account", .aliases = &.{"rate_max_per_account"} },
    .{ .section = "oidc", .field = "max_per_ip", .aliases = &.{"rate_max_per_ip"} },
    .{ .section = "oidc", .field = "rate_limit" },
    .{ .section = "oidc", .field = "import_avatar" },
    .{ .section = "oidc", .field = "idp_threads" },
    .{ .section = "oidc", .field = "idp_max_outstanding" },
    .{ .section = "oidc", .field = "idp_connect_timeout_ms" },
    .{ .section = "oidc", .field = "idp_timeout_ms" },
    .{ .section = "oidc", .field = "localpart_claim" },
    .{ .section = "oidc", .field = "localpart_claim_prefix" },
    .{ .section = "oidc", .field = "localpart_auto_suffix" },
    .{ .section = "master", .field = "core_path" },
    .{ .section = "master", .field = "auth_path" },
    .{ .section = "master", .field = "s2s_path" },
    .{ .section = "master", .field = "run_dir", .in_file = false },
    .{ .section = "master", .field = "background", .in_file = false },
    .{ .section = "ctl", .field = "password", .in_file = false },
    .{ .section = "ctl", .field = "password_file", .in_file = false },
    .{ .section = "ctl", .field = "max_uses", .in_file = false },
    .{ .section = "ctl", .field = "expires_hours", .in_file = false },
    .{ .section = "ctl", .field = "apply", .in_file = false },
    .{ .section = "ctl", .field = "raw", .in_file = false },
    .{ .section = "meta", .field = "config_path", .in_file = false },
    .{ .section = "meta", .field = "help", .in_file = false },
    .{ .section = "meta", .field = "version", .in_file = false },
    .{ .section = "meta", .field = "conf_fd", .in_file = false },
};

/// Every CLI spelling the master accepts today.
pub const master_cli = [_]conf.CliSpec{
    .{ .name = "host", .target = "server.hostname", .help = "XMPP server hostname" },
    .{ .name = "port", .target = "server.c2s_port", .help = "c2s listen port" },
    .{ .name = "bind", .target = "server.bind_address", .help = "c2s/s2s listen address literal" },
    .{ .name = "cert", .target = "tls.cert", .help = "TLS certificate file (PEM)" },
    .{ .name = "key", .target = "tls.key", .help = "TLS private key file (PEM)" },
    .{ .name = "core-path", .target = "master.core_path", .help = "path to xmppd-core" },
    .{ .name = "auth-path", .target = "master.auth_path", .help = "path to xmppd-auth" },
    .{ .name = "s2s-path", .target = "master.s2s_path", .help = "path to xmppd-s2s" },
    .{ .name = "no-s2s", .target = "s2s.enabled", .flag = false, .help = "disable s2s federation" },
    .{ .name = "auth-socket", .target = "auth.socket", .help = "auth IPC socket path" },
    .{ .name = "db", .target = "server.db_path", .help = "user database path" },
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"}, .help = "config file path (passed to children)" },
    .{ .name = "log-file", .target = "server.log_file", .help = "log file path (--background)" },
    .{ .name = "run-dir", .target = "master.run_dir", .help = "runtime dir for pid files" },
    .{ .name = "background", .target = "master.background", .flag = true, .aliases = &.{"b"}, .help = "daemonize (fork, detach from terminal)" },
    .{ .name = "version", .target = "meta.version", .flag = true, .aliases = &.{"v"}, .help = "print version and exit" },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"}, .help = "show this help" },
};

/// The master's loader: shared file schema plus the master CLI table.
pub const MasterLoader = conf.Loader(Sections, &file_spec, &master_cli, .{});

/// Every CLI spelling xmppd-core accepts. Dev-mode spellings (--address,
/// --bind, --port) and the supervised ones (--listen-fd, --conf-fd) share
/// the table; the forwarded blob covers every file key.
pub const core_cli = [_]conf.CliSpec{
    .{ .name = "host", .target = "server.hostname", .help = "XMPP server hostname" },
    .{ .name = "address", .target = "server.bind_address", .aliases = &.{"bind"}, .help = "bind address literal (dev mode)" },
    .{ .name = "port", .target = "server.c2s_port", .help = "c2s listen port (dev mode)" },
    .{ .name = "cert", .target = "tls.cert", .help = "TLS certificate file (PEM)" },
    .{ .name = "key", .target = "tls.key", .help = "TLS private key file (PEM)" },
    .{ .name = "auth-socket", .target = "auth.socket", .help = "auth IPC socket path" },
    .{ .name = "s2s-socket", .target = "s2s.socket", .help = "s2s IPC socket path" },
    .{ .name = "listen-fd", .target = "core.listen_fd", .help = "inherited listen fd list (comma-separated)" },
    .{ .name = "db", .target = "server.db_path", .help = "user database path" },
    .{ .name = "muc-host", .target = "muc.host", .help = "MUC service host" },
    .{ .name = "no-tls", .target = "tls.enabled", .flag = false, .help = "disable STARTTLS" },
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"}, .help = "config file path" },
    .{ .name = "conf-fd", .target = "meta.conf_fd", .help = "inherited sealed config fd" },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"}, .help = "show this help" },
};

/// Every CLI spelling xmppd-s2s accepts. --config is honored: the shared
/// file feeds the s2s fields the same way the forwarded blob does.
pub const s2s_cli = [_]conf.CliSpec{
    .{ .name = "host", .target = "server.hostname", .help = "XMPP server hostname" },
    .{ .name = "address", .target = "s2s.bind_address", .aliases = &.{"bind"}, .help = "s2s listen address literal" },
    .{ .name = "port", .target = "s2s.port", .help = "s2s listen port" },
    .{ .name = "core-socket", .target = "s2s.socket", .help = "core IPC socket path" },
    .{ .name = "cert", .target = "tls.cert", .help = "TLS certificate file (PEM)" },
    .{ .name = "key", .target = "tls.key", .help = "TLS private key file (PEM)" },
    .{ .name = "muc-host", .target = "muc.host", .help = "MUC service host" },
    .{ .name = "listen-fd", .target = "s2s.listen_fd", .help = "inherited s2s listen fd" },
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"}, .help = "config file path" },
    .{ .name = "conf-fd", .target = "meta.conf_fd", .help = "inherited sealed config fd" },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"}, .help = "show this help" },
};

/// Every CLI spelling xmppctl accepts. Subcommand positionals are
/// collected through the loader (positional_cap); --rename and the
/// repeatable --hosted-domain are pre-scanned by ctl itself because they
/// take two values or a list the schema cannot express.
pub const ctl_cli = [_]conf.CliSpec{
    .{ .name = "db", .target = "server.db_path", .help = "storage directory" },
    .{ .name = "auth-socket", .target = "auth.socket", .help = "auth daemon IPC socket" },
    .{ .name = "password", .target = "ctl.password", .help = "provide password non-interactively" },
    .{ .name = "password-file", .target = "ctl.password_file", .help = "read password from file" },
    .{ .name = "apply", .target = "ctl.apply", .flag = true, .help = "apply migration ops (default dry run)" },
    .{ .name = "raw", .target = "ctl.raw", .flag = true, .help = "deluser: exact source localpart" },
    .{ .name = "run-dir", .target = "master.run_dir", .help = "daemon pid-file directory" },
    .{ .name = "max-uses", .target = "ctl.max_uses", .help = "invite create: max uses" },
    .{ .name = "expires", .target = "ctl.expires_hours", .help = "invite create: hours until expiry" },
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"}, .help = "config file path" },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"}, .help = "show this help" },
};

pub const CoreLoader = conf.Loader(Sections, &file_spec, &core_cli, .{});
pub const S2sLoader = conf.Loader(Sections, &file_spec, &s2s_cli, .{});
/// ctl collects its subcommand and arguments as positionals.
pub const CtlLoader = conf.Loader(Sections, &file_spec, &ctl_cli, .{ .positional_cap = 16 });

/// The config file path the argv carries, in every accepted spelling
/// (--config, -c, and the = forms). Returns null past "--" and when the
/// option has no value; the loader diagnoses those cases itself.
pub fn configPathArg(argv: []const []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--")) return null;
        if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            if (i + 1 < argv.len) return argv[i + 1];
            return null;
        }
        const rest = if (std.mem.startsWith(u8, arg, "--"))
            arg[2..]
        else if (arg.len > 1 and arg[0] == '-')
            arg[1..]
        else
            continue;
        const eq = std.mem.indexOfScalar(u8, rest, '=') orelse continue;
        const name = rest[0..eq];
        if (std.mem.eql(u8, name, "config") or std.mem.eql(u8, name, "c")) {
            return rest[eq + 1 ..];
        }
    }
    return null;
}

/// The --conf-fd slot the argv carries, in every accepted spelling. The
/// loader needs the fd before applyArgs runs, so each child pre-scans
/// just like the config path. A missing or non-numeric value returns
/// null: applyArgs diagnoses it as a bad or missing value itself.
pub fn confFdArg(argv: []const []const u8) ?i32 {
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--")) return null;
        var value: ?[]const u8 = null;
        if (std.mem.eql(u8, arg, "--conf-fd")) {
            if (i + 1 < argv.len) value = argv[i + 1];
        } else if (std.mem.startsWith(u8, arg, "--conf-fd=")) {
            value = arg["--conf-fd=".len..];
        } else {
            continue;
        }
        const v = value orelse return null;
        return std.fmt.parseInt(i32, v, 10) catch null;
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn writeTempConfig(dir: *std.fs.Dir, name: []const u8, content: []const u8, buf: []u8) ![]const u8 {
    const f = try dir.createFile(name, .{});
    defer f.close();
    try f.writeAll(content);
    return try dir.realpath(name, buf);
}

test "child config: forwarded beats the file and loses to the child CLI flag" {
    // Goal: precedence default < file < forwarded < CLI holds inside a
    // child; provenance records the forwarded source, so a master CLI
    // override wins in the child exactly once (ADR-9).
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "child.ini",
        \\[server]
        \\hostname = file.test
        \\db_path = /file/db
        \\
    , &path_buf);

    const blob = "--server.hostname=fwd.test\n--server.db_path=/fwd/db\n";
    const cf = try conf.ConfFd.create(blob);

    var diag: conf.Diag = .{};
    var l = try CoreLoader.load(testing.allocator, .{
        .path = path,
        .conf_fd = cf.fd,
        .args = &.{ "--host", "cli.test" },
    }, &diag);
    defer l.deinit();

    try testing.expectEqualStrings("cli.test", l.values.server.hostname);
    try testing.expectEqual(.cli, l.provenanceOf("server", "hostname"));
    try testing.expectEqualStrings("/fwd/db", l.values.server.db_path);
    try testing.expectEqual(.forwarded, l.provenanceOf("server", "db_path"));
}

test "core reads the [tls] cert and key from the file" {
    // Goal: the ADR-9 gap is closed: file [tls] values land typed in the
    // shared sections instead of being skipped (the legacy core never
    // read them, so a file-only TLS config silently ran without TLS).
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "tls.ini",
        \\[tls]
        \\cert = /etc/xmppd/server.pem
        \\key = /etc/xmppd/server.key
        \\
    , &path_buf);

    var diag: conf.Diag = .{};
    var l = try CoreLoader.load(testing.allocator, .{ .path = path }, &diag);
    defer l.deinit();

    try testing.expectEqualStrings("/etc/xmppd/server.pem", l.values.tls.cert);
    try testing.expectEqualStrings("/etc/xmppd/server.key", l.values.tls.key);
    try testing.expectEqual(.file, l.provenanceOf("tls", "cert"));
    try testing.expect(l.values.tls.enabled);
}

test "s2s honors --config: file values reach the s2s fields" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "s2s.ini",
        \\[s2s]
        \\port = 5270
        \\socket = /run/x2.sock
        \\bind_address = 10.0.0.9
        \\[muc]
        \\host = muc.test
        \\
    , &path_buf);

    var diag: conf.Diag = .{};
    var l = try S2sLoader.load(testing.allocator, .{
        .path = configPathArg(&.{ "--config", path }),
        .args = &.{ "--config", path },
    }, &diag);
    defer l.deinit();

    try testing.expectEqual(@as(u16, 5270), l.values.s2s.port);
    try testing.expectEqualStrings("/run/x2.sock", l.values.s2s.socket);
    try testing.expectEqualStrings("10.0.0.9", l.values.s2s.bind_address);
    try testing.expectEqualStrings("muc.test", l.values.muc.host);
    try testing.expectEqual(.file, l.provenanceOf("s2s", "port"));
}

test "xmppctl rejects an unknown file key with file:line in the diag" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "bad.ini", "[server]\ndb_path = /db\nhostnam = typo\n", &path_buf);

    var diag: conf.Diag = .{};
    var l = CtlLoader.init(testing.allocator);
    defer l.deinit();
    try testing.expectError(error.UnknownKey, l.loadFile(path, &diag));
    try testing.expectEqual(@as(u32, 3), diag.line);
    try testing.expectEqualStrings("hostnam", diag.key);
}

test "a child without --conf-fd still loads its --config file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "plain.ini", "[server]\nhostname = plain.test\n", &path_buf);

    var diag: conf.Diag = .{};
    var l = try CoreLoader.load(testing.allocator, .{ .path = path }, &diag);
    defer l.deinit();

    try testing.expectEqualStrings("plain.test", l.values.server.hostname);
    try testing.expectEqual(.file, l.provenanceOf("server", "hostname"));
}

test "ctl collects the subcommand and args as positionals, options anywhere" {
    var diag: conf.Diag = .{};
    var l = try CtlLoader.load(testing.allocator, .{
        .args = &.{ "adduser", "alice@x.test", "--password", "pw", "--db", "/db" },
    }, &diag);
    defer l.deinit();

    const pos = l.positionals();
    try testing.expectEqual(@as(usize, 2), pos.len);
    try testing.expectEqualStrings("adduser", pos[0]);
    try testing.expectEqualStrings("alice@x.test", pos[1]);
    try testing.expectEqualStrings("pw", l.values.ctl.password);
    try testing.expectEqualStrings("/db", l.values.server.db_path);
    try testing.expectEqual(.cli, l.provenanceOf("ctl", "password"));
}

test "ctl rejects an unknown argument instead of silently dropping it" {
    var diag: conf.Diag = .{};
    var l = CtlLoader.init(testing.allocator);
    defer l.deinit();
    try testing.expectError(error.UnknownArgument, l.applyArgs(&.{"--bogus"}, &diag));
}
