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
//!   server.hostname    -> --host forwarded to core and s2s
//!   server.c2s_port    -> privileged C2S binds
//!   server.bind_address-> C2S and S2S binds (s2s.bind_address overrides)
//!   server.db_path     -> --db forwarded to auth and core, plus subdirs
//!   server.user        -> unprivileged run user for children
//!   server.log_file    -> stderr target under --background
//!   tls.cert/key       -> --cert/--key forwarded to s2s and core
//!   auth.socket        -> auth --socket, core --auth-socket, readiness
//!   s2s.socket         -> s2s --core-socket, core --s2s-socket, readiness
//!   s2s.port/enabled   -> s2s --port and whether the child spawns
//!   muc.host           -> s2s --muc-host (empty: conference.{hostname})
//!   core.workers       -> C2S listener count (auto: CPU count)
//!   master.*_path      -> child executable paths
//!   master.run_dir, master.background, meta.* -> CLI only (in_file=false)

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
    } = .{},
    meta: struct {
        config_path: []const u8 = "",
        help: bool = false,
        version: bool = false,
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
    .{ .section = "meta", .field = "config_path", .in_file = false },
    .{ .section = "meta", .field = "help", .in_file = false },
    .{ .section = "meta", .field = "version", .in_file = false },
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
