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
//! another. doc/CONFIGURATION.md is rendered from the same table
//! (`zig build docs-config`), so the doc cannot drift from the loader.
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
        db_path: []const u8 = "/var/db/xmppd",
        lmdb_map_size_mb: usize = 8192,
        user: []const u8 = "",
        log_file: []const u8 = "/var/log/xmppd/xmppd.log",
        pidfile: []const u8 = "/var/run/xmppd/xmppd.pid",
    } = .{},
    tls: struct {
        cert: []const u8 = "",
        key: []const u8 = "",
        enabled: bool = true,
        /// F7 pool lanes. `auto` derives a bounded count from host CPUs.
        handshake_threads: conf.IntOr(enum { auto }, u16) = .{ .kw = .auto },
        /// Active handshakes one pool lane may drive at once.
        handshake_concurrency: u16 = 32,
        /// Queued handoffs one pool lane may hold behind its active bound.
        handshake_queue: u16 = 128,
        /// Lifecycle deadline for one pooled handshake.
        handshake_timeout_ms: u32 = 10_000,
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
        crypto_threads: u32 = 4,
        registration: bool = false,
        require_invite: bool = true,
        /// Sustained SCRAM logins/second the replay cache is sized for:
        /// capacity = login_rate_ceiling x scram_nonce_window_seconds.
        login_rate_ceiling: u32 = 512,
        /// A server nonce stays consumable this long after the core mints
        /// it (freshness check + replay-cache entry TTL).
        scram_nonce_window_seconds: u32 = 60,
        /// Forward clock tolerance for nonce timestamps ahead of now.
        scram_nonce_skew_seconds: u32 = 15,
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
        /// Parked SCRAM exchanges per worker: bounds concurrent in-flight
        /// logins; a full pool answers temporary-auth-failure.
        scram_exchange_slots: usize = 256,
        /// Per-session bound on retained XEP-0198 unacked stanza bytes;
        /// mirrored from sm_state.DEFAULT_MAX_UNACKED_BYTES.
        sm_max_unacked_bytes: u64 = 4 * 1024 * 1024,
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
        /// Empty follows auth.socket so both auth backends share the IPC endpoint.
        socket: []const u8 = "",
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
/// doc, doc_default, used_by and required only feed doc/CONFIGURATION.md
/// (`zig build docs-config`); the loader ignores them.
pub const file_spec = [_]conf.FieldSpec{
    .{ .section = "server", .field = "hostname", .help = "XMPP server hostname", .used_by = "core, s2s",
        .doc = "XMPP domain served (e.g., `example.com`); set it for any real deployment" },
    .{ .section = "server", .field = "bind_address", .help = "listen address literal", .used_by = "master, core, s2s",
        .doc = "C2S listen address literal; S2S follows it unless `s2s.bind_address` is set" },
    .{ .section = "server", .field = "c2s_port", .help = "c2s listen port", .used_by = "master, core",
        .doc = "Client-to-server port" },
    .{ .section = "server", .field = "db_path", .help = "user database path", .used_by = "master, core, auth, oidc, ctl",
        .doc = "Storage base directory; the master also creates `auth/`, `op/`, `archive/` subdirectories under it" },
    .{ .section = "server", .field = "lmdb_map_size_mb", .help = "LMDB map size in MiB", .used_by = "auth, oidc",
        .doc = "LMDB map size in MiB; fixed at open, never resized at runtime" },
    .{ .section = "server", .field = "user", .help = "unprivileged user for children", .used_by = "master",
        .doc = "Unprivileged user the master's children run as (required when the master runs as root)" },
    .{ .section = "server", .field = "log_file", .help = "log file path", .used_by = "master",
        .doc = "Log file path (used with `--background`)" },
    .{ .section = "server", .field = "pidfile", .help = "pid file path",
        .doc = "PID file path; no daemon reads it yet (the master writes `{run_dir}/xmppd.pid`)" },
    .{ .section = "tls", .field = "cert", .help = "TLS certificate chain", .used_by = "core, s2s",
        .doc = "TLS certificate path (PEM, full chain)" },
    .{ .section = "tls", .field = "key", .help = "TLS private key", .used_by = "core, s2s",
        .doc = "TLS private key path (PEM)" },
    .{ .section = "tls", .field = "enabled", .help = "enable STARTTLS", .used_by = "core, s2s",
        .doc = "Enable TLS (C2S STARTTLS and s2s)" },
    .{ .section = "tls", .field = "handshake_threads", .help = "TLS handshake pool lanes", .used_by = "core",
        .doc = "TLS handshake pool lane count (`auto`: ceil(CPU count / 4), clamped to 1..8)" },
    .{ .section = "tls", .field = "handshake_concurrency", .help = "active handshakes per lane", .used_by = "core",
        .doc = "Concurrent TLS handshakes one pool lane may drive" },
    .{ .section = "tls", .field = "handshake_queue", .help = "queued handoffs per lane", .used_by = "core",
        .doc = "Queued TLS handoffs one pool lane may hold behind its active bound" },
    .{ .section = "tls", .field = "handshake_timeout_ms", .help = "handshake deadline", .used_by = "core",
        .doc = "Lifecycle deadline for one pooled TLS handshake in milliseconds" },
    .{ .section = "auth", .field = "socket", .help = "auth IPC socket", .used_by = "master, core, auth, oidc, ctl",
        .doc = "Auth daemon IPC socket; also the default for `oidc.socket`" },
    .{ .section = "auth", .field = "max_per_account", .aliases = &.{"rate_max_per_account"}, .help = "auth attempts per account per window", .used_by = "auth, oidc",
        .doc = "Max auth attempts per account per window" },
    .{ .section = "auth", .field = "max_per_ip", .aliases = &.{"rate_max_per_ip"}, .help = "auth attempts per IP per window", .used_by = "auth, oidc",
        .doc = "Max auth attempts per IP per window" },
    .{ .section = "auth", .field = "window_seconds", .help = "rate window in seconds", .used_by = "auth, oidc",
        .doc = "Rate window size in seconds" },
    .{ .section = "auth", .field = "lockout_duration", .help = "lockout duration", .used_by = "auth, oidc",
        .doc = "Temporary lockout (`300`, `300s` and `5m` are equivalent)" },
    .{ .section = "auth", .field = "lockout_threshold", .help = "failures before lockout", .used_by = "auth, oidc",
        .doc = "Consecutive account failures before temporary lockout" },
    .{ .section = "auth", .field = "ip_lockout_threshold", .help = "IP failures before lock", .used_by = "auth, oidc",
        .doc = "Consecutive IP failures before that address is temporarily locked" },
    .{ .section = "auth", .field = "users_scan_limit", .help = "startup users scan bound", .used_by = "auth",
        .doc = "Startup users scan bound" },
    .{ .section = "auth", .field = "rate_limit", .help = "enable rate limiting", .used_by = "auth, oidc",
        .doc = "Rate limiting master switch; `false` disables it entirely (testing/benchmarks only)" },
    .{ .section = "auth", .field = "crypto_threads", .help = "password hash threads", .used_by = "auth",
        .doc = "Password hash threads (`0` disables the pool and derives inline)" },
    .{ .section = "auth", .field = "registration", .help = "enable registration", .used_by = "auth",
        .doc = "In-band registration (XEP-0077)" },
    .{ .section = "auth", .field = "require_invite", .help = "registration needs invite", .used_by = "auth",
        .doc = "Require invitation code for registration" },
    .{ .section = "auth", .field = "login_rate_ceiling", .help = "sustained logins/s ceiling", .used_by = "auth",
        .doc = "Sustained SCRAM login rate the replay cache is sized for (capacity = ceiling x nonce window)" },
    .{ .section = "auth", .field = "scram_nonce_window_seconds", .help = "server nonce freshness window", .used_by = "auth",
        .doc = "Seconds a core-minted server nonce stays consumable; also the replay-cache entry TTL" },
    .{ .section = "auth", .field = "scram_nonce_skew_seconds", .help = "nonce future-dating tolerance", .used_by = "auth",
        .doc = "Seconds of forward clock skew tolerated on server-nonce timestamps" },
    .{ .section = "s2s", .field = "socket", .help = "s2s IPC socket", .used_by = "master, core, s2s",
        .doc = "IPC socket between core and xmppd-s2s" },
    .{ .section = "s2s", .field = "port", .help = "s2s listen port", .used_by = "master, s2s",
        .doc = "S2S listening port" },
    .{ .section = "s2s", .field = "enabled", .help = "enable s2s", .used_by = "master, core",
        .doc = "Enable s2s federation; the master skips the child and core does not connect" },
    .{ .section = "s2s", .field = "bind_address", .help = "s2s listen address literal", .used_by = "master, s2s",
        .doc_default = "(follows `server.bind_address`)",
        .doc = "S2S listen address literal" },
    .{ .section = "s2s", .field = "listen_fd", .in_file = false, .help = "inherited listen fd" },
    .{ .section = "muc", .field = "host", .help = "MUC service host", .used_by = "core, s2s",
        .doc_default = "`conference.{hostname}`",
        .doc = "MUC service domain; empty resolves to `conference.{server.hostname}`" },
    .{ .section = "core", .field = "max_sessions", .help = "session cap", .used_by = "core",
        .doc = "Maximum concurrent C2S sessions, divided evenly across workers" },
    .{ .section = "core", .field = "fan_out_batch_size", .help = "fan-out batch", .used_by = "core",
        .doc = "MUC occupants delivered per loop tick before yielding" },
    .{ .section = "core", .field = "max_resources_per_account", .help = "resource cap", .used_by = "core",
        .doc = "Maximum resources per account" },
    .{ .section = "core", .field = "scram_exchange_slots", .help = "parked SCRAM exchanges", .used_by = "core",
        .doc = "Concurrent in-flight SCRAM logins per worker; a full pool answers temporary-auth-failure" },
    .{ .section = "core", .field = "sm_max_unacked_bytes", .help = "SM unacked byte bound", .used_by = "core",
        .doc = "Per-session bound on retained stream-management unacked stanza bytes; a session that would exceed it is failed alone, alongside the 256-stanza count bound" },
    .{ .section = "core", .field = "workers", .help = "worker count", .used_by = "master",
        .doc = "C2S listener count; `auto` detects CPUs" },
    .{ .section = "core", .field = "listen_fd", .in_file = false, .help = "inherited listen fd" },
    .{ .section = "core", .field = "log_level", .help = "log verbosity",
        .doc = "Log verbosity (`debug`, `info`, `warn`, `err`); no daemon reads it yet (`std_options` pins `info`)" },
    .{ .section = "oidc", .field = "issuer", .used_by = "oidc", .required = true,
        .doc = "OIDC issuer URL; must match the token `iss` claim" },
    .{ .section = "oidc", .field = "client_id", .used_by = "oidc", .required = true,
        .doc = "OAuth2 client ID" },
    .{ .section = "oidc", .field = "client_secret", .used_by = "oidc", .required = true,
        .doc = "OAuth2 client secret" },
    .{ .section = "oidc", .field = "token_endpoint", .used_by = "oidc", .required = true,
        .doc = "Token endpoint URL (for ROPC)" },
    .{ .section = "oidc", .field = "jwks_uri", .used_by = "oidc", .required = true,
        .doc = "JWKS endpoint URL (for JWT key fetching)" },
    .{ .section = "oidc", .field = "ca_file", .used_by = "oidc",
        .doc = "CA bundle path for IdP TLS verification" },
    .{ .section = "oidc", .field = "introspection_endpoint", .used_by = "oidc",
        .doc = "RFC 7662 introspection (for opaque tokens)" },
    .{ .section = "oidc", .field = "user_domain", .used_by = "oidc",
        .doc = "Domain appended to bare usernames for ROPC (e.g., `morante.dev`)" },
    .{ .section = "oidc", .field = "socket", .used_by = "oidc",
        .doc_default = "(follows `[auth] socket`)",
        .doc = "OIDC-specific IPC socket override" },
    .{ .section = "oidc", .field = "max_per_account", .aliases = &.{"rate_max_per_account"}, .used_by = "oidc",
        .doc = "Max requests per account; `[auth] max_per_account` wins at equal provenance" },
    .{ .section = "oidc", .field = "max_per_ip", .aliases = &.{"rate_max_per_ip"}, .used_by = "oidc",
        .doc = "Max requests per IP; `[auth] max_per_ip` wins at equal provenance" },
    .{ .section = "oidc", .field = "rate_limit", .used_by = "oidc",
        .doc = "Rate limiting switch" },
    .{ .section = "oidc", .field = "import_avatar", .used_by = "oidc, core",
        .doc = "Import the IdP `picture` claim into the vCard on first login" },
    .{ .section = "oidc", .field = "idp_threads", .used_by = "oidc",
        .doc = "IdP HTTP client threads (1..32)" },
    .{ .section = "oidc", .field = "idp_max_outstanding", .used_by = "oidc",
        .doc = "Max in-flight IdP requests (1..4096)" },
    .{ .section = "oidc", .field = "idp_connect_timeout_ms", .used_by = "oidc",
        .doc = "IdP connect timeout in ms (100..60000)" },
    .{ .section = "oidc", .field = "idp_timeout_ms", .used_by = "oidc",
        .doc = "IdP request timeout in ms (connect timeout..120000)" },
    .{ .section = "oidc", .field = "localpart_claim", .used_by = "oidc",
        .doc = "Claim supplying the first-login localpart suggestion: `preferred_username`, `email`, `sub`, or empty to disable auto-provisioning" },
    .{ .section = "oidc", .field = "localpart_claim_prefix", .used_by = "oidc",
        .doc = "Prefix stripped from the suggestion claim before PRECIS preparation (e.g., `user:` for handle-form subjects)" },
    .{ .section = "oidc", .field = "localpart_auto_suffix", .used_by = "oidc",
        .doc = "When the suggested localpart is taken, try `lp-2` .. `lp-99`; `false` refuses a taken suggestion instead" },
    .{ .section = "master", .field = "core_path", .used_by = "master",
        .doc = "Core binary path" },
    .{ .section = "master", .field = "auth_path", .used_by = "master",
        .doc = "Auth binary path (or `xmppd-auth-oidc`)" },
    .{ .section = "master", .field = "s2s_path", .used_by = "master",
        .doc = "S2S federation binary path" },
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

/// Every CLI spelling xmppd-auth accepts. The forwarded blob supplies
/// supervised values; the CLI table still wins for manual overrides.
pub const auth_cli = [_]conf.CliSpec{
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"}, .help = "config file path" },
    .{ .name = "db", .target = "server.db_path", .help = "storage base directory" },
    .{ .name = "socket", .target = "auth.socket", .help = "auth IPC socket path" },
    .{ .name = "max-auth-per-account", .target = "auth.max_per_account", .help = "attempts per account per window" },
    .{ .name = "max-auth-per-ip", .target = "auth.max_per_ip", .help = "attempts per IP per window" },
    .{ .name = "auth-window", .target = "auth.window_seconds", .help = "rate window in seconds" },
    .{ .name = "lockout-duration", .target = "auth.lockout_duration", .help = "temporary lockout in seconds" },
    .{ .name = "lockout-threshold", .target = "auth.lockout_threshold", .help = "account failures before lockout" },
    .{ .name = "ip-lockout-threshold", .target = "auth.ip_lockout_threshold", .help = "IP failures before lockout" },
    .{ .name = "no-rate-limit", .target = "auth.rate_limit", .flag = false, .help = "disable auth rate limiting" },
    .{ .name = "enable-registration", .target = "auth.registration", .flag = true, .help = "enable in-band registration" },
    .{ .name = "no-require-invite", .target = "auth.require_invite", .flag = false, .help = "allow registration without an invite" },
    .{ .name = "users-scan-limit", .target = "auth.users_scan_limit", .help = "startup users scan bound" },
    .{ .name = "conf-fd", .target = "meta.conf_fd", .help = "inherited sealed config fd" },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"}, .help = "show this help" },
};

/// Every CLI spelling xmppd-auth-oidc accepts. An explicit --socket wins
/// over both the file and forwarded values; otherwise oidc.socket inherits
/// auth.socket when empty.
pub const oidc_cli = [_]conf.CliSpec{
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"}, .help = "config file path" },
    .{ .name = "db", .target = "server.db_path", .help = "storage base directory" },
    .{ .name = "socket", .target = "oidc.socket", .help = "auth IPC socket path" },
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
pub const AuthLoader = conf.Loader(Sections, &file_spec, &auth_cli, .{});
pub const OidcLoader = conf.Loader(Sections, &file_spec, &oidc_cli, .{});
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

/// The socket xmppd-auth-oidc listens on. An unset OIDC-specific socket
/// inherits the shared auth endpoint; an explicit file, forwarded or CLI
/// value wins in that order through the loader.
pub fn oidcSocket(values: *const Sections) []const u8 {
    return if (values.oidc.socket.len != 0) values.oidc.socket else values.auth.socket;
}

/// Records a semantic field error at the same file location the loader
/// would use for a parse error. `path` is the file loaded by the caller;
/// forwarded and CLI-only failures may have no path or line.
pub fn failField(
    loader: anytype,
    path: ?[]const u8,
    diag: *conf.Diag,
    comptime section: []const u8,
    comptime field: []const u8,
    detail: []const u8,
) error{BadValue} {
    const from_file = loader.provenanceOf(section, field) == .file;
    diag.set(.{
        .path = if (from_file) path orelse "" else "",
        .line = if (from_file) loader.lineOf(section, field) else 0,
        .section = section,
        .key = field,
        .detail = detail,
    });
    return error.BadValue;
}

fn validateRateMax(loader: anytype, path: ?[]const u8, diag: *conf.Diag, comptime section: []const u8, comptime field: []const u8) error{BadValue}!void {
    if (@field(@field(loader.values, section), field) > std.math.maxInt(u16)) {
        return failField(loader, path, diag, section, field, "rate maximum exceeds 65535");
    }
}

/// Validates the F7 handshake-pool bounds. The queue minimum is structural:
/// submission uses one queue slot as the cross-thread ownership handoff even
/// when an active slot is free, so zero would start a pool that admits nothing.
pub fn validateTlsHandshakePool(loader: anytype, path: ?[]const u8, diag: *conf.Diag) error{BadValue}!void {
    switch (loader.values.tls.handshake_threads) {
        .num => |n| if (n == 0) return failField(loader, path, diag, "tls", "handshake_threads", "handshake lanes must be at least one"),
        .kw => {},
    }
    if (loader.values.tls.handshake_concurrency == 0) {
        return failField(loader, path, diag, "tls", "handshake_concurrency", "active handshakes per lane must be at least one");
    }
    if (loader.values.tls.handshake_queue == 0) {
        return failField(loader, path, diag, "tls", "handshake_queue", "queued handoffs per lane must be at least one");
    }
    if (loader.values.tls.handshake_timeout_ms == 0) {
        return failField(loader, path, diag, "tls", "handshake_timeout_ms", "handshake deadline must be at least one millisecond");
    }
}

/// Validates values RateLimiter would otherwise clamp and returns the
/// lockout in its native whole-second unit.
pub fn validateAuthRate(loader: anytype, path: ?[]const u8, diag: *conf.Diag) error{BadValue}!u32 {
    try validateRateMax(loader, path, diag, "auth", "max_per_account");
    try validateRateMax(loader, path, diag, "auth", "max_per_ip");
    if (loader.values.auth.window_seconds == 0) {
        return failField(loader, path, diag, "auth", "window_seconds", "rate window must be at least one second");
    }
    const ms = loader.values.auth.lockout_duration.ms;
    if (ms % 1000 != 0) {
        return failField(loader, path, diag, "auth", "lockout_duration", "lockout must use whole seconds");
    }
    const seconds = ms / 1000;
    if (seconds > std.math.maxInt(u32)) {
        return failField(loader, path, diag, "auth", "lockout_duration", "lockout exceeds the u32 second range");
    }
    return @intCast(seconds);
}

/// OIDC shares the auth policy and additionally validates its legacy maxima.
pub fn validateOidcRate(loader: anytype, path: ?[]const u8, diag: *conf.Diag) error{BadValue}!u32 {
    const seconds = try validateAuthRate(loader, path, diag);
    try validateRateMax(loader, path, diag, "oidc", "max_per_account");
    try validateRateMax(loader, path, diag, "oidc", "max_per_ip");
    return seconds;
}

/// Converts the LMDB map size without allowing a configured overflow.
pub fn mapSizeBytes(loader: anytype, path: ?[]const u8, diag: *conf.Diag) error{BadValue}!usize {
    return std.math.mul(usize, loader.values.server.lmdb_map_size_mb, 1024 * 1024) catch {
        return failField(loader, path, diag, "server", "lmdb_map_size_mb", "map size overflows addressable bytes");
    };
}

/// The master forwards every field, including defaults. Preserve the OIDC
/// rule that explicitly configured shared auth maxima beat the OIDC aliases
/// by resolving them into the OIDC view before the blob is sealed.
pub fn normalizeForwardedOidcRates(loader: anytype) void {
    if (loader.provenanceOf("auth", "max_per_account") != .default) {
        loader.values.oidc.max_per_account = loader.values.auth.max_per_account;
    }
    if (loader.provenanceOf("auth", "max_per_ip") != .default) {
        loader.values.oidc.max_per_ip = loader.values.auth.max_per_ip;
    }
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

test "auth defaults and every CLI spelling match the daemon contract" {
    var diag: conf.Diag = .{};
    var l = try AuthLoader.load(testing.allocator, .{ .args = &.{
        "--config",               "a.ini",                 "--db",                "/cli/db",            "--socket",               "/cli/auth.sock",
        "--max-auth-per-account", "9",                     "--max-auth-per-ip",   "30",                 "--auth-window",          "90",
        "--lockout-duration",     "900",                   "--lockout-threshold", "3",                  "--ip-lockout-threshold", "4",
        "--no-rate-limit",        "--enable-registration", "--no-require-invite", "--users-scan-limit", "500",                    "--conf-fd",
        "7",                      "--help",
    } }, &diag);
    defer l.deinit();

    try testing.expectEqualStrings("/cli/db", l.values.server.db_path);
    try testing.expectEqualStrings("/cli/auth.sock", l.values.auth.socket);
    try testing.expectEqual(@as(u32, 9), l.values.auth.max_per_account);
    try testing.expectEqual(@as(u32, 30), l.values.auth.max_per_ip);
    try testing.expectEqual(@as(u32, 90), l.values.auth.window_seconds);
    try testing.expectEqual(@as(u64, 900_000), l.values.auth.lockout_duration.ms);
    try testing.expectEqual(@as(u16, 3), l.values.auth.lockout_threshold);
    try testing.expectEqual(@as(u16, 4), l.values.auth.ip_lockout_threshold);
    try testing.expectEqual(@as(usize, 500), l.values.auth.users_scan_limit);
    try testing.expect(!l.values.auth.rate_limit);
    try testing.expect(l.values.auth.registration);
    try testing.expect(!l.values.auth.require_invite);
    try testing.expectEqual(@as(i32, 7), l.values.meta.conf_fd);
    try testing.expect(l.values.meta.help);
    try testing.expectEqual(@as(u32, 900), try validateAuthRate(&l, null, &diag));

    var defaults = AuthLoader.init(testing.allocator);
    defer defaults.deinit();
    try testing.expectEqualStrings("/var/db/xmppd", defaults.values.server.db_path);
    try testing.expectEqual(@as(u32, 4), defaults.values.auth.crypto_threads);
    try testing.expectEqualStrings("/var/run/xmppd/auth.sock", oidcSocket(&defaults.values));
}

fn expectHelpCoversCli(comptime specs: []const conf.CliSpec, loader: anytype) !void {
    var help_buf: [32768]u8 = undefined;
    var w: std.Io.Writer = .fixed(&help_buf);
    try loader.writeHelp(&w);
    const help = w.buffered();
    inline for (specs) |spec| {
        var name_buf: [128]u8 = undefined;
        const long = try std.fmt.bufPrint(&name_buf, "--{s}", .{spec.name});
        try testing.expect(std.mem.indexOf(u8, help, long) != null);
        for (spec.aliases) |alias| {
            const short = try std.fmt.bufPrint(&name_buf, "-{s}", .{alias});
            try testing.expect(std.mem.indexOf(u8, help, short) != null);
        }
    }
}

test "generated auth help covers every schema CLI spelling" {
    var auth = AuthLoader.init(testing.allocator);
    defer auth.deinit();
    try expectHelpCoversCli(&auth_cli, &auth);

    var oidc = OidcLoader.init(testing.allocator);
    defer oidc.deinit();
    try expectHelpCoversCli(&oidc_cli, &oidc);
}

test "auth forwarded values beat the file and lose to CLI flags" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "auth.ini", "[server]\ndb_path = /file/db\n[auth]\nmax_per_account = 10\n", &path_buf);
    const blob = "--server.db_path=/fwd/db\n--auth.max_per_account=20\n";

    var diag: conf.Diag = .{};
    var forwarded = try AuthLoader.load(testing.allocator, .{
        .path = path,
        .conf_fd = (try conf.ConfFd.create(blob)).fd,
    }, &diag);
    defer forwarded.deinit();
    try testing.expectEqualStrings("/fwd/db", forwarded.values.server.db_path);
    try testing.expectEqual(@as(u32, 20), forwarded.values.auth.max_per_account);

    var cli = try AuthLoader.load(testing.allocator, .{
        .path = path,
        .conf_fd = (try conf.ConfFd.create(blob)).fd,
        .args = &.{ "--db", "/cli/db", "--max-auth-per-account", "30" },
    }, &diag);
    defer cli.deinit();
    try testing.expectEqualStrings("/cli/db", cli.values.server.db_path);
    try testing.expectEqual(@as(u32, 30), cli.values.auth.max_per_account);
    try testing.expectEqual(.cli, cli.provenanceOf("auth", "max_per_account"));
}

test "OIDC aliases load and shared auth maxima normalize into the forwarded view" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "oidc.ini", "[oidc]\nrate_max_per_account = 42\nrate_max_per_ip = 77\nsocket = /run/oidc.sock\n", &path_buf);

    var diag: conf.Diag = .{};
    var aliases = try OidcLoader.load(testing.allocator, .{ .path = path }, &diag);
    defer aliases.deinit();
    try testing.expectEqual(@as(u32, 42), aliases.values.oidc.max_per_account);
    try testing.expectEqual(@as(u32, 77), aliases.values.oidc.max_per_ip);
    try testing.expectEqualStrings("/run/oidc.sock", oidcSocket(&aliases.values));

    var parent = try MasterLoader.load(testing.allocator, .{ .path = path, .args = &.{"--auth.max_per_account=7"} }, &diag);
    defer parent.deinit();
    normalizeForwardedOidcRates(&parent);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const blob = try parent.forwardBlob(arena.allocator(), &diag);
    var child = try OidcLoader.load(testing.allocator, .{ .conf_fd = (try conf.ConfFd.create(blob)).fd }, &diag);
    defer child.deinit();
    try testing.expectEqual(@as(u32, 7), child.values.oidc.max_per_account);
    try testing.expectEqual(@as(u32, 77), child.values.oidc.max_per_ip);
}

test "semantic rate and map-size errors keep their file location" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "bad-rate.ini", "[auth]\nwindow_seconds = 0\n", &path_buf);
    var diag: conf.Diag = .{};
    var l = try AuthLoader.load(testing.allocator, .{ .path = path }, &diag);
    defer l.deinit();
    try testing.expectError(error.BadValue, validateAuthRate(&l, path, &diag));
    try testing.expectEqual(@as(u32, 2), diag.line);
    try testing.expectEqualStrings("window_seconds", diag.key);

    const huge = try std.fmt.allocPrint(testing.allocator, "[server]\nlmdb_map_size_mb = {d}\n", .{std.math.maxInt(usize)});
    defer testing.allocator.free(huge);
    const map_path = try writeTempConfig(&tmp.dir, "bad-map.ini", huge, &path_buf);
    var map = try AuthLoader.load(testing.allocator, .{ .path = map_path }, &diag);
    defer map.deinit();
    try testing.expectError(error.BadValue, mapSizeBytes(&map, map_path, &diag));
    try testing.expectEqual(@as(u32, 2), diag.line);
}

test "TLS handshake pool rejects a zero handoff queue with its file location" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "bad-pool.ini", "[tls]\nhandshake_queue = 0\n", &path_buf);
    var diag: conf.Diag = .{};
    var l = try CoreLoader.load(testing.allocator, .{ .path = path }, &diag);
    defer l.deinit();

    try testing.expectError(error.BadValue, validateTlsHandshakePool(&l, path, &diag));
    try testing.expectEqual(@as(u32, 2), diag.line);
    try testing.expectEqualStrings("handshake_queue", diag.key);
}
