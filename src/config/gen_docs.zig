//! gen_docs: renders doc/CONFIGURATION.md from the ADR-9 schema
//! (src/config/schema.zig). The file-key tables come from file_spec and
//! the defaults from the Sections field initializers, so the doc cannot
//! drift from what every daemon's lib/conf loader accepts.
//!
//! `zig build docs-config` runs this with the output path as argv[1]
//! (default doc/CONFIGURATION.md). `--check PATH` renders in memory and
//! exits nonzero when the file on disk differs, without writing.

const std = @import("std");
const conf = @import("conf");
const schema = @import("schema");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const args = try std.process.argsAlloc(gpa);

    var check = false;
    var path: []const u8 = "doc/CONFIGURATION.md";
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--check")) {
            check = true;
        } else {
            path = args[i];
        }
    }

    var buf: [96 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try render(gpa, &w);
    const rendered = w.buffered();

    if (check) {
        const on_disk = std.fs.cwd().readFileAlloc(gpa, path, 1 << 20) catch |err| {
            std.debug.print("docs-config --check: cannot read {s}: {}\n", .{ path, err });
            return error.CheckFailed;
        };
        if (!std.mem.eql(u8, on_disk, rendered)) {
            std.debug.print(
                "docs-config --check: {s} is stale; regenerate with `zig build docs-config`\n",
                .{path},
            );
            return error.CheckFailed;
        }
        return;
    }

    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = rendered });
    std.debug.print("wrote {s} ({d} bytes)\n", .{ path, rendered.len });
}

/// The file-key spelling: an explicit key override or the field name.
fn fileKey(comptime f: conf.FieldSpec) []const u8 {
    return if (f.key.len != 0) f.key else f.field;
}

/// True when the section holds at least one file key; sections that are
/// all CLI-only (ctl, meta) get no table.
fn sectionHasFileKeys(comptime name: []const u8) bool {
    for (schema.file_spec) |f| {
        if (f.in_file and std.mem.eql(u8, f.section, name)) return true;
    }
    return false;
}

/// The default-column cell for one field: an explicit doc_default for
/// non-literal defaults, "(required)" for daemon-enforced presence, else
/// the Sections field initializer.
fn writeDefaultCell(comptime f: conf.FieldSpec, w: *std.Io.Writer) std.Io.Writer.Error!void {
    if (f.required) return w.writeAll("(required)");
    if (f.doc_default.len != 0) return w.writeAll(f.doc_default);
    const v = @field(@field(schema.Sections{}, f.section), f.field);
    return writeValue(@TypeOf(v), w, v);
}

/// Canonical spelling of a field value, mirroring conf.writeValue's
/// dispatch for the types the schema uses.
fn writeValue(comptime T: type, w: *std.Io.Writer, v: T) std.Io.Writer.Error!void {
    if (T == []const u8) {
        if (v.len == 0) return w.writeAll("(none)");
        return w.print("`{s}`", .{v});
    }
    if (T == bool) return w.print("`{s}`", .{if (v) "true" else "false"});
    if (T == [][]const u8) {
        try w.writeByte('`');
        for (v, 0..) |item, i| {
            if (i != 0) try w.writeByte(',');
            try w.writeAll(item);
        }
        return w.writeByte('`');
    }
    switch (@typeInfo(T)) {
        .int => return w.print("`{d}`", .{v}),
        .@"enum" => return w.print("`{s}`", .{@tagName(v)}),
        .@"union" => {
            // IntOr and friends bring their own writer, called the same
            // way conf.writeValue calls it.
            try w.writeByte('`');
            try v.write(w);
            return w.writeByte('`');
        },
        .@"struct" => {
            // Duration and friends render through {f} (their canonical
            // form: 5m, 300s, ...).
            if (@hasDecl(T, "format")) return w.print("`{f}`", .{v});
            @compileError("gen_docs: no default rendering for " ++ @typeName(T));
        },
        else => @compileError("gen_docs: no default rendering for " ++ @typeName(T)),
    }
}

fn writeSectionTable(comptime name: []const u8, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll("| Key | Default | Used by | Description |\n");
    try w.writeAll("|-----|---------|---------|-------------|\n");
    inline for (schema.file_spec) |f| {
        if (!f.in_file or !std.mem.eql(u8, f.section, name)) {
            // CLI-only or other section: no table row.
        } else {
            try w.print("| `{s}` | ", .{fileKey(f)});
            try writeDefaultCell(f, w);
            try w.writeAll(" | ");
            try w.writeAll(if (f.used_by.len != 0) f.used_by else "(none yet)");
            try w.writeAll(" | ");
            try w.writeAll(if (f.doc.len != 0) f.doc else f.help);
            switch (f.aliases.len) {
                0 => {},
                1 => try w.print(" (alias `{s}`)", .{f.aliases[0]}),
                else => {
                    try w.writeAll(" (aliases ");
                    for (f.aliases, 0..) |a, i| {
                        if (i != 0) try w.writeAll(", ");
                        try w.print("`{s}`", .{a});
                    }
                    try w.writeByte(')');
                },
            }
            try w.writeAll(" |\n");
        }
    }
    try w.writeByte('\n');
}

/// Names the in_file = false fields of a section as CLI-only.
fn writeCliOnlyNote(comptime name: []const u8, w: *std.Io.Writer) std.Io.Writer.Error!void {
    var count: usize = 0;
    for (schema.file_spec) |f| {
        if (!f.in_file and std.mem.eql(u8, f.section, name)) count += 1;
    }
    if (count == 0) return;
    var first = true;
    inline for (schema.file_spec) |f| {
        if (!f.in_file and std.mem.eql(u8, f.section, name)) {
            if (!first) try w.writeAll(" and ");
            try w.print("`{s}`", .{fileKey(f)});
            first = false;
        }
    }
    if (count == 1) {
        try w.writeAll(" is CLI-only: a file key naming it is an unknown-key error.\n\n");
    } else {
        try w.writeAll(" are CLI-only: a file key naming one is an unknown-key error.\n\n");
    }
}

/// Writes `writeHelp` output for one loader. When `full` is false the
/// "File keys:" tail (identical for every daemon) is cut.
fn writeDaemonHelp(
    alloc: std.mem.Allocator,
    comptime L: type,
    comptime full: bool,
    w: *std.Io.Writer,
) !void {
    var gen = L.init(alloc);
    defer gen.deinit();
    var buf: [48 * 1024]u8 = undefined;
    var hw: std.Io.Writer = .fixed(&buf);
    try gen.writeHelp(&hw);
    var help = hw.buffered();
    if (!full) {
        const cut = std.mem.indexOf(u8, help, "File keys:") orelse help.len;
        help = help[0..cut];
    }
    try w.writeAll(help);
}

pub fn render(alloc: std.mem.Allocator, w: *std.Io.Writer) !void {
    try w.writeAll(header);
    comptime var i: usize = 0;
    inline while (i < schema.file_spec.len) : (i += 1) {
        const f = schema.file_spec[i];
        const first = i == 0 or !std.mem.eql(u8, f.section, schema.file_spec[i - 1].section);
        if (first and sectionHasFileKeys(f.section)) {
            try w.print("### [{s}]\n\n", .{f.section});
            if (comptime std.mem.eql(u8, f.section, "oidc")) {
                try w.writeAll("Required when `[master] auth_path` points at " ++
                    "xmppd-auth-oidc; ignored otherwise.\n\n");
            }
            try writeSectionTable(f.section, w);
            try writeCliOnlyNote(f.section, w);
            if (comptime std.mem.eql(u8, f.section, "oidc")) {
                try w.writeAll(oidc_extras);
            }
        }
    }
    try w.writeAll(cli_intro);
    try w.writeAll("### xmppd (master)\n\n```\n");
    try writeDaemonHelp(alloc, schema.MasterLoader, true, w);
    try w.writeAll("```\n\n");
    inline for (.{
        .{ "xmppd-core", schema.CoreLoader },
        .{ "xmppd-s2s", schema.S2sLoader },
        .{ "xmppd-auth", schema.AuthLoader },
        .{ "xmppd-auth-oidc", schema.OidcLoader },
        .{ "xmppctl", schema.CtlLoader },
    }) |d| {
        try w.print("### {s}\n\n```\n", .{d[0]});
        try writeDaemonHelp(alloc, d[1], false, w);
        try w.writeAll("```\n\n");
        if (comptime std.mem.eql(u8, d[0], "xmppd-auth-oidc")) {
            try w.writeAll(oidc_cli_note);
        }
        if (comptime std.mem.eql(u8, d[0], "xmppctl")) {
            try w.writeAll(ctl_cli_note);
        }
    }
    try w.writeAll(footer);
}

const header =
    \\# xmppd Configuration
    \\
    \\<!-- Generated by `zig build docs-config` from src/config/schema.zig. Do not edit. -->
    \\
    \\All configuration lives in a single INI file shared by every daemon, selected
    \\with `--config PATH` (`-c`). `xmppd-auth-oidc` defaults to
    \\`/usr/local/etc/xmppd/xmppd.conf` when `--config` is absent. Precedence is
    \\default < file < CLI, tracked per field, with the master's resolved values
    \\forwarded to its children in between (see "Config forwarding" below). An
    \\unknown section or key, a bad value, or a malformed line is a startup error
    \\that names the file and line; defaults live only in the schema
    \\(`src/config/schema.zig`), so `xmppd --help` is the authoritative option
    \\list.
    \\
    \\## File keys
    \\
    \\Every key the shared file may carry, grouped by section. Fields that
    \\take no file key (`in_file = false` in the schema) are CLI-only and
    \\listed under the daemon that accepts them.
    \\
    \\
;

const oidc_extras =
    \\#### Account binding
    \\
    \\XMPP accounts bind permanently to the `(iss, sub)` pair (OIDC Core 5.7):
    \\once a subject logs in, its mapping in `{db}/auth` (`oidc_identities`
    \\namespace) decides the account forever, and renamed IdP claims cannot
    \\re-map it. The `localpart_claim` value is only a first-login
    \\*suggestion*: it never binds identity. The suggestion is prepared with
    \\the same RFC 7622 UsernameCaseMapped localpart function as registration
    \\(`NaplesTB` suggests `naplestb`), so two different claims that prepare to
    \\one localpart collide and the second is refused. A suggestion is refused
    \\when the localpart is already bound to another subject, when a provisioned
    \\`users` row exists, or when the account already owns roster, archive or
    \\MUC data (upgrade installs must run `xmppctl oidc-unclaimed` and
    \\`oidc-link` first; see UPGRADING.md). `localpart_claim = email` is
    \\accepted only when the IdP reports `email_verified = true` and is the
    \\weakest choice because email is editable at most IdPs. Setting
    \\`localpart_claim` to an empty string disables auto-provisioning
    \\entirely: every account then needs an explicit `xmppctl oidc-link`.
    \\Local registration runs the reverse index too: XEP-0077 registration and
    \\`xmppctl add` refuse a localpart bound to a subject (`conflict`, and a
    \\bound-localpart error at the ctl) instead of attaching a password
    \\credential to the bound account.
    \\
    \\Claiming a localpart is a conditional write that must hold against every
    \\process that can open `{db}/auth` (`xmppd-auth-oidc`, the core daemon,
    \\`xmppctl`, and any second auth daemon). Only the LMDB and SQLite
    \\backends serialize that check across processes; RocksDB orders
    \\`putIfAbsent` with an in-process mutex, so `xmppd-auth-oidc` refuses to
    \\start when the operational storage backend is RocksDB. OIDC account
    \\binding requires `-Dop-storage=lmdb` (the default) or
    \\`-Dop-storage=sqlite`.
    \\
    \\| IdP | Recommended keys | Notes |
    \\|-----|------------------|-------|
    \\| identity-oidc | `localpart_claim = sub`, `localpart_claim_prefix = user:` | While subject IDs are handle-form (`user:name`), strip the prefix. After identityd issue #52 lands opaque subjects, use an admin-controlled preferred username instead. |
    \\| Rauthy | `localpart_claim = preferred_username` | Safe only with immutable usernames and controlled provisioning. `email` is unsafe: it is user-editable and `email_fallback` makes it self-selected. |
    \\| Keycloak | `localpart_claim = preferred_username` | Safe only when username edits are forbidden and provisioning is controlled. Otherwise use `localpart_claim =` (empty) plus operator links. |
    \\
    \\
;

const cli_intro =
    \\## Example
    \\
    \\```ini
    \\[server]
    \\hostname = example.com
    \\user = jabber
    \\db_path = /var/db/xmppd
    \\log_file = /var/log/xmppd/xmppd.log
    \\
    \\[tls]
    \\cert = /usr/local/etc/xmppd/fullchain.pem
    \\key = /usr/local/etc/xmppd/privkey.pem
    \\
    \\[core]
    \\max_sessions = 4096
    \\
    \\[muc]
    \\host = conference.example.com
    \\
    \\[master]
    \\core_path = /usr/local/libexec/xmppd/xmppd-core
    \\auth_path = /usr/local/libexec/xmppd/xmppd-auth
    \\```
    \\
    \\## OIDC Example
    \\
    \\```ini
    \\[master]
    \\auth_path = /usr/local/libexec/xmppd/xmppd-auth-oidc
    \\
    \\[oidc]
    \\issuer = https://auth.example.com/auth/v1/
    \\client_id = xmppd
    \\client_secret = your-client-secret
    \\token_endpoint = https://auth.example.com/auth/v1/oidc/token
    \\jwks_uri = https://auth.example.com/auth/v1/oidc/certs
    \\user_domain = example.com
    \\ca_file = /usr/local/etc/xmppd/ca-bundle.pem
    \\```
    \\
    \\## CLI Flags
    \\
    \\All binaries accept `--config PATH` (`-c`) to specify the config file
    \\location. Each `--help` below is produced by the shared loader from
    \\the same schema, so it cannot drift from what the parser accepts.
    \\Only the master prints the file-key table after its options; the
    \\list is the shared grammar above and is identical for every daemon.
    \\
    \\
;

const oidc_cli_note =
    \\Without `--config` or `--conf-fd`, xmppd-auth-oidc reads
    \\`/usr/local/etc/xmppd/xmppd.conf`.
    \\
    \\
;

const ctl_cli_note =
    \\`xmppctl` also takes subcommand positionals it pre-scans itself:
    \\`--hosted-domain` (repeatable, a list the schema cannot express) and
    \\`--rename OLD NEW` (two values). A subcommand that is not a known
    \\verb is a usage error.
    \\
    \\
;

const footer =
    \\Unknown arguments, unknown file keys, malformed lines, non-numeric values,
    \\and values outside the consuming daemon's bounds are startup errors with a
    \\`file:line` diagnostic when they came from a file. Rate maxima above 65535,
    \\a zero rate window, and a lockout that is not a whole number of seconds are
    \\errors rather than values to clamp or replace with defaults.
    \\
    \\## Config forwarding
    \\
    \\The master forwards the *resolved* values to every child. After loading
    \\the file and its own CLI it serializes the effective fields once into a
    \\sealed in-memory fd that `xmppd-auth` (either backend), `xmppd-core`, and
    \\`xmppd-s2s` inherit through the supervisor's `pass_fds` remap, named on
    \\their argv as `--conf-fd N`. Their precedence is therefore
    \\default < file < forwarded < CLI: a file key or a master CLI flag
    \\(`xmppd -c xmppd.conf --host x.test`) reaches every child exactly once,
    \\and a child-side CLI flag still wins for a manual run. Child argv carries
    \\only fd remap slots (`--listen-fd` where applicable and `--conf-fd`). A
    \\child started by hand without `--conf-fd` reads `--config` directly. On
    \\SIGHUP the master rebuilds the fd from the reloaded configuration before
    \\forwarding the signal, so a respawned child sees the new values; no
    \\supervised child re-reads the file.
    \\
;

test "doc/CONFIGURATION.md is generated and current" {
    var buf: [96 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try render(std.testing.allocator, &w);
    // Run artifacts execute from the build root.
    const on_disk = try std.fs.cwd().readFileAlloc(
        std.testing.allocator, "doc/CONFIGURATION.md", 1 << 20);
    defer std.testing.allocator.free(on_disk);
    std.testing.expectEqualStrings(on_disk, w.buffered()) catch {
        std.debug.print(
            "doc/CONFIGURATION.md is stale; regenerate with `zig build docs-config`\n",
            .{},
        );
        return error.TestExpectedEqual;
    };
}
