//! lib/conf: typed configuration for xmppd daemons (ADR-9).
//!
//! A daemon declares section structs whose field initializers are the only
//! defaults, a `fields` table mapping each field to its INI key, and a `cli`
//! table mapping CLI spellings to fields. The shared file grammar lets one
//! config file serve every daemon, while each daemon gets its own CLI map
//! (the same file key may be `--socket` to one daemon and `--auth-socket`
//! to another).
//!
//! Precedence is default < file < CLI, recorded per field as provenance.
//! An unknown section, unknown key, bad value or malformed line is an
//! operating error carrying file:line (or the CLI spelling) in Diag;
//! nothing ever falls back silently to a default.
//!
//! Bounded: file size, line length and key count have hard caps. One arena
//! per load owns the file bytes; values borrow from them, so a loaded
//! config is freed by one deinit.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub const max_file_bytes = 1 << 20;
pub const max_line_bytes = 1024;
pub const default_max_keys = 2048;

/// Where a field's effective value came from.
/// file < forwarded < cli: a value forwarded over the sealed conf fd
/// loses to a real CLI flag but still beats the config file.
pub const Source = enum { default, file, forwarded, cli };

/// One configurable field and its INI spelling.
pub const FieldSpec = struct {
    /// INI section name; also the field name in the sections struct.
    section: []const u8,
    /// Field name inside that section struct.
    field: []const u8,
    /// INI key spelling; defaults to `field` when empty.
    key: []const u8 = "",
    /// False for fields reachable only through CLI (no file key), e.g.
    /// --run-dir, --background, --listen-fd.
    in_file: bool = true,
    /// Old spellings still accepted for this key.
    aliases: []const []const u8 = &.{},
    /// One-line description for generated --help.
    help: []const u8 = "",
};

/// One CLI spelling bound to a field.
pub const CliSpec = struct {
    /// Spelling without leading dashes; both --name and -name are accepted.
    name: []const u8,
    /// "section.field" the option writes.
    target: []const u8,
    /// Alternate spellings (short or legacy forms).
    aliases: []const []const u8 = &.{},
    /// When set, the option takes no value and writes this bool into the
    /// (bool-typed) target, e.g. "--no-tls" writes false.
    flag: ?bool = null,
    /// One-line description for generated --help.
    help: []const u8 = "",
};

pub const Error = error{
    FileNotFound,
    ReadFailed,
    FileTooLarge,
    LineTooLong,
    TooManyKeys,
    UnknownSection,
    UnknownKey,
    DuplicateKey,
    MalformedLine,
    BadValue,
    UnknownArgument,
    MissingValue,
    FlagTakesNoValue,
    UnexpectedPositional,
    /// A serialized field did not fit the serializer's scratch buffer.
    ValueTooLong,
    /// The inherited conf fd is below the remap range or not fully
    /// sealed.
    UnsealedFd,
    OutOfMemory,
};

/// Location and context of a config failure; filled by loaders before they
/// return an error so callers can print "path:line: ..." diagnostics.
/// Field slices point into the Diag's own storage, set by `set`, so a
/// Diag outlives the argv, file text or temp buffer it describes.
pub const Diag = struct {
    /// Config file path; empty when the error is about a CLI argument.
    path: []const u8 = "",
    /// 1-based file line; 0 for CLI errors.
    line: u32 = 0,
    /// INI section of the offending key.
    section: []const u8 = "",
    /// Key or CLI spelling involved.
    key: []const u8 = "",
    /// The offending value, if any.
    value: []const u8 = "",
    /// Static detail, e.g. "expected integer".
    detail: []const u8 = "",

    path_buf: [4096]u8 = undefined,
    section_buf: [64]u8 = undefined,
    key_buf: [128]u8 = undefined,
    value_buf: [512]u8 = undefined,
    detail_buf: [256]u8 = undefined,

    pub const Parts = struct {
        path: []const u8 = "",
        line: u32 = 0,
        section: []const u8 = "",
        key: []const u8 = "",
        value: []const u8 = "",
        detail: []const u8 = "",
    };

    fn into(dst: []u8, s: []const u8) []const u8 {
        const n = @min(dst.len, s.len);
        if (n == 0) return dst[0..0];
        const ds = @intFromPtr(dst.ptr);
        const ss = @intFromPtr(s.ptr);
        if (ss >= ds and ss < ds + dst.len) {
            // s aliases dst, e.g. set() fed a Diag field back into its
            // own buffer; the source sits above the destination, so a
            // forward copy is shift-safe where @memcpy would panic.
            std.mem.copyForwards(u8, dst[0..n], s[0..n]);
        } else {
            @memcpy(dst[0..n], s[0..n]);
        }
        return dst[0..n];
    }

    /// Copies every field into the Diag's own buffers (truncating past
    /// the bound) so no slice ever borrows caller memory.
    pub fn set(self: *Diag, parts: Parts) void {
        self.* = .{ .line = parts.line };
        self.path = into(&self.path_buf, parts.path);
        self.section = into(&self.section_buf, parts.section);
        self.key = into(&self.key_buf, parts.key);
        self.value = into(&self.value_buf, parts.value);
        self.detail = into(&self.detail_buf, parts.detail);
    }

    /// Repoints every field slice into this Diag's own buffers. A plain
    /// struct copy leaves the slices addressing the original's storage;
    /// call this once after copying so the two Diags are independent.
    pub fn rebind(self: *Diag) void {
        self.path = into(&self.path_buf, self.path);
        self.section = into(&self.section_buf, self.section);
        self.key = into(&self.key_buf, self.key);
        self.value = into(&self.value_buf, self.value);
        self.detail = into(&self.detail_buf, self.detail);
    }

    pub fn format(self: Diag, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.line != 0) {
            try w.print("{s}:{d}: ", .{ self.path, self.line });
        } else if (self.path.len != 0) {
            try w.print("{s}: ", .{self.path});
        }
        if (self.section.len != 0) {
            try w.print("[{s}] ", .{self.section});
        }
        if (self.key.len != 0) {
            try w.print("key '{s}': ", .{self.key});
        }
        try w.print("{s}", .{self.detail});
        if (self.value.len != 0) {
            try w.print(" ('{s}')", .{self.value});
        }
    }
};

pub const ParseError = error{BadValue};

/// Parses one string into a field value. Supported T: []const u8 (borrowed
/// slice, never copied), bool, any integer type, enum (exact tag), Duration,
/// std.net.Address (IP literal, optional :port; no DNS).
pub fn parseValue(comptime T: type, s: []const u8) ParseError!T {
    if (T == []const u8) return s;
    if (T == bool) return parseBool(s);
    if (T == Duration) return Duration.parse(s);
    if (T == std.net.Address) {
        if (std.net.Address.parseIpAndPort(s)) |a| {
            return a;
        } else |_| {}
        const a = std.net.Address.parseIp(s, 0) catch return error.BadValue;
        // A "::"-compressed literal ending in :digits is ambiguous with
        // an unbracketed v6:port ("::1:5222"); require "[v6]:port".
        if (std.mem.indexOf(u8, s, "::") != null) {
            if (std.mem.lastIndexOfScalar(u8, s, ':')) |i| {
                const last = s[i + 1 ..];
                var digits = last.len != 0;
                for (last) |c| {
                    if (!std.ascii.isDigit(c)) digits = false;
                }
                if (digits) {
                    if (std.net.Address.parseIp(s[0..i], 0)) |_| {
                        return error.BadValue;
                    } else |_| {}
                }
            }
        }
        return a;
    }
    switch (@typeInfo(T)) {
        .int => |i| {
            _ = i;
            return std.fmt.parseInt(T, s, 10) catch error.BadValue;
        },
        .@"enum" => return std.meta.stringToEnum(T, s) orelse error.BadValue,
        .@"union" => {
            // IntOr(K) and friends must bring their own parser; the check
            // stays inline because a helper call loses comptime decls.
            if (!@hasDecl(T, "parse")) @compileError("conf.parseValue: unsupported union " ++ @typeName(T));
            return T.parse(s);
        },
        else => @compileError("conf.parseValue: unsupported type " ++ @typeName(T)),
    }
}

fn parseBool(s: []const u8) ParseError!bool {
    if (std.ascii.eqlIgnoreCase(s, "true")) return true;
    if (std.ascii.eqlIgnoreCase(s, "false")) return false;
    if (std.ascii.eqlIgnoreCase(s, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(s, "no")) return false;
    if (std.ascii.eqlIgnoreCase(s, "on")) return true;
    if (std.ascii.eqlIgnoreCase(s, "off")) return false;
    if (std.mem.eql(u8, s, "1")) return true;
    if (std.mem.eql(u8, s, "0")) return false;
    return error.BadValue;
}

/// A field type that is either an integer or one keyword from K, e.g.
/// `workers = auto` or `workers = 8`. Carries its own parse/write so
/// parseValue needs no comptime introspection of the union.
pub fn IntOr(comptime K: type) type {
    if (@typeInfo(K) != .@"enum") @compileError("conf.IntOr: keyword set must be an enum");
    return union(enum) {
        kw: K,
        num: i64,

        pub fn parse(s: []const u8) ParseError!@This() {
            // Strict plain decimal: digits only, no sign, underscores or
            // leading zeros; anything else must be a keyword.
            var numeric = s.len != 0;
            for (s) |c| {
                if (!std.ascii.isDigit(c)) numeric = false;
            }
            if (numeric and (s.len == 1 or s[0] != '0')) {
                const n = std.fmt.parseInt(i64, s, 10) catch return error.BadValue;
                return .{ .num = n };
            }
            const kw = std.meta.stringToEnum(K, s) orelse return error.BadValue;
            return .{ .kw = kw };
        }

        pub fn write(self: @This(), w: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (self) {
                .kw => |k| try w.writeAll(@tagName(k)),
                .num => |n| try w.print("{d}", .{n}),
            }
        }
    };
}

/// Max items in one comma-separated list value (matches the 64-fd
/// --listen-fd ceiling).
pub const list_max_items: usize = 64;

/// Splits a comma list into trimmed item slices; the array comes from
/// `arena`, the items borrow the source text like scalar strings do.
/// Empty items ("a,,b") and lists past list_max_items are errors.
fn parseList(s: []const u8, arena: Allocator) Error![][]const u8 {
    var items = std.ArrayList([]const u8).empty;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |item| {
        const t = std.mem.trim(u8, item, " \t");
        if (t.len == 0) return error.BadValue;
        try items.append(arena, t);
        if (items.items.len > list_max_items) return error.BadValue;
    }
    return items.toOwnedSlice(arena);
}

/// Duration in milliseconds. Fields that only need one unit stay plain
/// integers with the unit in the field name (timeout_ms, window_seconds).
pub const Duration = struct {
    ms: u64 = 0,

    /// Parses "Nms", "Ns", "Nm", "Nh"; a bare integer is seconds, matching
    /// the units of every duration key the daemons accept today.
    pub fn parse(s: []const u8) ParseError!Duration {
        if (s.len == 0) return error.BadValue;
        var num = s;
        var factor: u64 = 1000; // bare number: seconds
        if (std.mem.endsWith(u8, s, "ms")) {
            num = s[0 .. s.len - 2];
            factor = 1;
        } else if (s[s.len - 1] == 's') {
            num = s[0 .. s.len - 1];
        } else if (s[s.len - 1] == 'm') {
            num = s[0 .. s.len - 1];
            factor = 60_000;
        } else if (s[s.len - 1] == 'h') {
            num = s[0 .. s.len - 1];
            factor = 3_600_000;
        }
        if (num.len == 0) return error.BadValue;
        const n = std.fmt.parseInt(u64, num, 10) catch return error.BadValue;
        return .{ .ms = std.math.mul(u64, n, factor) catch return error.BadValue };
    }

    /// Canonical form: largest unit that divides the value exactly.
    pub fn format(self: Duration, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.ms % 3_600_000 == 0) {
            try w.print("{d}h", .{self.ms / 3_600_000});
        } else if (self.ms % 60_000 == 0) {
            try w.print("{d}m", .{self.ms / 60_000});
        } else if (self.ms % 1000 == 0) {
            try w.print("{d}s", .{self.ms / 1000});
        } else {
            try w.print("{d}ms", .{self.ms});
        }
    }
};

/// Writes a field value in its canonical CLI/file spelling.
fn writeValue(comptime T: type, w: *std.Io.Writer, v: T) std.Io.Writer.Error!void {
    if (T == []const u8) return w.writeAll(v);
    if (T == bool) return w.writeAll(if (v) "true" else "false");
    if (T == Duration) return w.print("{f}", .{v});
    if (T == std.net.Address) {
        if (v.getPort() != 0) return w.print("{f}", .{v});
        // Port 0 means "no port": emit the bare literal, which parses
        // back as port 0 (parsePort rejects an explicit :0).
        var b: [64]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&b);
        try bw.print("{f}", .{v});
        const s = bw.buffered();
        return w.writeAll(s[0 .. s.len - 2]);
    }
    if (T == [][]const u8) {
        for (v, 0..) |item, i| {
            if (i != 0) try w.writeByte(',');
            try w.writeAll(item);
        }
        return;
    }
    switch (@typeInfo(T)) {
        .int => try w.print("{d}", .{v}),
        .@"enum" => try w.writeAll(@tagName(v)),
        .@"union" => try v.write(w),
        else => unreachable, // field types are checked at comptime
    }
}

fn fieldTypeOf(comptime T: type, comptime name: []const u8) type {
    switch (@typeInfo(T)) {
        .@"struct" => |st| {
            for (st.fields) |f| {
                if (std.mem.eql(u8, f.name, name)) return f.type;
            }
            @compileError("conf: no field '" ++ name ++ "' in " ++ @typeName(T));
        },
        else => @compileError("conf: section '" ++ @typeName(T) ++ "' is not a struct"),
    }
}

/// Splits "section.field" at the single '.' separator.
fn splitRef(comptime ref: []const u8) struct { []const u8, []const u8 } {
    const dot = std.mem.indexOfScalar(u8, ref, '.') orelse
        @compileError("conf: target '" ++ ref ++ "' must be section.field");
    return .{ ref[0..dot], ref[dot + 1 ..] };
}

/// Builds the loader type for a sections struct, a field table and a CLI
/// table. All tables are validated at comptime: field references must
/// exist, file (section, key) pairs and CLI spellings must be unique, flag
/// options must target bool fields, and every field type must be one
/// parseValue supports.
pub const Options = struct {
    /// Hard cap on key=value lines in one file.
    max_keys: usize = default_max_keys,
    /// Positional arguments the loader collects instead of rejecting;
    /// 0 means every positional is an error (the default). ctl opts in
    /// for its subcommands.
    positional_cap: usize = 0,
};

pub fn Loader(
    comptime Sections: type,
    comptime fields: []const FieldSpec,
    comptime cli: []const CliSpec,
    comptime options: Options,
) type {
    const field_types = comptime blk: {
        @setEvalBranchQuota(1_000_000);
        var types: [fields.len]type = undefined;
        for (fields, 0..) |f, i| {
            if (f.section.len == 0) @compileError("conf: empty section name");
            if (!f.in_file and f.aliases.len != 0)
                @compileError("conf: cli-only field " ++ f.field ++ " cannot have aliases");
            const sec = fieldTypeOf(Sections, f.section);
            types[i] = fieldTypeOf(sec, f.field);
            // Every field type must be parseable.
            const T = types[i];
            if (T != []const u8 and T != bool and T != Duration and T != std.net.Address and T != [][]const u8) {
                switch (@typeInfo(T)) {
                    .int, .@"enum" => {},
                    .@"union" => {
                        if (!@hasDecl(T, "parse")) @compileError("conf: unsupported union type " ++ @typeName(T) ++
                            " for " ++ f.section ++ "." ++ f.field);
                    },
                    else => @compileError("conf: unparseable field type " ++ @typeName(T) ++
                        " for " ++ f.section ++ "." ++ f.field),
                }
            }
            for (f.aliases) |a| {
                if (a.len == 0) @compileError("conf: empty alias");
            }
        }
        for (fields, 0..) |f, i| {
            if (!f.in_file) continue;
            for (fields[i + 1 ..]) |g| {
                if (!g.in_file) continue;
                if (std.mem.eql(u8, f.section, g.section) and
                    std.mem.eql(u8, keyOf(f), keyOf(g)))
                {
                    @compileError("conf: duplicate file key " ++ f.section ++ "." ++ keyOf(f));
                }
            }
            for (f.aliases) |a| {
                for (fields, 0..) |g, j| {
                    if (j != i and std.mem.eql(u8, f.section, g.section) and
                        std.mem.eql(u8, a, keyOf(g)))
                    {
                        @compileError("conf: alias '" ++ a ++ "' shadows key " ++ g.section ++ "." ++ keyOf(g));
                    }
                }
            }
        }
        break :blk types;
    };

    const cli_targets = comptime blk: {
        @setEvalBranchQuota(1_000_000);
        var targets: [cli.len]usize = undefined;
        var seen: [cli.len]usize = undefined;
        var n: usize = 0;
        for (cli, 0..) |c, i| {
            const ref = splitRef(c.target);
            var found: ?usize = null;
            for (fields, 0..) |f, j| {
                if (std.mem.eql(u8, f.section, ref[0]) and std.mem.eql(u8, f.field, ref[1])) {
                    found = j;
                }
            }
            targets[i] = found orelse
                @compileError("conf: cli '" ++ c.name ++ "' targets unknown field " ++ c.target);
            if (c.flag != null and field_types[targets[i]] != bool) {
                @compileError("conf: flag '" ++ c.name ++ "' targets non-bool " ++ c.target);
            }
            for (seen[0..n]) |prev| {
                if (prev == targets[i]) @compileError("conf: two cli options target " ++ c.target);
            }
            seen[n] = targets[i];
            n += 1;
        }
        // Every CLI spelling must be unique.
        for (cli, 0..) |c, i| {
            for (cli[i + 1 ..]) |d| {
                if (std.mem.eql(u8, c.name, d.name)) {
                    @compileError("conf: duplicate cli spelling '--" ++ c.name ++ "'");
                }
                for (d.aliases) |a| {
                    if (std.mem.eql(u8, c.name, a)) {
                        @compileError("conf: cli spelling '--" ++ c.name ++ "' shadows an alias");
                    }
                }
                if (d.flag != null and std.mem.eql(u8, c.name, d.name)) {
                    @compileError("conf: duplicate cli flag '--" ++ c.name ++ "'");
                }
            }
            for (c.aliases) |a| {
                for (cli) |d| {
                    if (std.mem.eql(u8, a, d.name)) {
                        @compileError("conf: cli alias '--" ++ a ++ "' shadows '--" ++ d.name ++ "'");
                    }
                }
            }
        }
        break :blk targets;
    };

    return struct {
        pub const Self = @This();
        pub const spec_fields = fields;
        pub const spec_cli = cli;

        /// Effective values; defaults live in the section initializers.
        values: Sections,
        /// Per-field provenance, indexed like `fields`.
        /// Positional arguments collected when options.positional_cap
        /// allows them (ctl subcommands). Borrowed from the caller's
        /// argv, like string field values.
        positionals: []const []const u8 = &.{},
        pos_buf: [options.positional_cap][]const u8 = undefined,
        pos_len: usize = 0,
        provenance: [fields.len]Source,
        /// File line a field was set at (0 when not set from a file).
        lines: [fields.len]u32,
        arena_state: std.heap.ArenaAllocator,

        pub fn init(gpa: Allocator) Self {
            return .{
                .values = .{},
                .provenance = @splat(.default),
                .lines = @splat(0),
                .arena_state = std.heap.ArenaAllocator.init(gpa),
            };
        }

        /// Frees the load arena (file bytes and every value borrowed from
        /// them).
        pub fn deinit(self: *Self) void {
            self.arena_state.deinit();
        }

        /// Loads file then CLI per the LoadOpts; one call is one load.
        pub fn load(gpa: Allocator, opts: LoadOpts, diag: *Diag) Error!Self {
            var self = Self.init(gpa);
            errdefer self.deinit();
            if (opts.path) |p| try self.loadFile(p, diag);
            // Order is precedence: file < forwarded < real CLI. The blob
            // lives in the load arena because forwarded values borrow it
            // the way file values borrow the file bytes.
            if (opts.conf_fd) |fd| {
                const blob = try readForwarded(fd, self.arena_state.allocator(), diag);
                try self.applyForwarded(blob, diag);
            }
            try self.applyArgs(opts.args, diag);
            return self;
        }

        /// Field index of a "section.field" reference, resolved comptime.
        pub fn fieldIndex(comptime section: []const u8, comptime field: []const u8) usize {
            for (fields, 0..) |f, i| {
                if (std.mem.eql(u8, f.section, section) and std.mem.eql(u8, f.field, field)) {
                    return i;
                }
            }
            @compileError("conf: no field " ++ section ++ "." ++ field);
        }

        pub fn provenanceOf(self: *const Self, comptime section: []const u8, comptime field: []const u8) Source {
            return self.provenance[comptime fieldIndex(section, field)];
        }

        pub fn lineOf(self: *const Self, comptime section: []const u8, comptime field: []const u8) u32 {
            return self.lines[comptime fieldIndex(section, field)];
        }

        /// Parses an INI file into values. Sections and keys must be known
        /// to the field table; an unknown one is an error with file:line.
        /// Unlike the legacy parser, a key before the first [section] is
        /// rejected rather than silently bound to an empty section.
        pub fn loadFile(self: *Self, path: []const u8, diag: *Diag) Error!void {
            const arena = self.arena_state.allocator();
            const file = std.fs.cwd().openFile(path, .{}) catch |err| {
                diag.set(.{ .path = path, .detail = @errorName(err) });
                return switch (err) {
                    error.FileNotFound => error.FileNotFound,
                    else => error.ReadFailed,
                };
            };
            defer file.close();

            const content = file.readToEndAlloc(arena, max_file_bytes) catch |err| {
                diag.set(.{ .path = path, .detail = @errorName(err) });
                return switch (err) {
                    error.FileTooBig => error.FileTooLarge,
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.ReadFailed,
                };
            };

            var section: []const u8 = "";
            var keys_seen: usize = 0;
            var line_no: u32 = 0;
            var it = std.mem.splitScalar(u8, content, '\n');
            while (it.next()) |raw| {
                line_no += 1;
                if (raw.len > max_line_bytes) {
                    diag.set(.{ .path = path, .line = line_no, .detail = "line too long" });
                    return error.LineTooLong;
                }
                // Comment policy: '#' or ';' opens a comment at line
                // start or after whitespace; inside a token it is a
                // literal byte (p#ss stays intact). There is no quote
                // processing: a quoted value keeps its quote bytes.
                var line = std.mem.trim(u8, raw, " \t\r");
                if (line.len == 0) continue;
                for (line[1..], 1..) |c, j| {
                    if ((c == '#' or c == ';') and (line[j - 1] == ' ' or line[j - 1] == '\t')) {
                        line = std.mem.trim(u8, line[0..j], " \t");
                        break;
                    }
                }
                if (line.len == 0) continue;
                if (line[0] == '#' or line[0] == ';') continue;
                if (line[0] == '[') {
                    if (line.len < 3 or line[line.len - 1] != ']') {
                        diag.set(.{ .path = path, .line = line_no, .detail = "malformed section header" });
                        return error.MalformedLine;
                    }
                    section = line[1 .. line.len - 1];
                    if (!sectionKnown(section)) {
                        diag.set(.{ .path = path, .line = line_no, .section = section, .detail = "unknown section" });
                        return error.UnknownSection;
                    }
                    continue;
                }
                const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
                    diag.set(.{ .path = path, .line = line_no, .detail = "expected key = value" });
                    return error.MalformedLine;
                };
                const key = std.mem.trim(u8, line[0..eq], " \t");
                const value = std.mem.trim(u8, line[eq + 1 ..], " \t");
                if (key.len == 0) {
                    diag.set(.{ .path = path, .line = line_no, .detail = "empty key" });
                    return error.MalformedLine;
                }
                keys_seen += 1;
                if (keys_seen > options.max_keys) {
                    diag.set(.{ .path = path, .line = line_no, .detail = "too many keys" });
                    return error.TooManyKeys;
                }
                const idx = findField(section, key) orelse {
                    diag.set(.{ .path = path, .line = line_no, .section = section, .key = key, .detail = "unknown key" });
                    return error.UnknownKey;
                };
                if (self.provenance[idx] == .file) {
                    diag.set(.{ .path = path, .line = self.lines[idx], .section = section, .key = key, .detail = "duplicate key (first set here)" });
                    return error.DuplicateKey;
                }
                try self.setField(idx, value, .{ .path = path, .line = line_no }, diag);
                self.provenance[idx] = .file;
                self.lines[idx] = line_no;
            }
        }

        /// Applies CLI arguments over the current values. Accepts
        /// "--name value", "--name=value", "-name value" and flag options
        /// declared in the cli table.
        pub fn applyArgs(self: *Self, args: []const []const u8, diag: *Diag) Error!void {
            try self.applyArgv(args, .cli, diag);
        }

        /// Applies a forwarded configuration blob: the memfd contents are
        /// canonical CLI lines, one per line, parsed exactly like real
        /// arguments but recorded with provenance .forwarded.
        pub fn applyForwarded(self: *Self, blob: []const u8, diag: *Diag) Error!void {
            var lines = std.mem.splitScalar(u8, blob, '\n');
            while (lines.next()) |line| {
                if (line.len == 0) continue;
                try self.applyArgv(&.{line}, .forwarded, diag);
            }
        }

        fn applyArgv(self: *Self, args: []const []const u8, prov: Source, diag: *Diag) Error!void {
            var end_of_options = false;
            var i: usize = 0;
            while (i < args.len) : (i += 1) {
                const arg = args[i];
                if (end_of_options or arg.len == 0 or arg[0] != '-') {
                    if (comptime options.positional_cap == 0) {
                        diag.set(.{ .key = arg, .detail = "unexpected positional argument" });
                        return error.UnexpectedPositional;
                    } else {
                        if (self.pos_len == options.positional_cap) {
                            diag.set(.{ .key = arg, .detail = "too many positional arguments" });
                            return error.UnexpectedPositional;
                        }
                        self.pos_buf[self.pos_len] = arg;
                        self.pos_len += 1;
                        self.positionals = self.pos_buf[0..self.pos_len];
                        continue;
                    }
                }
                if (std.mem.eql(u8, arg, "--")) {
                    end_of_options = true;
                    continue;
                }
                const stripped = if (arg.len >= 2 and arg[1] == '-') arg[2..] else arg[1..];
                if (stripped.len == 0) {
                    diag.set(.{ .key = arg, .detail = "malformed argument" });
                    return error.UnknownArgument;
                }
                var name = stripped;
                var value: ?[]const u8 = null;
                if (std.mem.indexOfScalar(u8, stripped, '=')) |eq| {
                    name = stripped[0..eq];
                    value = stripped[eq + 1 ..];
                }
                if (findCli(name)) |ci| {
                    if (cli[ci].flag) |sets| {
                        if (value != null) {
                            diag.set(.{ .key = arg, .detail = "flag takes no value" });
                            return error.FlagTakesNoValue;
                        }
                        try self.setField(cli_targets[ci], if (sets) "true" else "false", .{}, diag);
                        self.provenance[cli_targets[ci]] = prov;
                        continue;
                    }
                    if (value == null) {
                        i += 1;
                        if (i >= args.len) {
                            diag.set(.{ .key = arg, .detail = "option requires a value" });
                            return error.MissingValue;
                        }
                        value = args[i];
                    }
                    try self.setField(cli_targets[ci], value.?, .{ .key = arg }, diag);
                    self.provenance[cli_targets[ci]] = prov;
                } else if (std.mem.indexOfScalar(u8, name, '.')) |dot| {
                    // Canonical forwarded form: --section.key=value,
                    // spelled the same for every loader.
                    const idx = findField(name[0..dot], name[dot + 1 ..]) orelse {
                        diag.set(.{ .key = arg, .detail = "unknown argument" });
                        return error.UnknownArgument;
                    };
                    if (value == null) {
                        diag.set(.{ .key = arg, .detail = "option requires a value" });
                        return error.MissingValue;
                    }
                    try self.setField(idx, value.?, .{ .key = arg }, diag);
                    self.provenance[idx] = prov;
                } else {
                    diag.set(.{ .key = arg, .detail = "unknown argument" });
                    return error.UnknownArgument;
                }
            }
        }

        /// Serializes the resolved config in the canonical forwarding
        /// form, one "--section.key=value" element per file-schema
        /// field, so every loader accepts it. Meta and CLI-only fields
        /// (config_path, run_dir, help, --) are not forwarded. A
        /// formatted value past the 4 KiB scratch is ValueTooLong.
        pub fn forwardArgs(self: *const Self, arena: Allocator, diag: *Diag) Error![]const []const u8 {
            var list = std.ArrayList([]const u8).empty;
            var buf: [4096]u8 = undefined;
            inline for (fields, 0..) |f, i| {
                if (!f.in_file) continue;
                const v = @field(@field(self.values, f.section), f.field);
                var w: std.Io.Writer = .fixed(&buf);
                writeValue(field_types[i], &w, v) catch {
                    diag.set(.{ .key = keyOf(f), .detail = "serialized value exceeds the 4 KiB scratch buffer" });
                    return error.ValueTooLong;
                };
                try list.append(arena, try std.fmt.allocPrint(arena, "--{s}.{s}={s}", .{ f.section, keyOf(f), w.buffered() }));
            }
            return list.toOwnedSlice(arena);
        }

        /// Serializes the resolved config as the forwarding blob: one
        /// canonical "--section.key=value" line per file-schema field,
        /// LF-terminated. A value containing LF cannot survive the line
        /// form and is rejected with a diagnostic naming the key.
        pub fn forwardBlob(self: *const Self, arena: Allocator, diag: *Diag) Error![]u8 {
            var blob = std.ArrayList(u8).empty;
            var buf: [4096]u8 = undefined;
            inline for (fields, 0..) |f, i| {
                if (!f.in_file) continue;
                const v = @field(@field(self.values, f.section), f.field);
                var w: std.Io.Writer = .fixed(&buf);
                writeValue(field_types[i], &w, v) catch {
                    diag.set(.{ .key = keyOf(f), .detail = "serialized value exceeds the 4 KiB scratch buffer" });
                    return error.ValueTooLong;
                };
                const val = w.buffered();
                if (std.mem.indexOfScalar(u8, val, '\n') != null) {
                    var kbuf: [160]u8 = undefined;
                    diag.set(.{
                        .key = std.fmt.bufPrint(&kbuf, "--{s}.{s}", .{ f.section, keyOf(f) }) catch keyOf(f),
                        .value = val,
                        .detail = "value contains a newline and cannot be forwarded",
                    });
                    return error.BadValue;
                }
                try blob.appendSlice(arena, "--");
                try blob.appendSlice(arena, f.section);
                try blob.append(arena, '.');
                try blob.appendSlice(arena, keyOf(f));
                try blob.append(arena, '=');
                try blob.appendSlice(arena, val);
                try blob.append(arena, '\n');
            }
            return blob.toOwnedSlice(arena);
        }

        /// Generated --help: every CLI option, then every file key, each
        /// with its help text and default.
        pub fn writeHelp(self: *const Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
            try w.writeAll("Options:\n");
            inline for (cli, 0..) |c, i| {
                const f = fields[cli_targets[i]];
                if (c.flag) |sets| {
                    try w.print("  --{s:<24} sets {s}.{s} {s}", .{ c.name, f.section, f.field, if (sets) "true" else "false" });
                } else {
                    try w.print("  --{s} <{s}>", .{ c.name, @typeName(field_types[cli_targets[i]]) });
                }
                if (c.help.len != 0) try w.print("  {s}", .{c.help});
                try w.writeByte('\n');
            }
            try w.writeAll("File keys:\n");
            inline for (fields, 0..) |f, i| {
                if (!f.in_file) continue;
                const v = @field(@field(self.values, f.section), f.field);
                try w.print("  [{s}] {s:<28} default: ", .{ f.section, keyOf(f) });
                try writeValue(field_types[i], w, v);
                if (f.aliases.len != 0) {
                    try w.writeAll("  aliases:");
                    for (f.aliases) |a| try w.print(" {s}", .{a});
                }
                if (f.help.len != 0) try w.print("  {s}", .{f.help});
                try w.writeByte('\n');
            }
        }

        fn sectionKnown(name: []const u8) bool {
            for (fields) |f| {
                if (f.in_file and std.mem.eql(u8, f.section, name)) return true;
            }
            return false;
        }

        fn findField(section: []const u8, key: []const u8) ?usize {
            for (fields, 0..) |f, i| {
                if (!f.in_file) continue;
                if (!std.mem.eql(u8, f.section, section)) continue;
                if (std.mem.eql(u8, key, keyOf(f))) return i;
                for (f.aliases) |a| {
                    if (std.mem.eql(u8, key, a)) return i;
                }
            }
            return null;
        }

        fn findCli(name: []const u8) ?usize {
            for (cli, 0..) |c, i| {
                if (std.mem.eql(u8, name, c.name)) return i;
                for (c.aliases) |a| {
                    if (std.mem.eql(u8, name, a)) return i;
                }
            }
            return null;
        }

        const LoadContext = struct {
            path: []const u8 = "",
            line: u32 = 0,
            key: []const u8 = "",
        };

        fn setField(self: *Self, idx: usize, s: []const u8, ctx: LoadContext, diag: *Diag) Error!void {
            inline for (fields, 0..) |f, i| {
                if (idx == i) {
                    if (field_types[i] == [][]const u8) {
                        @field(@field(self.values, f.section), f.field) = parseList(s, self.arena_state.allocator()) catch |err| {
                            switch (err) {
                                error.OutOfMemory => return error.OutOfMemory,
                                else => {
                                    diag.set(.{
                                        .path = ctx.path,
                                        .line = ctx.line,
                                        .section = f.section,
                                        .key = if (ctx.key.len != 0) ctx.key else keyOf(f),
                                        .value = s,
                                        .detail = "invalid value",
                                    });
                                    return error.BadValue;
                                },
                            }
                        };
                        return;
                    }
                    const val = parseValue(field_types[i], s) catch {
                        diag.set(.{
                            .path = ctx.path,
                            .line = ctx.line,
                            .section = f.section,
                            .key = if (ctx.key.len != 0) ctx.key else keyOf(f),
                            .value = s,
                            .detail = "invalid value",
                        });
                        return error.BadValue;
                    };
                    @field(@field(self.values, f.section), f.field) = val;
                    return;
                }
            }
            unreachable; // idx always comes from findField/findCli
        }
    };
}

pub const LoadOpts = struct {
    path: ?[]const u8 = null,
    /// Inherited sealed conf blob fd (-1/none when absent): pread to EOF
    /// and closed by the loader, applied between file and real CLI args.
    conf_fd: ?posix.fd_t = null,
    args: []const []const u8 = &.{},
};

/// The forwarded blob is bounded so a child can pread it in one pass.
/// Shared by the writer (ConfFd.create) and the reader (readForwarded).
pub const forward_max: usize = 256 * 1024;

/// The sealed anonymous blob a child inherits as its forwarded
/// configuration. The creator keeps it CLOEXEC; only a child's fd remap
/// slot drops the flag, so the blob fd cannot leak into a sibling or a
/// grandchild. One object is reused for every respawn until a reload
/// rebuilds it.
pub const ConfFd = struct {
    fd: posix.fd_t = -1,

    /// Creates the sealed blob object (CLOEXEC). Only a child's remap
    /// slot clears that flag.
    pub fn create(blob: []const u8) error{ BlobTooLarge, MemfdFailed, WriteFailed, SealFailed }!ConfFd {
        if (blob.len > forward_max) return error.BlobTooLarge;
        const fd = std.c.memfd_create("xmppd-conf", std.c.MFD.CLOEXEC | std.c.MFD.ALLOW_SEALING);
        if (fd < 0) return error.MemfdFailed;
        errdefer posix.close(fd);
        var off: usize = 0;
        while (off < blob.len) {
            off += posix.write(fd, blob[off..]) catch return error.WriteFailed;
        }
        const seals: c_int = std.c.F.SEAL_WRITE | std.c.F.SEAL_GROW | std.c.F.SEAL_SHRINK | std.c.F.SEAL_SEAL;
        if (std.c.fcntl(fd, std.c.F.ADD_SEALS, seals) < 0) return error.SealFailed;
        return .{ .fd = fd };
    }

    /// Rebuilds after a reload: the new sealed object replaces the old
    /// one so the next respawn reads fresh config while running
    /// children keep nothing but the fd they already read and closed.
    pub fn rebuild(self: *ConfFd, blob: []const u8) !void {
        const next = try ConfFd.create(blob);
        if (self.fd >= 0) posix.close(self.fd);
        self.* = next;
    }

    pub fn deinit(self: *ConfFd) void {
        if (self.fd >= 0) posix.close(self.fd);
        self.fd = -1;
    }
};

/// pread a sealed conf fd from offset 0 to EOF into a buffer the caller
/// frees, then close the fd. The fd is always closed, error or not, and
/// must be an inherited remap slot (>= 3) carrying all four seals;
/// anything else is refused before a byte is read. std.c.close is used
/// so a bad fd cannot trip posix.close's EBADF assertion.
pub fn readForwarded(fd: posix.fd_t, gpa: Allocator, diag: *Diag) Error![]u8 {
    defer _ = std.c.close(fd);
    if (fd < 3) {
        diag.set(.{ .detail = "conf fd is below the remap slot range" });
        return error.UnsealedFd;
    }
    const seals = std.c.fcntl(fd, std.c.F.GET_SEALS);
    if (seals < 0) {
        // EINVAL means the object simply carries no seals; a dead fd
        // stays a read failure either way.
        if (std.c._errno().* != @intFromEnum(std.c.E.INVAL)) {
            diag.set(.{ .detail = "cannot query conf fd seals" });
            return error.ReadFailed;
        }
        diag.set(.{ .detail = "conf fd is not fully sealed" });
        return error.UnsealedFd;
    }
    // SEAL_WRITE | SEAL_GROW | SEAL_SHRINK | SEAL_SEAL.
    if (seals != 0xf) {
        diag.set(.{ .detail = "conf fd is not fully sealed" });
        return error.UnsealedFd;
    }
    var blob = std.ArrayList(u8).empty;
    errdefer blob.deinit(gpa);
    var buf: [8192]u8 = undefined;
    var off: u64 = 0;
    while (true) {
        const n = posix.pread(fd, &buf, off) catch {
            diag.set(.{ .detail = "cannot read forwarded configuration fd" });
            return error.ReadFailed;
        };
        if (n == 0) break;
        if (blob.items.len + n > forward_max) {
            diag.set(.{ .detail = "forwarded configuration exceeds 256 KiB" });
            return error.FileTooLarge;
        }
        try blob.appendSlice(gpa, buf[0..n]);
        off += n;
    }
    return blob.toOwnedSlice(gpa);
}

fn keyOf(f: FieldSpec) []const u8 {
    return if (f.key.len != 0) f.key else f.field;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

const TestSections = struct {
    server: struct {
        hostname: []const u8 = "localhost",
        bind_address: std.net.Address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
        c2s_port: u16 = 5222,
        db_path: []const u8 = "/var/db/xmppd/users.db",
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
        max_per_account: u32 = 5,
        max_per_ip: u32 = 20,
        window_seconds: u32 = 60,
        lockout_duration: Duration = .{ .ms = 300_000 },
        lockout_threshold: u32 = 10,
        rate_limit: bool = true,
        crypto_threads: u32 = 0,
        registration: bool = false,
        require_invite: bool = true,
    } = .{},
    s2s: struct {
        socket: []const u8 = "/var/run/xmppd/s2s.sock",
        port: u16 = 5269,
        enabled: bool = true,
    } = .{},
    muc: struct {
        host: []const u8 = "muc.localhost",
    } = .{},
    core: struct {
        max_sessions: u32 = 10000,
        fan_out_batch_size: u32 = 64,
        max_resources_per_account: u32 = 16,
        workers: IntOr(enum { auto }) = .{ .kw = .auto },
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
        max_per_account: u32 = 5,
        max_per_ip: u32 = 20,
        rate_limit: bool = true,
        import_avatar: bool = false,
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

const file_spec = [_]FieldSpec{
    .{ .section = "server", .field = "hostname", .help = "server hostname" },
    .{ .section = "server", .field = "bind_address", .help = "c2s listen address" },
    .{ .section = "server", .field = "c2s_port", .help = "c2s listen port" },
    .{ .section = "server", .field = "db_path", .help = "user database path" },
    .{ .section = "server", .field = "user", .help = "unprivileged user" },
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
    .{ .section = "auth", .field = "rate_limit", .help = "enable rate limiting" },
    .{ .section = "auth", .field = "crypto_threads", .help = "password hash threads" },
    .{ .section = "auth", .field = "registration", .help = "enable registration" },
    .{ .section = "auth", .field = "require_invite", .help = "registration needs invite" },
    .{ .section = "s2s", .field = "socket", .help = "s2s IPC socket" },
    .{ .section = "s2s", .field = "port", .help = "s2s listen port" },
    .{ .section = "s2s", .field = "enabled", .help = "enable s2s" },
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

const master_cli = [_]CliSpec{
    .{ .name = "host", .target = "server.hostname" },
    .{ .name = "port", .target = "server.c2s_port" },
    .{ .name = "cert", .target = "tls.cert" },
    .{ .name = "key", .target = "tls.key" },
    .{ .name = "core-path", .target = "master.core_path" },
    .{ .name = "auth-path", .target = "master.auth_path" },
    .{ .name = "s2s-path", .target = "master.s2s_path" },
    .{ .name = "no-s2s", .target = "s2s.enabled", .flag = false },
    .{ .name = "auth-socket", .target = "auth.socket" },
    .{ .name = "db", .target = "server.db_path" },
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"} },
    .{ .name = "log-file", .target = "server.log_file" },
    .{ .name = "run-dir", .target = "master.run_dir" },
    .{ .name = "background", .target = "master.background", .flag = true, .aliases = &.{"b"} },
    .{ .name = "version", .target = "meta.version", .flag = true, .aliases = &.{"v"} },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"} },
};

const core_cli = [_]CliSpec{
    .{ .name = "host", .target = "server.hostname" },
    .{ .name = "address", .target = "server.bind_address", .aliases = &.{"bind"} },
    .{ .name = "port", .target = "server.c2s_port" },
    .{ .name = "cert", .target = "tls.cert" },
    .{ .name = "key", .target = "tls.key" },
    .{ .name = "auth-socket", .target = "auth.socket" },
    .{ .name = "s2s-socket", .target = "s2s.socket" },
    .{ .name = "listen-fd", .target = "core.listen_fd" },
    .{ .name = "db", .target = "server.db_path" },
    .{ .name = "muc-host", .target = "muc.host" },
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"} },
    .{ .name = "no-tls", .target = "tls.enabled", .flag = false },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"} },
};

const auth_cli = [_]CliSpec{
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"} },
    .{ .name = "db", .target = "server.db_path" },
    .{ .name = "socket", .target = "auth.socket" },
    .{ .name = "max-auth-per-account", .target = "auth.max_per_account" },
    .{ .name = "max-auth-per-ip", .target = "auth.max_per_ip" },
    .{ .name = "auth-window", .target = "auth.window_seconds" },
    .{ .name = "lockout-duration", .target = "auth.lockout_duration" },
    .{ .name = "lockout-threshold", .target = "auth.lockout_threshold" },
    .{ .name = "no-rate-limit", .target = "auth.rate_limit", .flag = false },
    .{ .name = "enable-registration", .target = "auth.registration", .flag = true },
    .{ .name = "no-require-invite", .target = "auth.require_invite", .flag = false },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"} },
};

const oidc_cli = [_]CliSpec{
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"} },
    .{ .name = "socket", .target = "oidc.socket" },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"} },
};

const s2s_cli = [_]CliSpec{
    .{ .name = "host", .target = "server.hostname" },
    .{ .name = "address", .target = "server.bind_address", .aliases = &.{"bind"} },
    .{ .name = "port", .target = "s2s.port" },
    .{ .name = "core-socket", .target = "s2s.socket" },
    .{ .name = "cert", .target = "tls.cert" },
    .{ .name = "key", .target = "tls.key" },
    .{ .name = "listen-fd", .target = "core.listen_fd" },
    .{ .name = "config", .target = "meta.config_path", .aliases = &.{"c"} },
    .{ .name = "help", .target = "meta.help", .flag = true, .aliases = &.{"h"} },
};

const ctl_cli = [_]CliSpec{
    .{ .name = "db", .target = "server.db_path" },
    .{ .name = "auth-socket", .target = "auth.socket" },
    .{ .name = "password", .target = "ctl.password" },
    .{ .name = "password-file", .target = "ctl.password_file" },
    .{ .name = "max-uses", .target = "ctl.max_uses" },
    .{ .name = "expires", .target = "ctl.expires_hours" },
};

const MasterLoader = Loader(TestSections, &file_spec, &master_cli, .{});
const CoreLoader = Loader(TestSections, &file_spec, &core_cli, .{});
const AuthLoader = Loader(TestSections, &file_spec, &auth_cli, .{});
const OidcLoader = Loader(TestSections, &file_spec, &oidc_cli, .{});
const S2sLoader = Loader(TestSections, &file_spec, &s2s_cli, .{});
const CtlLoader = Loader(TestSections, &file_spec, &ctl_cli, .{ .positional_cap = 8 });

/// Writes `content` to a temp file and returns its absolute path in `buf`.
fn writeTempConfig(dir: *std.fs.Dir, name: []const u8, content: []const u8, buf: []u8) ![]const u8 {
    const f = try dir.createFile(name, .{});
    defer f.close();
    try f.writeAll(content);
    return try dir.realpath(name, buf);
}

test "full file-key inventory parses with typed values" {
    // Goal: every key src/config/parser.zig consumers read today parses
    // into a typed field, including the old [auth]/[oidc] rate_max_*
    // spellings through aliases.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "inv.ini",
        \\[server]
        \\hostname = example.test
        \\bind_address = 10.0.0.1
        \\c2s_port = 5223
        \\db_path = /data/users.db
        \\user = xmppd
        \\log_file = /var/log/xmppd.log
        \\[tls]
        \\cert = /etc/xmppd/cert.pem
        \\key = /etc/xmppd/key.pem
        \\enabled = false
        \\[auth]
        \\socket = /run/auth.sock
        \\rate_max_per_account = 7
        \\rate_max_per_ip = 30
        \\window_seconds = 120
        \\lockout_duration = 600
        \\lockout_threshold = 5
        \\rate_limit = false
        \\crypto_threads = 4
        \\registration = true
        \\require_invite = false
        \\[s2s]
        \\socket = /run/s2s.sock
        \\port = 5270
        \\enabled = false
        \\[muc]
        \\host = conf.example.test
        \\[core]
        \\max_sessions = 20000
        \\fan_out_batch_size = 128
        \\max_resources_per_account = 32
        \\workers = 8
        \\log_level = debug
        \\[oidc]
        \\issuer = https://auth.example.test/
        \\client_id = xmppd
        \\client_secret = s3cr3t
        \\token_endpoint = https://auth.example.test/token
        \\jwks_uri = https://auth.example.test/jwks
        \\ca_file = /etc/ssl/ca.pem
        \\introspection_endpoint = https://auth.example.test/introspect
        \\user_domain = example.test
        \\socket = /run/oidc.sock
        \\rate_max_per_account = 9
        \\rate_max_per_ip = 40
        \\rate_limit = yes
        \\import_avatar = true
        \\[master]
        \\core_path = /opt/xmppd-core
        \\auth_path = /opt/xmppd-auth
        \\s2s_path = /opt/xmppd-s2s
        \\
    , &path_buf);

    var diag: Diag = .{};
    var l = try MasterLoader.load(testing.allocator, .{ .path = path }, &diag);
    defer l.deinit();
    const v = &l.values;

    try testing.expectEqualStrings("example.test", v.server.hostname);
    try testing.expectEqual(std.posix.AF.INET, v.server.bind_address.any.family);
    try testing.expectEqual(@as(u32, 0x0100000A), v.server.bind_address.in.sa.addr);
    try testing.expectEqual(@as(u16, 5223), v.server.c2s_port);
    try testing.expectEqualStrings("/data/users.db", v.server.db_path);
    try testing.expectEqualStrings("xmppd", v.server.user);
    try testing.expectEqualStrings("/var/log/xmppd.log", v.server.log_file);
    try testing.expectEqualStrings("/etc/xmppd/cert.pem", v.tls.cert);
    try testing.expectEqualStrings("/etc/xmppd/key.pem", v.tls.key);
    try testing.expect(!v.tls.enabled);
    try testing.expectEqualStrings("/run/auth.sock", v.auth.socket);
    try testing.expectEqual(@as(u32, 7), v.auth.max_per_account);
    try testing.expectEqual(@as(u32, 30), v.auth.max_per_ip);
    try testing.expectEqual(@as(u32, 120), v.auth.window_seconds);
    try testing.expectEqual(@as(u64, 600_000), v.auth.lockout_duration.ms);
    try testing.expectEqual(@as(u32, 5), v.auth.lockout_threshold);
    try testing.expect(!v.auth.rate_limit);
    try testing.expectEqual(@as(u32, 4), v.auth.crypto_threads);
    try testing.expect(v.auth.registration);
    try testing.expect(!v.auth.require_invite);
    try testing.expectEqualStrings("/run/s2s.sock", v.s2s.socket);
    try testing.expectEqual(@as(u16, 5270), v.s2s.port);
    try testing.expect(!v.s2s.enabled);
    try testing.expectEqualStrings("conf.example.test", v.muc.host);
    try testing.expectEqual(@as(u32, 20000), v.core.max_sessions);
    try testing.expectEqual(@as(u32, 128), v.core.fan_out_batch_size);
    try testing.expectEqual(@as(u32, 32), v.core.max_resources_per_account);
    switch (v.core.workers) {
        .num => |n| try testing.expectEqual(@as(i64, 8), n),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(.debug, v.core.log_level);
    try testing.expectEqualStrings("https://auth.example.test/", v.oidc.issuer);
    try testing.expectEqualStrings("xmppd", v.oidc.client_id);
    try testing.expectEqualStrings("s3cr3t", v.oidc.client_secret);
    try testing.expectEqualStrings("https://auth.example.test/token", v.oidc.token_endpoint);
    try testing.expectEqualStrings("https://auth.example.test/jwks", v.oidc.jwks_uri);
    try testing.expectEqualStrings("/etc/ssl/ca.pem", v.oidc.ca_file);
    try testing.expectEqualStrings("https://auth.example.test/introspect", v.oidc.introspection_endpoint);
    try testing.expectEqualStrings("example.test", v.oidc.user_domain);
    try testing.expectEqualStrings("/run/oidc.sock", v.oidc.socket);
    try testing.expectEqual(@as(u32, 9), v.oidc.max_per_account);
    try testing.expectEqual(@as(u32, 40), v.oidc.max_per_ip);
    try testing.expect(v.oidc.rate_limit);
    try testing.expect(v.oidc.import_avatar);
    try testing.expectEqualStrings("/opt/xmppd-core", v.master.core_path);
    try testing.expectEqualStrings("/opt/xmppd-auth", v.master.auth_path);
    try testing.expectEqualStrings("/opt/xmppd-s2s", v.master.s2s_path);
    try testing.expectEqual(.file, l.provenanceOf("server", "hostname"));
    try testing.expect(v.auth.lockout_duration.ms == 600_000);
}

test "every daemon CLI flag maps and parses" {
    // Goal: every argument spelling the six daemons accept today is
    // expressible in a CliSpec table and parses into the right field.
    var diag: Diag = .{};

    var master = try MasterLoader.load(testing.allocator, .{
        .args = &.{ "--host", "h.test", "--port", "5225", "--cert", "c.pem", "--key", "k.pem", "--core-path", "cp", "--auth-path", "ap", "--s2s-path", "sp", "--no-s2s", "--auth-socket", "as.sock", "--db", "d.db", "--config", "x.ini", "--log-file", "l.log", "--run-dir", "/run/x", "--background", "--version", "-h" },
    }, &diag);
    defer master.deinit();
    try testing.expectEqualStrings("h.test", master.values.server.hostname);
    try testing.expectEqual(@as(u16, 5225), master.values.server.c2s_port);
    try testing.expectEqualStrings("c.pem", master.values.tls.cert);
    try testing.expectEqualStrings("k.pem", master.values.tls.key);
    try testing.expectEqualStrings("cp", master.values.master.core_path);
    try testing.expectEqualStrings("ap", master.values.master.auth_path);
    try testing.expectEqualStrings("sp", master.values.master.s2s_path);
    try testing.expect(!master.values.s2s.enabled);
    try testing.expectEqualStrings("as.sock", master.values.auth.socket);
    try testing.expectEqualStrings("d.db", master.values.server.db_path);
    try testing.expectEqualStrings("x.ini", master.values.meta.config_path);
    try testing.expectEqualStrings("l.log", master.values.server.log_file);
    try testing.expectEqualStrings("/run/x", master.values.master.run_dir);
    try testing.expect(master.values.master.background);
    try testing.expect(master.values.meta.version);
    try testing.expect(master.values.meta.help);

    var core = try CoreLoader.load(testing.allocator, .{
        .args = &.{ "--host", "h.test", "--address", "1.2.3.4", "--bind", "5.6.7.8", "--port", "5226", "--cert", "c.pem", "--key", "k.pem", "--auth-socket", "a.sock", "--s2s-socket", "s.sock", "--listen-fd", "7", "--db", "d.db", "--muc-host", "m.test", "-c", "y.ini", "--no-tls", "-h" },
    }, &diag);
    defer core.deinit();
    try testing.expectEqualStrings("h.test", core.values.server.hostname);
    try testing.expectEqual(@as(u32, 0x08070605), core.values.server.bind_address.in.sa.addr);
    try testing.expectEqual(@as(u16, 5226), core.values.server.c2s_port);
    try testing.expectEqualStrings("c.pem", core.values.tls.cert);
    try testing.expectEqualStrings("k.pem", core.values.tls.key);
    try testing.expectEqualStrings("a.sock", core.values.auth.socket);
    try testing.expectEqualStrings("s.sock", core.values.s2s.socket);
    try testing.expectEqualStrings("7", core.values.core.listen_fd[0]);
    try testing.expectEqualStrings("d.db", core.values.server.db_path);
    try testing.expectEqualStrings("m.test", core.values.muc.host);
    try testing.expectEqualStrings("y.ini", core.values.meta.config_path);
    try testing.expect(!core.values.tls.enabled);
    try testing.expect(core.values.meta.help);

    var auth = try AuthLoader.load(testing.allocator, .{
        .args = &.{ "--config", "a.ini", "--db", "d.db", "--socket", "a.sock", "--max-auth-per-account", "9", "--max-auth-per-ip", "30", "--auth-window", "90", "--lockout-duration", "900", "--lockout-threshold", "3", "--no-rate-limit", "--enable-registration", "--no-require-invite", "-h" },
    }, &diag);
    defer auth.deinit();
    try testing.expectEqualStrings("a.ini", auth.values.meta.config_path);
    try testing.expectEqualStrings("d.db", auth.values.server.db_path);
    try testing.expectEqualStrings("a.sock", auth.values.auth.socket);
    try testing.expectEqual(@as(u32, 9), auth.values.auth.max_per_account);
    try testing.expectEqual(@as(u32, 30), auth.values.auth.max_per_ip);
    try testing.expectEqual(@as(u32, 90), auth.values.auth.window_seconds);
    try testing.expectEqual(@as(u64, 900_000), auth.values.auth.lockout_duration.ms);
    try testing.expectEqual(@as(u32, 3), auth.values.auth.lockout_threshold);
    try testing.expect(!auth.values.auth.rate_limit);
    try testing.expect(auth.values.auth.registration);
    try testing.expect(!auth.values.auth.require_invite);
    try testing.expect(auth.values.meta.help);

    var oidc = try OidcLoader.load(testing.allocator, .{
        .args = &.{ "-c", "o.ini", "--socket", "o.sock", "-h" },
    }, &diag);
    defer oidc.deinit();
    try testing.expectEqualStrings("o.ini", oidc.values.meta.config_path);
    try testing.expectEqualStrings("o.sock", oidc.values.oidc.socket);
    try testing.expect(oidc.values.meta.help);

    var s2s = try S2sLoader.load(testing.allocator, .{
        .args = &.{ "--host", "h.test", "--address", "1.2.3.4", "--port", "5271", "--core-socket", "c.sock", "--cert", "c.pem", "--key", "k.pem", "--listen-fd", "9", "--config", "s.ini", "-h" },
    }, &diag);
    defer s2s.deinit();
    try testing.expectEqualStrings("h.test", s2s.values.server.hostname);
    try testing.expectEqual(@as(u32, 0x04030201), s2s.values.server.bind_address.in.sa.addr);
    try testing.expectEqual(@as(u16, 5271), s2s.values.s2s.port);
    try testing.expectEqualStrings("c.sock", s2s.values.s2s.socket);
    try testing.expectEqualStrings("c.pem", s2s.values.tls.cert);
    try testing.expectEqualStrings("k.pem", s2s.values.tls.key);
    try testing.expectEqualStrings("9", s2s.values.core.listen_fd[0]);
    try testing.expectEqualStrings("s.ini", s2s.values.meta.config_path);
    try testing.expect(s2s.values.meta.help);

    var ctl = try CtlLoader.load(testing.allocator, .{
        .args = &.{ "--db", "d.db", "--auth-socket", "a.sock", "--password", "pw", "--password-file", "pf", "--max-uses", "5", "--expires", "48" },
    }, &diag);
    defer ctl.deinit();
    try testing.expectEqualStrings("d.db", ctl.values.server.db_path);
    try testing.expectEqualStrings("a.sock", ctl.values.auth.socket);
    try testing.expectEqualStrings("pw", ctl.values.ctl.password);
    try testing.expectEqualStrings("pf", ctl.values.ctl.password_file);
    try testing.expectEqual(@as(u32, 5), ctl.values.ctl.max_uses);
    try testing.expectEqual(@as(u32, 48), ctl.values.ctl.expires_hours);

    try testing.expectEqual(.cli, auth.provenanceOf("auth", "max_per_account"));
    try testing.expectEqual(.default, ctl.provenanceOf("server", "hostname"));
}

test "precedence default < file < CLI with provenance per field" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "prec.ini",
        \\[server]
        \\c2s_port = 6000
        \\hostname = file.test
        \\
    , &path_buf);

    var diag: Diag = .{};
    var l = try MasterLoader.load(testing.allocator, .{
        .path = path,
        .args = &.{ "--port", "6001" },
    }, &diag);
    defer l.deinit();

    try testing.expectEqual(@as(u16, 6001), l.values.server.c2s_port);
    try testing.expectEqual(.cli, l.provenanceOf("server", "c2s_port"));
    try testing.expectEqualStrings("file.test", l.values.server.hostname);
    try testing.expectEqual(.file, l.provenanceOf("server", "hostname"));
    try testing.expectEqual(@as(u32, 3), l.lineOf("server", "hostname"));
    try testing.expectEqual(.default, l.provenanceOf("server", "db_path"));
    try testing.expectEqual(@as(u32, 0), l.lineOf("server", "db_path"));
}

test "unknown section, key, bad value and duplicates report file:line" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    var diag: Diag = .{};

    const p1 = try writeTempConfig(&tmp.dir, "a.ini", "[nope]\nx = 1\n", &path_buf);
    var l = MasterLoader.init(testing.allocator);
    defer l.deinit();
    try testing.expectError(error.UnknownSection, l.loadFile(p1, &diag));
    try testing.expectEqual(@as(u32, 1), diag.line);
    try testing.expectEqualStrings("nope", diag.section);

    const p2 = try writeTempConfig(&tmp.dir, "b.ini", "[server]\nhostnam = x\n", &path_buf);
    try testing.expectError(error.UnknownKey, l.loadFile(p2, &diag));
    try testing.expectEqual(@as(u32, 2), diag.line);
    try testing.expectEqualStrings("hostnam", diag.key);

    const p3 = try writeTempConfig(&tmp.dir, "c.ini", "[server]\nc2s_port = abc\n", &path_buf);
    try testing.expectError(error.BadValue, l.loadFile(p3, &diag));
    try testing.expectEqual(@as(u32, 2), diag.line);
    try testing.expectEqualStrings("abc", diag.value);

    const p4 = try writeTempConfig(&tmp.dir, "d.ini", "[server]\nc2s_port = 1\nc2s_port = 2\n", &path_buf);
    try testing.expectError(error.DuplicateKey, l.loadFile(p4, &diag));
    try testing.expectEqual(@as(u32, 2), diag.line);

    const p5 = try writeTempConfig(&tmp.dir, "e.ini", "[server]\nno-equals-sign\n", &path_buf);
    try testing.expectError(error.MalformedLine, l.loadFile(p5, &diag));

    const p6 = try writeTempConfig(&tmp.dir, "f.ini", "[server]\nhostname = ok\nbad line\n", &path_buf);
    try testing.expectError(error.MalformedLine, l.loadFile(p6, &diag));
    try testing.expectEqual(@as(u32, 3), diag.line);

    try testing.expectError(error.FileNotFound, l.loadFile("/nonexistent/x.ini", &diag));
}

test "CLI errors: unknown argument, missing value, positional, flag value" {
    var diag: Diag = .{};
    var l = MasterLoader.init(testing.allocator);
    defer l.deinit();

    try testing.expectError(error.UnknownArgument, l.applyArgs(&.{"--bogus"}, &diag));
    try testing.expectError(error.MissingValue, l.applyArgs(&.{"--port"}, &diag));
    try testing.expectError(error.UnexpectedPositional, l.applyArgs(&.{"file.ini"}, &diag));
    try testing.expectError(error.FlagTakesNoValue, l.applyArgs(&.{"--background=yes"}, &diag));
    try testing.expectError(error.BadValue, l.applyArgs(&.{"--port=xyz"}, &diag));
    try testing.expectEqualStrings("--port=xyz", diag.key);
}

test "generated help lists every cli option and file key" {
    var l = MasterLoader.init(testing.allocator);
    defer l.deinit();

    var buf: [16384]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try l.writeHelp(&w);
    const help = w.buffered();

    inline for (master_cli) |c| {
        const needle = "--" ++ c.name;
        try testing.expect(std.mem.indexOf(u8, help, needle) != null);
    }
    inline for (file_spec) |f| {
        if (!f.in_file) continue;
        try testing.expect(std.mem.indexOf(u8, help, keyOf(f)) != null);
    }
    // Defaults and aliases appear in the file-key listing.
    try testing.expect(std.mem.indexOf(u8, help, "localhost") != null);
    try testing.expect(std.mem.indexOf(u8, help, "rate_max_per_account") != null);
}

test "the canonical blob parses identically across two different loaders" {
    var d0: Diag = .{};
    var parent = try MasterLoader.load(testing.allocator, .{
        .args = &.{ "--host", "h.test", "--no-s2s" },
    }, &d0);
    defer parent.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diag: Diag = .{};
    const blob = try parent.forwardBlob(arena.allocator(), &diag);
    // Canonical lines name every file-schema field as --section.key=.
    try testing.expect(std.mem.indexOf(u8, blob, "--server.hostname=h.test\n") != null);
    try testing.expect(std.mem.indexOf(u8, blob, "--s2s.enabled=false\n") != null);
    // Meta and cli-only fields are never forwarded.
    try testing.expect(std.mem.indexOf(u8, blob, "config_path") == null);
    try testing.expect(std.mem.indexOf(u8, blob, "run_dir") == null);
    var core = try CoreLoader.load(testing.allocator, .{ .conf_fd = try testConfFd(blob) }, &diag);
    defer core.deinit();
    var auth = try AuthLoader.load(testing.allocator, .{ .conf_fd = try testConfFd(blob) }, &diag);
    defer auth.deinit();
    try testing.expectEqualStrings("h.test", core.values.server.hostname);
    try testing.expectEqualStrings("h.test", auth.values.server.hostname);
    try testing.expect(!core.values.s2s.enabled);
    // A master-only spelling never leaks through: --core-path had no
    // file field, so nothing in the blob can fail an auth load.
}

test "forwardArgs round-trips the resolved config" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "fwd.ini",
        \\[server]
        \\hostname = file.test
        \\[tls]
        \\cert = c.pem
        \\
    , &path_buf);

    var diag: Diag = .{};
    var parent = try MasterLoader.load(testing.allocator, .{
        .path = path,
        .args = &.{ "--no-s2s", "--port", "6111" },
    }, &diag);
    defer parent.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const argv = try parent.forwardArgs(arena.allocator(), &diag);

    var child = MasterLoader.init(testing.allocator);
    defer child.deinit();
    try child.applyArgs(argv, &diag);

    try testing.expectEqualStrings("file.test", child.values.server.hostname);
    try testing.expectEqualStrings("c.pem", child.values.tls.cert);
    try testing.expectEqual(@as(u16, 6111), child.values.server.c2s_port);
    try testing.expect(!child.values.s2s.enabled);
    try testing.expectEqual(.cli, child.provenanceOf("server", "hostname"));
}

/// Creates a sealed anonymous conf blob fd the way the master does, so
/// loader tests exercise the real kernel path: write, seal, hand back.
fn testConfFd(blob: []const u8) !posix.fd_t {
    const c = try ConfFd.create(blob);
    return c.fd;
}

test "ConfFd creates a fully sealed CLOEXEC blob and rebuild swaps it" {
    var c = try ConfFd.create("--server.hostname=x.test\n");
    defer c.deinit();
    const fl = std.c.fcntl(c.fd, std.c.F.GETFD);
    try testing.expect(fl >= 0 and fl & 1 != 0); // FD_CLOEXEC set on the master copy
    try testing.expectEqual(@as(c_int, 0xf), @as(c_int, @intCast(std.c.fcntl(c.fd, std.c.F.GET_SEALS))));
    var b: [32]u8 = undefined;
    try testing.expectEqual(@as(isize, 25), std.c.pread(c.fd, &b, 32, 0));
    try testing.expectEqualStrings("--server.hostname=x.test\n", b[0..25]);
    try testing.expect(std.c.write(c.fd, "x", 1) < 0); // sealed
    const old = c.fd;
    try c.rebuild("--server.hostname=y.test\n");
    try testing.expect(c.fd != old);
    try testing.expect(std.c.fcntl(old, std.c.F.GETFD) < 0); // old fd closed
    var big: [forward_max + 1]u8 = undefined;
    try testing.expectError(error.BlobTooLarge, ConfFd.create(&big));
}

test "forwarded blob round-trips through a sealed memfd with .forwarded provenance" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "fwd.ini",
        \\[server]
        \\hostname = file.test
        \\[tls]
        \\cert = c.pem
        \\
    , &path_buf);

    var diag: Diag = .{};
    var parent = try MasterLoader.load(testing.allocator, .{
        .path = path,
        .args = &.{ "--no-s2s", "--port", "6111" },
    }, &diag);
    defer parent.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const blob = try parent.forwardBlob(arena.allocator(), &diag);
    const fd = try testConfFd(blob);

    // The child loads file < forwarded < cli: a real CLI flag on the
    // child still beats the forwarded value.
    var child = try MasterLoader.load(testing.allocator, .{
        .path = null,
        .conf_fd = fd,
        .args = &.{ "--port", "7000" },
    }, &diag);
    defer child.deinit();

    try testing.expectEqualStrings("file.test", child.values.server.hostname);
    try testing.expectEqualStrings("c.pem", child.values.tls.cert);
    try testing.expectEqual(@as(u16, 7000), child.values.server.c2s_port);
    try testing.expect(!child.values.s2s.enabled);
    try testing.expectEqual(.forwarded, child.provenanceOf("server", "hostname"));
    try testing.expectEqual(.forwarded, child.provenanceOf("s2s", "enabled"));
    try testing.expectEqual(.cli, child.provenanceOf("server", "c2s_port"));
    // The loader closed the fd after reading.
    try testing.expect(std.c.fcntl(fd, std.c.F.GETFD) < 0 and std.c._errno().* == @intFromEnum(std.c.E.BADF));
}

test "a forwarded value beats the file but loses to the child CLI" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "prec.ini",
        \\[server]
        \\hostname = file.test
        \\c2s_port = 1000
        \\
    , &path_buf);
    var diag: Diag = .{};

    var l = try MasterLoader.load(testing.allocator, .{
        .path = path,
        .conf_fd = try testConfFd("--port=2000\n--host=fwd.test\n"),
        .args = &.{ "--port", "3000" },
    }, &diag);
    defer l.deinit();

    try testing.expectEqualStrings("fwd.test", l.values.server.hostname);
    try testing.expectEqual(@as(u16, 3000), l.values.server.c2s_port);
    try testing.expectEqual(.forwarded, l.provenanceOf("server", "hostname"));
    try testing.expectEqual(.cli, l.provenanceOf("server", "c2s_port"));
}

test "Diag set tolerates its own fields; a copy rebinds to its storage" {
    var d: Diag = .{};
    d.set(.{ .key = "hostname", .value = "old.test", .detail = "invalid value" });
    // Feeding the Diag's own slices back must not panic on aliased copy.
    d.set(.{ .key = d.key, .value = d.value, .detail = "again" });
    try testing.expectEqualStrings("hostname", d.key);
    try testing.expectEqualStrings("old.test", d.value);
    try testing.expectEqualStrings("again", d.detail);
    // A plain copy shares the original's buffers; rebind() detaches it.
    var d2 = d;
    d2.rebind();
    d.set(.{ .key = "other", .value = "new.test", .detail = "x" });
    try testing.expectEqualStrings("hostname", d2.key);
    try testing.expectEqualStrings("old.test", d2.value);
}

test "serializers report ValueTooLong with a filled Diag on overflow" {
    var d0: Diag = .{};
    var l: MasterLoader = try .load(testing.allocator, .{
        .args = &.{ "--host", "x" },
    }, &d0);
    defer l.deinit();
    const huge = "h" ++ ("a" ** 5000);
    l.values.server.hostname = huge;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diag: Diag = .{};
    try testing.expectError(error.ValueTooLong, l.forwardBlob(arena.allocator(), &diag));
    try testing.expectEqualStrings("hostname", diag.key);
    try testing.expect(diag.detail.len != 0);
}

test "forwardBlob rejects a value containing LF and names the key" {
    var diag: Diag = .{};
    var l = MasterLoader.init(testing.allocator);
    defer l.deinit();
    l.values.server.hostname = try l.arena_state.allocator().dupe(u8, "a\nb");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.BadValue, l.forwardBlob(arena.allocator(), &diag));
    try testing.expectEqualStrings("--server.hostname", diag.key);
}

test "readForwarded caps the blob at 256 KiB and still closes the fd" {
    // A sealed object past the cap: built raw since ConfFd.create
    // refuses to produce one.
    const fd = std.c.memfd_create("xmppd-conf", std.c.MFD.CLOEXEC | std.c.MFD.ALLOW_SEALING);
    try testing.expect(fd >= 0);
    try posix.ftruncate(fd, forward_max + 1);
    const seals: c_int = std.c.F.SEAL_WRITE | std.c.F.SEAL_GROW | std.c.F.SEAL_SHRINK | std.c.F.SEAL_SEAL;
    try testing.expect(std.c.fcntl(fd, std.c.F.ADD_SEALS, seals) == 0);

    var diag: Diag = .{};
    try testing.expectError(error.FileTooLarge, readForwarded(fd, testing.allocator, &diag));
    try testing.expect(std.c.fcntl(fd, std.c.F.GETFD) < 0 and std.c._errno().* == @intFromEnum(std.c.E.BADF));
}

test "readForwarded refuses low, unsealed and dead fds without panicking" {
    var diag: Diag = .{};
    // A regular file carries no seals.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile("plain.blob", .{ .read = true });
    try testing.expectError(error.UnsealedFd, readForwarded(f.handle, testing.allocator, &diag));
    try testing.expectEqualStrings("conf fd is not fully sealed", diag.detail);
    // An already-closed fd errors instead of panicking through close.
    try testing.expectError(error.ReadFailed, readForwarded(99, testing.allocator, &diag));
    // Slot 0 is below the remap range. Last: the reader owns and closes
    // the fd even on refusal, so this takes stdin with it; a /dev/null
    // open reoccupies slot 0 for the rest of the suite.
    try testing.expectError(error.UnsealedFd, readForwarded(0, testing.allocator, &diag));
    try testing.expectEqualStrings("conf fd is below the remap slot range", diag.detail);
    // Deliberately left open: it holds slot 0 for the rest of the run.
    const keep = try posix.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try testing.expectEqual(@as(posix.fd_t, 0), keep);
}

test "the line limit is exactly 1024 bytes, not off by one" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    // hostname value sized so the whole line is exactly 1024 bytes.
    const vlen = max_line_bytes - "hostname = ".len;
    var body = std.ArrayList(u8).empty;
    defer body.deinit(testing.allocator);
    try body.appendSlice(testing.allocator, "[server]\nhostname = ");
    for (0..vlen) |_| try body.append(testing.allocator, 'a');
    try body.append(testing.allocator, '\n');
    const ok = try writeTempConfig(&tmp.dir, "edge.ini", body.items, &path_buf);
    var diag: Diag = .{};
    var l = try MasterLoader.load(testing.allocator, .{ .path = ok }, &diag);
    defer l.deinit();
    try testing.expectEqual(@as(usize, vlen), l.values.server.hostname.len);
    try body.insert(testing.allocator, body.items.len - 1, 'b');
    const over = try writeTempConfig(&tmp.dir, "edge2.ini", body.items, &path_buf);
    try testing.expectError(error.LineTooLong, MasterLoader.load(testing.allocator, .{ .path = over }, &diag));
}

test "forwarded values containing spaces round-trip untouched" {
    var d0: Diag = .{};
    var parent = try MasterLoader.load(testing.allocator, .{
        .args = &.{ "--host", "my host.example" },
    }, &d0);
    defer parent.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diag: Diag = .{};
    const blob = try parent.forwardBlob(arena.allocator(), &diag);
    var child = try CoreLoader.load(testing.allocator, .{ .conf_fd = try testConfFd(blob) }, &diag);
    defer child.deinit();
    try testing.expectEqualStrings("my host.example", child.values.server.hostname);
    try testing.expectEqual(.forwarded, child.provenanceOf("server", "hostname"));
}

test "ctl defaults match the code and positionals collect through --" {
    var diag: Diag = .{};
    var d = try CtlLoader.load(testing.allocator, .{ .args = &.{} }, &diag);
    defer d.deinit();
    try testing.expectEqual(@as(u16, 1), d.values.ctl.max_uses);
    try testing.expectEqual(@as(u32, 0), d.values.ctl.expires_hours);
    var d2 = try CtlLoader.load(testing.allocator, .{
        .args = &.{ "--db", "d.db", "--", "adduser", "alice" },
    }, &diag);
    defer d2.deinit();
    try testing.expectEqual(@as(usize, 2), d2.positionals.len);
    try testing.expectEqualStrings("adduser", d2.positionals[0]);
    try testing.expectEqualStrings("alice", d2.positionals[1]);
    var d3 = try CtlLoader.load(testing.allocator, .{
        .args = &.{ "passwd", "--db", "d.db" },
    }, &diag);
    defer d3.deinit();
    try testing.expectEqual(@as(usize, 1), d3.positionals.len);
}

test "inline comments end a value only after whitespace; quoting is literal" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "comments.ini",
        \\# whole-line comment
        \\[server] ; trailing comment on a header
        \\hostname = h.test # inline comment
        \\bind_address = 127.0.0.1 ; another
        \\db_path = /data/p#ss.db
        \\log_file = "quoted.log"
        \\
    , &path_buf);
    var diag: Diag = .{};
    var l = try MasterLoader.load(testing.allocator, .{ .path = path }, &diag);
    defer l.deinit();
    try testing.expectEqualStrings("h.test", l.values.server.hostname);
    try testing.expectEqual(@as(u16, posix.AF.INET), l.values.server.bind_address.any.family);
    // '#'/';' inside a token is literal, and so are quote bytes.
    try testing.expectEqualStrings("/data/p#ss.db", l.values.server.db_path);
    try testing.expectEqualStrings("\"quoted.log\"", l.values.server.log_file);
}

const m6_sections = struct {
    srv: struct {
        addrs: [][]const u8 = &.{},
        workers: IntOr(enum { auto }) = .{ .kw = .auto },
    } = .{},
};
const m6_fields = [_]FieldSpec{
    .{ .section = "srv", .field = "addrs" },
    .{ .section = "srv", .field = "workers" },
};
const m6_cli = [_]CliSpec{
    .{ .name = "addrs", .target = "srv.addrs" },
    .{ .name = "workers", .target = "srv.workers" },
};
const M6Loader = Loader(@TypeOf(m6_sections{}), &m6_fields, &m6_cli, .{});

test "comma-list and int-or-keyword field types parse and serialize" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const path = try writeTempConfig(&tmp.dir, "m6.ini",
        \\[srv]
        \\addrs = 10.0.0.1, ::1 , 127.0.0.1
        \\workers = 8
        \\
    , &path_buf);
    var diag: Diag = .{};

    var l = try M6Loader.load(testing.allocator, .{ .path = path }, &diag);
    defer l.deinit();
    try testing.expectEqual(@as(usize, 3), l.values.srv.addrs.len);
    try testing.expectEqualStrings("::1", l.values.srv.addrs[1]);
    switch (l.values.srv.workers) {
        .num => |n| try testing.expectEqual(@as(i64, 8), n),
        else => return error.TestUnexpectedResult,
    }

    // CLI and keyword forms land the same types.
    var l2 = try M6Loader.load(testing.allocator, .{
        .args = &.{ "--workers=auto", "--addrs=one,two" },
    }, &diag);
    defer l2.deinit();
    switch (l2.values.srv.workers) {
        .kw => |k| try testing.expectEqual(.auto, k),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 2), l2.values.srv.addrs.len);

    // writeValue emits the canonical forms back.
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeValue([][]const u8, &w, l.values.srv.addrs);
    try testing.expectEqualStrings("10.0.0.1,::1,127.0.0.1", w.buffered());
    var w2: std.Io.Writer = .fixed(&buf);
    try writeValue(@TypeOf(l2.values.srv.workers), &w2, l2.values.srv.workers);
    try testing.expectEqualStrings("auto", w2.buffered());

    // A bad keyword and a bad list item are rejected, not clamped.
    try testing.expectError(error.BadValue, parseValue(IntOr(enum { auto }), "sometimes"));

    // IntOr takes plain decimal only: no sign, underscores or leading
    // zeros, and it must be digits end to end.
    const Workers = IntOr(enum { auto });
    try testing.expectError(error.BadValue, Workers.parse("+8"));
    try testing.expectError(error.BadValue, Workers.parse("1_0"));
    try testing.expectError(error.BadValue, Workers.parse("08"));
    try testing.expectError(error.BadValue, Workers.parse(""));
    try testing.expectEqual(Workers{ .num = 0 }, try Workers.parse("0"));
    try testing.expectEqual(Workers{ .num = 8 }, try Workers.parse("8"));

    // Empty items and over-long lists are errors, not silent drops.
    var diag3: Diag = .{};
    try testing.expectError(error.BadValue, M6Loader.load(testing.allocator, .{ .args = &.{"--addrs=a,,b"} }, &diag3));
    var over = std.ArrayList(u8).empty;
    defer over.deinit(testing.allocator);
    try over.appendSlice(testing.allocator, "--addrs=");
    for (0..list_max_items + 1) |i| {
        if (i != 0) try over.append(testing.allocator, ',');
        try over.append(testing.allocator, 'a');
    }
    try testing.expectError(error.BadValue, M6Loader.load(testing.allocator, .{ .args = &.{over.items} }, &diag3));
}

const capped_sections = struct {
    s: struct { a: u32 = 0, b: u32 = 0, c: u32 = 0, d: u32 = 0 } = .{},
};
const capped_fields = [_]FieldSpec{
    .{ .section = "s", .field = "a" },
    .{ .section = "s", .field = "b" },
    .{ .section = "s", .field = "c" },
    .{ .section = "s", .field = "d" },
};
const CappedLoader = Loader(@TypeOf(capped_sections{}), &capped_fields, &.{}, .{ .max_keys = 3 });

test "bounds: oversized line and too many keys are errors" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    var diag: Diag = .{};
    var l = MasterLoader.init(testing.allocator);
    defer l.deinit();

    var long_line: [max_line_bytes + 8]u8 = undefined;
    @memset(&long_line, 'x');
    const long_content = try std.fmt.allocPrint(testing.allocator, "[server]\n{s}\n", .{long_line});
    defer testing.allocator.free(long_content);
    const p1 = try writeTempConfig(&tmp.dir, "long.ini", long_content, &path_buf);
    try testing.expectError(error.LineTooLong, l.loadFile(p1, &diag));

    var capped = CappedLoader.init(testing.allocator);
    defer capped.deinit();
    const p2 = try writeTempConfig(&tmp.dir, "many.ini",
        \\[s]
        \\a = 1
        \\b = 2
        \\c = 3
        \\d = 4
        \\
    , &path_buf);
    try testing.expectError(error.TooManyKeys, capped.loadFile(p2, &diag));
    try testing.expectEqual(@as(u32, 5), diag.line);
}

test "Duration parse and canonical format" {
    try testing.expectEqual(@as(u64, 500), (try Duration.parse("500ms")).ms);
    try testing.expectEqual(@as(u64, 30_000), (try Duration.parse("30s")).ms);
    try testing.expectEqual(@as(u64, 300_000), (try Duration.parse("5m")).ms);
    try testing.expectEqual(@as(u64, 7_200_000), (try Duration.parse("2h")).ms);
    try testing.expectEqual(@as(u64, 300_000), (try Duration.parse("300")).ms);
    try testing.expectError(error.BadValue, Duration.parse("10x"));
    try testing.expectError(error.BadValue, Duration.parse(""));
    try testing.expectError(error.BadValue, Duration.parse("ms"));
    try testing.expectError(error.BadValue, Duration.parse("18446744073709551616h"));

    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try (Duration{ .ms = 300_000 }).format(&w);
    try testing.expectEqualStrings("5m", w.buffered());
    w = .fixed(&buf);
    try (Duration{ .ms = 500 }).format(&w);
    try testing.expectEqualStrings("500ms", w.buffered());
}

test "parseValue covers ints, bools, enums, strings, address, durations" {
    try testing.expectEqual(@as(u16, 5222), try parseValue(u16, "5222"));
    try testing.expectEqual(@as(i32, -3), try parseValue(i32, "-3"));
    try testing.expectError(error.BadValue, parseValue(u8, "999"));
    try testing.expectError(error.BadValue, parseValue(u16, "-1"));

    try testing.expect(try parseValue(bool, "true"));
    try testing.expect(try parseValue(bool, "YES"));
    try testing.expect(!(try parseValue(bool, "off")));
    try testing.expectError(error.BadValue, parseValue(bool, "maybe"));

    const E = enum { debug, info, warn };
    try testing.expectEqual(.warn, try parseValue(E, "warn"));
    try testing.expectError(error.BadValue, parseValue(E, "trace"));

    try testing.expectEqualStrings("raw value", try parseValue([]const u8, "raw value"));

    const a = try parseValue(std.net.Address, "127.0.0.1");
    try testing.expectEqual(std.posix.AF.INET, a.any.family);
    const a6 = try parseValue(std.net.Address, "::1");
    try testing.expectEqual(std.posix.AF.INET6, a6.any.family);
    try testing.expectError(error.BadValue, parseValue(std.net.Address, "not-an-ip"));

    // Port-bearing forms round-trip: "ip:port" and "[v6]:port" keep
    // their port; a port-0 address writes as the bare literal so a
    // default re-serializes and re-parses instead of failing on ":0".
    const ap = try parseValue(std.net.Address, "127.0.0.1:5222");
    try testing.expectEqual(@as(u16, 5222), ap.getPort());
    const a6p = try parseValue(std.net.Address, "[::1]:5269");
    try testing.expectEqual(@as(u16, 5269), a6p.getPort());
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeValue(std.net.Address, &w, ap);
    const back = try parseValue(std.net.Address, w.buffered());
    try testing.expect(back.eql(ap));
    w = .fixed(&buf);
    try writeValue(std.net.Address, &w, a); // 127.0.0.1, port 0
    try testing.expectEqualStrings("127.0.0.1", w.buffered());
    try testing.expect((try parseValue(std.net.Address, w.buffered())).eql(a));
    w = .fixed(&buf);
    try writeValue(std.net.Address, &w, a6);
    try testing.expectEqualStrings("[::1]", w.buffered());
    // Ambiguous or meaningless forms are rejected, not re-interpreted.
    try testing.expectError(error.BadValue, parseValue(std.net.Address, "::1:5222"));
    try testing.expectError(error.BadValue, parseValue(std.net.Address, "0.0.0.0:0"));
}
