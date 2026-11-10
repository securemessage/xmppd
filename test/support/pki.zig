//! Test-only PKI rigs driven by the openssl CLI.
//!
//! Both the s2s and xmppc DANE tests need certificate chains with specific
//! trust properties, and neither may keep key material in the tree. Everything
//! here shells out to `openssl`; a machine without it skips these tests via
//! `error.SkipZigTest`.
//!
//! Only a missing binary is a skip. A command that runs and fails, or output
//! that does not parse, is a broken rig and returns its own error, so a
//! regression here fails the suite instead of quietly skipping it.

const std = @import("std");

/// A command that could not start because `openssl` is not installed is the
/// one condition tests are allowed to skip on.
fn runOrSkip(alloc: std.mem.Allocator, dir: std.fs.Dir, argv: []const []const u8, max_output_bytes: usize) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = alloc,
        .argv = argv,
        .cwd_dir = dir,
        .max_output_bytes = max_output_bytes,
    }) catch |err| switch (err) {
        error.FileNotFound => error.SkipZigTest,
        else => err,
    };
}

fn checkExit(argv: []const []const u8, r: std.process.Child.RunResult) !void {
    switch (r.term) {
        .Exited => |code| if (code != 0) {
            // Keep the reason with the failure: a rig that breaks must say why.
            std.debug.print("openssl {s} exited {d}: {s}\n", .{ argv[1], code, r.stderr });
            return error.RigCommandFailed;
        },
        else => {
            std.debug.print("openssl {s} terminated abnormally: {s}\n", .{ argv[1], r.stderr });
            return error.RigCommandFailed;
        },
    }
}

/// Run `openssl` in `dir`, ignoring its output.
pub fn run(alloc: std.mem.Allocator, dir: std.fs.Dir, argv: []const []const u8) !void {
    const r = try runOrSkip(alloc, dir, argv, 64 * 1024);
    defer alloc.free(r.stdout);
    defer alloc.free(r.stderr);
    try checkExit(argv, r);
}

/// As `run`, returning stdout. Caller owns the slice.
pub fn capture(alloc: std.mem.Allocator, dir: std.fs.Dir, argv: []const []const u8) ![]u8 {
    const r = try runOrSkip(alloc, dir, argv, 64 * 1024);
    defer alloc.free(r.stderr);
    errdefer alloc.free(r.stdout);
    try checkExit(argv, r);
    return r.stdout;
}

pub fn writeFile(dir: std.fs.Dir, name: []const u8, data: []const u8) !void {
    var f = try dir.createFile(name, .{});
    defer f.close();
    try f.writeAll(data);
}

/// Concatenate PEM files into `out_name`, the form
/// `SSL_CTX_use_certificate_chain_file` expects (leaf first).
pub fn concatPem(alloc: std.mem.Allocator, dir: std.fs.Dir, out_name: []const u8, parts: []const []const u8) !void {
    var out = try dir.createFile(out_name, .{});
    defer out.close();
    for (parts) |name| {
        const pem = try dir.readFileAlloc(alloc, name, 64 * 1024);
        defer alloc.free(pem);
        try out.writeAll(pem);
        if (pem.len > 0 and pem[pem.len - 1] != '\n') try out.writeAll("\n");
    }
}

/// Decode the first PEM certificate in `name` to DER. Caller owns the slice.
pub fn readCertDer(alloc: std.mem.Allocator, dir: std.fs.Dir, name: []const u8) ![]u8 {
    const pem = try dir.readFileAlloc(alloc, name, 64 * 1024);
    defer alloc.free(pem);

    const hdr = "-----BEGIN CERTIFICATE-----";
    const ftr = "-----END CERTIFICATE-----";
    const start = (std.mem.indexOf(u8, pem, hdr) orelse return error.BadPem) + hdr.len;
    const end = std.mem.indexOf(u8, pem, ftr) orelse return error.BadPem;

    var b64: [8192]u8 = undefined;
    var n: usize = 0;
    for (pem[start..end]) |ch| {
        if (ch == '\n' or ch == '\r' or ch == ' ') continue;
        if (n == b64.len) return error.BadPem;
        b64[n] = ch;
        n += 1;
    }

    const dec = std.base64.standard.Decoder;
    const der = try alloc.alloc(u8, try dec.calcSizeForSlice(b64[0..n]));
    errdefer alloc.free(der);
    try dec.decode(der, b64[0..n]);
    return der;
}

/// A self-signed leaf for `localhost`. Writes cert.pem and key.pem, so a
/// DANE-EE record over cert.pem authenticates the peer presenting it.
pub fn genSelfSigned(alloc: std.mem.Allocator, dir: std.fs.Dir) !void {
    try run(alloc, dir, &.{
        "openssl", "req",           "-x509",   "-newkey",                      "rsa:2048", "-nodes",
        "-subj",   "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days",    "1",
        "-keyout", "key.pem",       "-out",    "cert.pem",
    });
}

/// A real two-level chain: `ca.pem` signs a `localhost` leaf, cert.pem holds
/// [leaf, CA] and key.pem the leaf key. The CA's DER is DANE-TA data.
pub fn genDaneTaRig(alloc: std.mem.Allocator, dir: std.fs.Dir) !void {
    return genDaneTaRigNamed(alloc, dir, "localhost");
}

/// As `genDaneTaRig`, with the leaf's only DNS SAN spelled out. A DANE-TA
/// match runs the name check (RFC 7671 section 5.1 leaves it on for usages
/// 0-2), so the SAN decides which reference identifiers can accept the peer.
pub fn genDaneTaRigNamed(alloc: std.mem.Allocator, dir: std.fs.Dir, san: []const u8) !void {
    try run(alloc, dir, &.{
        "openssl", "req",                   "-x509",   "-newkey",                           "rsa:2048", "-nodes",
        "-subj",   "/CN=DANE TA Test Root", "-addext", "basicConstraints=critical,CA:TRUE", "-days",    "1",
        "-keyout", "ca_key.pem",            "-out",    "ca.pem",
    });
    try run(alloc, dir, &.{
        "openssl",  "req",                   "-newkey", "rsa:2048", "-nodes",
        "-subj",    "/CN=DANE TA Test Leaf", "-keyout", "key.pem",  "-out",
        "leaf.csr",
    });
    // `openssl x509 -req` drops CSR extensions unless an extfile is given,
    // and without a SAN no name check can pass.
    const ext = try std.fmt.allocPrint(alloc,
        \\basicConstraints=critical,CA:FALSE
        \\keyUsage=critical,digitalSignature,keyEncipherment
        \\extendedKeyUsage=serverAuth
        \\subjectAltName=DNS:{s}
        \\
    , .{san});
    defer alloc.free(ext);
    try writeFile(dir, "leaf.ext", ext);
    try run(alloc, dir, &.{
        "openssl",  "x509",     "-req",   "-in",        "leaf.csr",
        "-CA",      "ca.pem",   "-CAkey", "ca_key.pem", "-CAcreateserial",
        "-extfile", "leaf.ext", "-days",  "1",          "-out",
        "leaf.pem",
    });
    try concatPem(alloc, dir, "cert.pem", &.{ "leaf.pem", "ca.pem" });
}

/// The forged-anchor rig of the shared module's conformance case 6: a real
/// CA, and an attacker CA that reuses the real CA's subject DN to sign a
/// victim leaf. The peer presents [victim leaf, real CA] and the TLSA record
/// names the real CA, so only the signature can tell them apart.
///
/// Writes cert.pem (leaf + real CA), key.pem (victim leaf key) and ca.pem
/// (real CA, whose DER is the DANE-TA association data).
pub fn genForgedAnchorRig(alloc: std.mem.Allocator, dir: std.fs.Dir) !void {
    const ca_subject = "/CN=DANE Forged Anchor Test CA";

    try run(alloc, dir, &.{
        "openssl", "req",        "-x509",   "-newkey",                           "rsa:2048", "-nodes",
        "-subj",   ca_subject,   "-addext", "basicConstraints=critical,CA:TRUE", "-days",    "1",
        "-keyout", "ca_key.pem", "-out",    "ca.pem",
    });
    try run(alloc, dir, &.{
        "openssl", "req",                 "-x509",   "-newkey",                           "rsa:2048", "-nodes",
        "-subj",   ca_subject,            "-addext", "basicConstraints=critical,CA:TRUE", "-days",    "1",
        "-keyout", "attacker_ca_key.pem", "-out",    "attacker_ca.pem",
    });

    // The victim leaf carries the real CA's key identifier as its authority
    // key identifier. That AKID is what makes the chain attempt to build
    // through the real CA, so the failure is a signature check and not a
    // "no matching record" miss: cases 6 and 7 differ by exactly this.
    const ski = try capture(alloc, dir, &.{
        "openssl", "x509", "-in", "ca.pem", "-noout", "-ext", "subjectKeyIdentifier",
    });
    defer alloc.free(ski);
    const hex = try skiHex(alloc, ski);
    defer alloc.free(hex);

    const ext = try std.fmt.allocPrint(alloc,
        \\basicConstraints=critical,CA:FALSE
        \\keyUsage=critical,digitalSignature,keyEncipherment
        \\extendedKeyUsage=serverAuth
        \\subjectAltName=DNS:localhost
        \\2.5.29.35=DER:30:16:80:14:{s}
        \\
    , .{hex});
    defer alloc.free(ext);
    try writeFile(dir, "leaf.ext", ext);

    try run(alloc, dir, &.{
        "openssl",  "req",           "-newkey", "rsa:2048", "-nodes",
        "-subj",    "/CN=localhost", "-keyout", "key.pem",  "-out",
        "leaf.csr",
    });
    try run(alloc, dir, &.{
        "openssl",  "x509",            "-req",   "-in",                 "leaf.csr",
        "-CA",      "attacker_ca.pem", "-CAkey", "attacker_ca_key.pem", "-CAcreateserial",
        "-extfile", "leaf.ext",        "-days",  "1",                   "-out",
        "leaf.pem",
    });
    try concatPem(alloc, dir, "cert.pem", &.{ "leaf.pem", "ca.pem" });
}

/// Format the `subjectKeyIdentifier` value from `openssl x509 -ext` output
/// as the colon-separated bytes an `-extfile` DER value takes. Only the value
/// line is read: the heading above it ("X509v3 Subject Key Identifier:") is
/// full of hex-looking characters.
fn skiHex(alloc: std.mem.Allocator, text: []const u8) ![]u8 {
    var it = std.mem.splitScalar(u8, text, '\n');
    var value: ?[]const u8 = null;
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (std.mem.indexOf(u8, trimmed, "Key Identifier") != null) continue;
        value = trimmed;
    }
    const v = value orelse return error.BadSki;

    var raw: [40]u8 = undefined;
    var n: usize = 0;
    for (v) |ch| {
        if (!std.ascii.isHex(ch)) continue;
        if (n == raw.len) return error.BadSki;
        raw[n] = std.ascii.toUpper(ch);
        n += 1;
    }
    if (n != raw.len) return error.BadSki;

    const out = try alloc.alloc(u8, 3 * raw.len / 2 - 1);
    errdefer alloc.free(out);
    for (0..raw.len / 2) |i| {
        if (i > 0) out[i * 3 - 1] = ':';
        out[i * 3] = raw[i * 2];
        out[i * 3 + 1] = raw[i * 2 + 1];
    }
    return out;
}
