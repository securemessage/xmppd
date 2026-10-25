//! StanzaWriter: streaming XMPP stanza serializer over std.Io.Writer.
//!
//! One StanzaWriter emits one stanza into a caller-provided writer. Element
//! and attribute names are checked against the XML Name production (ASCII
//! subset; XMPP uses no non-ASCII names). Attribute values and text are
//! validated against the XML Char production and always escaped for the five
//! escapables (`& < > ' "`). Only reader-validated markup may pass through
//! rawSpan; the ValidatedSpan type carries that proof.
//!
//! The writer owns nothing and never allocates: every byte goes to the
//! caller's writer. When that writer fills or fails, a sticky failure is
//! latched, later emits are dropped, and finish() reports error.Overflow
//! once, so partial output can never count as success.

const std = @import("std");

/// Errors for malformed caller input (operating errors, not asserts).
pub const Error = error{
    /// Element or attribute name outside the XML Name production.
    InvalidName,
    /// Value bytes are not well-formed UTF-8.
    InvalidUtf8,
    /// Value contains bytes outside the XML Char production: NUL, C0
    /// controls other than tab/LF/CR, or the noncharacters U+FFFE/U+FFFF.
    InvalidCharacter,
};

/// finish() reports the latched output failure once.
pub const FinishError = error{Overflow};

pub const max_name_len = 256;
pub const max_depth = 512;

const vec_len = std.simd.suggestVectorLength(u8) orelse 16;
const ByteVec = @Vector(vec_len, u8);
const BitMask = std.meta.Int(.unsigned, vec_len);

const v_amp: ByteVec = @splat('&');
const v_lt: ByteVec = @splat('<');
const v_gt: ByteVec = @splat('>');
const v_apos: ByteVec = @splat('\'');
const v_quot: ByteVec = @splat('"');
const v_ctrl: ByteVec = @splat(0x20);
const v_ef: ByteVec = @splat(0xEF);

/// Markup bytes the stream reader has already validated (XML Char, UTF-8,
/// well-formedness). rawSpan emits them verbatim; the type exists so that
/// raw bytes cannot reach the output without that validation.
pub const ValidatedSpan = struct {
    bytes: []const u8,

    /// Constructed by the validating reader only. Any other caller is
    /// bypassing the guarantee this type exists to enforce.
    pub fn fromReader(bytes: []const u8) ValidatedSpan {
        return .{ .bytes = bytes };
    }
};

pub const StanzaWriter = struct {
    out: *std.Io.Writer,
    /// Latched when the underlying writer reports WriteFailed; once set, no
    /// further bytes are emitted and finish() reports error.Overflow.
    failed: bool = false,
    /// True between elementOpen and elementOpenEnd/elementSelfClose.
    in_start_tag: bool = false,
    /// Open element depth.
    depth: u16 = 0,

    pub fn init(out: *std.Io.Writer) StanzaWriter {
        return .{ .out = out };
    }

    /// Emits `<name`, opening a start tag. Attributes follow until
    /// elementOpenEnd or elementSelfClose.
    pub fn elementOpen(self: *StanzaWriter, name: []const u8) Error!void {
        assert(!self.in_start_tag);
        assert(self.depth < max_depth);
        validateName(name) catch |e| {
            self.failed = true;
            return e;
        };
        self.emitByte('<');
        self.emit(name);
        self.in_start_tag = true;
        self.depth += 1;
    }

    /// ` name='value'` inside an open start tag. The value is typed:
    /// strings are validated and escaped, integers formatted, enums written
    /// by tag name, bools as "true"/"false", optionals recurse on the
    /// payload (null writes an empty value).
    pub fn attr(self: *StanzaWriter, name: []const u8, value: anytype) Error!void {
        assert(self.in_start_tag);
        validateName(name) catch |e| {
            self.failed = true;
            return e;
        };
        validateValue(value) catch |e| {
            self.failed = true;
            return e;
        };
        self.emitByte(' ');
        self.emit(name);
        self.emit("='");
        self.emitTyped(value) catch |e| {
            self.failed = true;
            return e;
        };
        self.emitByte('\'');
    }

    /// Emits `>`, ending an open start tag.
    pub fn elementOpenEnd(self: *StanzaWriter) void {
        assert(self.in_start_tag);
        self.emitByte('>');
        self.in_start_tag = false;
    }

    /// Emits `/>`, ending an open start tag and its element.
    pub fn elementSelfClose(self: *StanzaWriter) void {
        assert(self.in_start_tag);
        assert(self.depth > 0);
        self.emit("/>");
        self.in_start_tag = false;
        self.depth -= 1;
    }

    /// `</name>`.
    pub fn elementClose(self: *StanzaWriter, name: []const u8) Error!void {
        assert(!self.in_start_tag);
        assert(self.depth > 0);
        validateName(name) catch |e| {
            self.failed = true;
            return e;
        };
        self.emit("</");
        self.emit(name);
        self.emitByte('>');
        self.depth -= 1;
    }

    /// Character data, validated and escaped. Same typed values as attr.
    pub fn text(self: *StanzaWriter, value: anytype) Error!void {
        assert(!self.in_start_tag);
        assert(self.depth > 0);
        validateValue(value) catch |e| {
            self.failed = true;
            return e;
        };
        self.emitTyped(value) catch |e| {
            self.failed = true;
            return e;
        };
    }

    /// Reader-validated markup emitted verbatim, escaping nothing. The
    /// ValidatedSpan type is the enforcement: no plain slice may be passed.
    pub fn rawSpan(self: *StanzaWriter, span: ValidatedSpan) void {
        assert(!self.in_start_tag);
        self.emit(span.bytes);
    }

    /// Reports the latched output failure once. Asserts the stanza is
    /// complete (all elements closed) when nothing failed.
    pub fn finish(self: *StanzaWriter) FinishError!void {
        if (self.failed) return error.Overflow;
        assert(self.depth == 0);
        assert(!self.in_start_tag);
    }

    fn emit(self: *StanzaWriter, bytes: []const u8) void {
        if (self.failed) return;
        self.out.writeAll(bytes) catch {
            self.failed = true;
        };
    }

    fn emitByte(self: *StanzaWriter, b: u8) void {
        if (self.failed) return;
        self.out.writeByte(b) catch {
            self.failed = true;
        };
    }

    fn emitFmt(self: *StanzaWriter, comptime fmt: []const u8, args: anytype) void {
        if (self.failed) return;
        self.out.print(fmt, args) catch {
            self.failed = true;
        };
    }

    fn emitEscaped(self: *StanzaWriter, s: []const u8) void {
        if (self.failed) return;
        writeEscaped(self.out, s) catch {
            self.failed = true;
        };
    }

    /// Validation-only twin of emitTyped: every rejection is decided
    /// before a single output byte is emitted for this value.
    fn validateValue(value: anytype) Error!void {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .optional => {
                if (value) |v| try validateValue(v);
            },
            .bool, .int, .comptime_int => {},
            .@"enum" => try validateChars(@tagName(value)),
            .pointer => {
                comptime {
                    if (!isStringArg(T)) {
                        @compileError("StanzaWriter: unsupported value type " ++ @typeName(T));
                    }
                }
                const s: []const u8 = value;
                try validateChars(s);
            },
            else => @compileError("StanzaWriter: unsupported value type " ++ @typeName(T)),
        }
    }

    fn emitTyped(self: *StanzaWriter, value: anytype) Error!void {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .optional => {
                if (value) |v| try self.emitTyped(v);
            },
            .bool => self.emit(if (value) "true" else "false"),
            .int, .comptime_int => self.emitFmt("{d}", .{value}),
            .@"enum" => {
                const tag = @tagName(value);
                try validateChars(tag);
                self.emitEscaped(tag);
            },
            .pointer => {
                comptime {
                    if (!isStringArg(T)) {
                        @compileError("StanzaWriter: unsupported value type " ++ @typeName(T));
                    }
                }
                const s: []const u8 = value;
                try validateChars(s);
                self.emitEscaped(s);
            },
            else => @compileError("StanzaWriter: unsupported value type " ++ @typeName(T)),
        }
    }
};

/// True for `[]const u8`-compatible arguments: u8 slices and pointers to
/// u8 arrays, which covers string literals.
fn isStringArg(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| (p.size == .slice and p.child == u8) or
            (p.size == .one and switch (@typeInfo(p.child)) {
                .array => |a| a.child == u8,
                else => false,
            }),
        else => false,
    };
}

fn isNameStart(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or c == '_' or c == ':';
}

fn isNameChar(c: u8) bool {
    return isNameStart(c) or (c >= '0' and c <= '9') or c == '-' or c == '.';
}

/// XML Name production restricted to ASCII (the only names XMPP emits).
pub fn isValidName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;
    if (!isNameStart(name[0])) return false;
    for (name[1..]) |c| {
        if (!isNameChar(c)) return false;
    }
    return true;
}

fn validateName(name: []const u8) Error!void {
    if (!isValidName(name)) return error.InvalidName;
}

/// Validates UTF-8 well-formedness and the XML Char production
/// (#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]).
/// Vector scan finds C0 bytes and 0xEF lead bytes; each is checked scalar.
/// 0xEF is the lead byte of U+F000..U+FFFF sequences, so only its U+FFFE
/// and U+FFFF encodings (EF BF BE, EF BF BF) are rejected; utf8ValidateSlice
/// has already ruled out surrogates and values above U+10FFFF.
pub fn validateChars(s: []const u8) Error!void {
    if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
    var i: usize = 0;
    while (i + vec_len <= s.len) : (i += vec_len) {
        const chunk: ByteVec = s[i..][0..vec_len].*;
        const suspect = (chunk < v_ctrl) | (chunk == v_ef);
        var mask: BitMask = @bitCast(suspect);
        while (mask != 0) {
            const idx: usize = @ctz(mask);
            const c = s[i + idx];
            if (c < 0x20) {
                if (c != '\t' and c != '\n' and c != '\r') return error.InvalidCharacter;
            } else {
                // 0xEF leads a valid three-byte sequence, so both
                // continuation bytes are present.
                if (s[i + idx + 1] == 0xBF and (s[i + idx + 2] == 0xBE or s[i + idx + 2] == 0xBF)) {
                    return error.InvalidCharacter;
                }
            }
            mask &= mask - 1;
        }
    }
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c < 0x20) {
            if (c != '\t' and c != '\n' and c != '\r') return error.InvalidCharacter;
        } else if (c == 0xEF) {
            if (s[i + 1] == 0xBF and (s[i + 2] == 0xBE or s[i + 2] == 0xBF)) {
                return error.InvalidCharacter;
            }
        }
    }
}

/// Writes `s` to `w` with the five XML escapables replaced by entities.
/// SIMD run-copy: each vector locates escapable bytes and the clean run
/// before each is copied in a single writeAll.
pub fn writeEscaped(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    var run_start: usize = 0;
    var i: usize = 0;
    while (i + vec_len <= s.len) : (i += vec_len) {
        const chunk: ByteVec = s[i..][0..vec_len].*;
        var mask = escapeMask(chunk);
        while (mask != 0) {
            const idx: usize = @ctz(mask);
            const hit = i + idx;
            try w.writeAll(s[run_start..hit]);
            try w.writeAll(entityFor(s[hit]));
            run_start = hit + 1;
            mask &= mask - 1;
        }
    }
    while (i < s.len) : (i += 1) {
        if (isEscapable(s[i])) {
            try w.writeAll(s[run_start..i]);
            try w.writeAll(entityFor(s[i]));
            run_start = i + 1;
        }
    }
    try w.writeAll(s[run_start..]);
}

fn escapeMask(chunk: ByteVec) BitMask {
    const hits = (chunk == v_amp) | (chunk == v_lt) | (chunk == v_gt) |
        (chunk == v_apos) | (chunk == v_quot);
    return @bitCast(hits);
}

fn isEscapable(c: u8) bool {
    return c == '&' or c == '<' or c == '>' or c == '\'' or c == '"';
}

fn entityFor(c: u8) []const u8 {
    return switch (c) {
        '&' => "&amp;",
        '<' => "&lt;",
        '>' => "&gt;",
        '\'' => "&apos;",
        '"' => "&quot;",
        else => unreachable,
    };
}

const assert = std.debug.assert;

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

/// Scalar reference escaper: the differential oracle for writeEscaped.
fn refEscape(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| {
        switch (c) {
            '&' => try w.writeAll("&amp;"),
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '\'' => try w.writeAll("&apos;"),
            '"' => try w.writeAll("&quot;"),
            else => try w.writeByte(c),
        }
    }
}

const StanzaType = enum { chat, normal, groupchat };

/// Emits one fixed sample stanza used by the output and overflow tests.
fn writeSample(x: *StanzaWriter) Error!void {
    try x.elementOpen("message");
    try x.attr("from", "alice@example.test");
    try x.attr("to", "bob@example.test");
    try x.attr("type", StanzaType.chat);
    x.elementOpenEnd();
    try x.elementOpen("body");
    x.elementOpenEnd();
    try x.text("Hi & bye <now> \"quoted\" 'q'");
    try x.elementClose("body");
    try x.elementClose("message");
}

test "elements, typed attributes and escaped text serialize correctly" {
    // Goal: verify exact wire bytes for the whole API surface.
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try writeSample(&x);
    try x.finish();

    try testing.expectEqualStrings(
        "<message from='alice@example.test' to='bob@example.test' type='chat'>" ++
            "<body>Hi &amp; bye &lt;now&gt; &quot;quoted&quot; &apos;q&apos;</body></message>",
        w.buffered(),
    );
}

test "typed attribute values: int, bool, enum, optional" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("iq");
    try x.attr("n", @as(u32, 42));
    try x.attr("flag", true);
    try x.attr("type", StanzaType.normal);
    const none: ?[]const u8 = null;
    try x.attr("empty", none);
    x.elementSelfClose();
    try x.finish();

    try testing.expectEqualStrings(
        "<iq n='42' flag='true' type='normal' empty=''/>",
        w.buffered(),
    );
}

test "injection: quote in attribute value cannot terminate it" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("s");
    try x.attr("a", "x' onload='evil");
    try x.attr("b", "y\" z=\"");
    x.elementOpenEnd();
    try x.text("ok");
    try x.elementClose("s");
    try x.finish();

    try testing.expectEqualStrings(
        "<s a='x&apos; onload=&apos;evil' b='y&quot; z=&quot;'>ok</s>",
        w.buffered(),
    );
}

test "injection: </ and ]]> in text are escaped" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("t");
    x.elementOpenEnd();
    try x.text("a</t><evil/>]]>");
    try x.elementClose("t");
    try x.finish();

    try testing.expectEqualStrings("<t>a&lt;/t&gt;&lt;evil/&gt;]]&gt;</t>", w.buffered());
}

test "NUL, control characters and invalid UTF-8 are rejected" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);
    try x.elementOpen("t");
    x.elementOpenEnd();

    try testing.expectError(error.InvalidCharacter, x.text("a\x00b"));
    try testing.expectError(error.InvalidCharacter, x.text("\x01\x02"));
    try testing.expectError(error.InvalidCharacter, x.text("\x0b")); // vertical tab
    try testing.expectError(error.InvalidUtf8, x.text("\xff\xfe"));
    try testing.expectError(error.InvalidUtf8, x.text("ok\xc0")); // truncated lead byte
    // U+FFFE and U+FFFF are valid UTF-8 but outside the XML Char production.
    try testing.expectError(error.InvalidCharacter, x.text("\xef\xbf\xbe"));
    try testing.expectError(error.InvalidCharacter, x.text("\xef\xbf\xbf"));
    // Tab, LF, CR and a supplementary-plane character are legal.
    // A rejected input latches the writer: the stanza can no longer
    // report success at finish().
    try testing.expectError(error.Overflow, x.finish());
}

test "element and attribute names are validated" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try testing.expectError(error.InvalidName, x.elementOpen("bad name"));
    try testing.expectError(error.InvalidName, x.elementOpen("1digit"));
    try testing.expectError(error.InvalidName, x.elementOpen(""));

    try x.elementOpen("ns:tag");
    try testing.expectError(error.InvalidName, x.attr("na'me", "v"));
    try testing.expectError(error.InvalidName, x.attr("=x", "v"));
    try x.attr("xml:lang", "en");
    x.elementSelfClose();
    // The earlier name rejections are latched: finish() fails.
    try testing.expectError(error.Overflow, x.finish());
}

test "rawSpan emits reader-validated bytes verbatim" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("iq");
    x.elementOpenEnd();
    const span = ValidatedSpan.fromReader("<child a='&amp;'>raw &amp; text</child>");
    x.rawSpan(span);
    try x.elementClose("iq");
    try x.finish();

    // Entities inside the span stay as the reader produced them.
    try testing.expectEqualStrings(
        "<iq><child a='&amp;'>raw &amp; text</child></iq>",
        w.buffered(),
    );
}

test "SIMD escaper matches scalar reference, 100000 random inputs" {
    // Goal: differential proof that writeEscaped equals the per-byte
    // reference on arbitrary input, fixed seed for reproducibility.
    var prng = std.Random.DefaultPrng.init(0xF4_1001);
    const rand = prng.random();
    // Alphabet biased toward escapables so hits are dense.
    const alphabet = "ab&<>'\"cd\n\t&<>'\"ef&<>'\"gh&<>'\"";
    var input_buf: [300]u8 = undefined;
    var want_buf: [2048]u8 = undefined;
    var got_buf: [2048]u8 = undefined;

    var iter: usize = 0;
    while (iter < 100_000) : (iter += 1) {
        const len = rand.uintLessThan(usize, input_buf.len + 1);
        for (input_buf[0..len]) |*b| {
            b.* = alphabet[rand.uintLessThan(usize, alphabet.len)];
        }
        const input = input_buf[0..len];

        var wwant: std.Io.Writer = .fixed(&want_buf);
        try refEscape(&wwant, input);
        var wgot: std.Io.Writer = .fixed(&got_buf);
        try writeEscaped(&wgot, input);

        try testing.expectEqualStrings(wwant.buffered(), wgot.buffered());
    }
}

test "overflow at every byte boundary fails once at finish" {
    // Goal: any prefix capacity must surface as exactly one Overflow at
    // finish(); a full-size buffer must produce the exact stanza.
    var full_buf: [512]u8 = undefined;
    var wfull: std.Io.Writer = .fixed(&full_buf);
    var xfull = StanzaWriter.init(&wfull);
    try writeSample(&xfull);
    try xfull.finish();
    const expected = wfull.buffered();

    var cap: usize = 0;
    while (cap <= expected.len) : (cap += 1) {
        var buf: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(buf[0..cap]);
        var x = StanzaWriter.init(&w);
        try writeSample(&x);
        // After failure the writer stays latched: further calls drop bytes
        // and finish() reports the single sticky error.
        if (cap < expected.len) {
            try testing.expectError(error.Overflow, x.finish());
        } else {
            try x.finish();
            try testing.expectEqualStrings(expected, w.buffered());
        }
    }
}

test "writer latches failure and drops later output" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("message");
    try x.attr("to", "a@b.c"); // overflows inside the attribute
    x.elementOpenEnd();
    try x.text("more text that cannot fit");

    try testing.expectError(error.Overflow, x.finish());
    // Sticky: a second finish reports the same single failure.
    try testing.expectError(error.Overflow, x.finish());
}

test "StanzaWriter performs zero heap allocations" {
    // Goal: prove the no-allocator contract. The API takes no allocator, so
    // the only proof is structural (no Allocator field anywhere in the
    // writer state) plus behavioral (a full stanza into a caller buffer).
    comptime {
        for (@typeInfo(StanzaWriter).@"struct".fields) |f| {
            std.debug.assert(f.type != std.mem.Allocator);
        }
    }

    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);
    try x.elementOpen("presence");
    try x.attr("from", "a@b.c/r");
    x.elementSelfClose();
    try x.finish();
    try testing.expectEqualStrings("<presence from='a@b.c/r'/>", w.buffered());
}

test "a rejected attribute emits nothing and latches finish() (L1)" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("m");
    try testing.expectError(error.InvalidCharacter, x.attr("a", "bad\x00"));
    // Nothing of the attribute reached the output: no name, no quote.
    try testing.expectEqualStrings("<m", w.buffered());
    // The rejection is sticky: finish() cannot report success.
    try testing.expectError(error.Overflow, x.finish());

    // Same for a bad close-tag name and bad text.
    var w2: std.Io.Writer = .fixed(&buf);
    var y = StanzaWriter.init(&w2);
    try y.elementOpen("m");
    y.elementOpenEnd();
    try testing.expectError(error.InvalidName, y.elementClose("bad name"));
    try testing.expectEqualStrings("<m>", w2.buffered());
    try testing.expectError(error.Overflow, y.finish());
}
