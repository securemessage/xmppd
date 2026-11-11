//! Token: generational address for slot-map entries and kqueue udata (ADR-4).
//!
//! A Token names one slot in one table at one generation. A token whose slot
//! has been freed and reused is stale: the generation check makes it fail to
//! resolve, so a stale token can never address the wrong object. Tokens are
//! the only lib/net values meant to cross threads; the owning thread validates
//! each one on arrival.
//!
//! Generation zero is never issued, so `Token.none` (and a zeroed udata field)
//! never resolves in any table.

const std = @import("std");

pub const Token = packed struct(u64) {
    index: u32,
    gen: u24,
    kind: u8,

    pub const none: Token = .{ .index = 0, .gen = 0, .kind = 0 };

    // kevent udata is uintptr_t; a Token rides inside it whole.
    comptime {
        std.debug.assert(@sizeOf(usize) == 8);
        std.debug.assert(@sizeOf(@This()) == 8);
    }

    pub fn toUdata(token: Token) usize {
        return @as(u64, @bitCast(token));
    }

    pub fn fromUdata(udata: usize) Token {
        return @bitCast(udata);
    }

    pub fn eql(a: Token, b: Token) bool {
        return a.index == b.index and a.gen == b.gen and a.kind == b.kind;
    }
};

test "Token: none is zero and never matches an issued token" {
    const issued: Token = .{ .index = 0, .gen = 1, .kind = 7 };
    try std.testing.expect(!issued.eql(.none));
    try std.testing.expectEqual(@as(usize, 0), Token.none.toUdata());
    try std.testing.expect(Token.none.eql(Token.fromUdata(0)));
}

test "Token: toUdata/fromUdata round trip" {
    const t: Token = .{ .index = 0xDEADBEEF, .gen = 0xABCDEF, .kind = 0x12 };
    try std.testing.expect(t.eql(Token.fromUdata(t.toUdata())));
}
