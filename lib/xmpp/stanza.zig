const std = @import("std");
const Jid = @import("jid.zig").Jid;

/// XMPP stanza types per RFC 6120/6121.
pub const StanzaType = enum {
    message,
    presence,
    iq,
};

/// Message stanza types per RFC 6121 Section 5.2.2.
pub const MessageType = enum {
    chat,
    error_msg,
    groupchat,
    headline,
    normal,

    pub fn fromString(s: []const u8) MessageType {
        if (std.mem.eql(u8, s, "chat")) return .chat;
        if (std.mem.eql(u8, s, "error")) return .error_msg;
        if (std.mem.eql(u8, s, "groupchat")) return .groupchat;
        if (std.mem.eql(u8, s, "headline")) return .headline;
        return .normal;
    }

    pub fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .chat => "chat",
            .error_msg => "error",
            .groupchat => "groupchat",
            .headline => "headline",
            .normal => "normal",
        };
    }
};

/// Presence stanza types per RFC 6121 Section 4.7.1.
pub const PresenceType = enum {
    available,
    unavailable,
    subscribe,
    subscribed,
    unsubscribe,
    unsubscribed,
    probe,
    error_pres,

    pub fn fromString(s: []const u8) PresenceType {
        if (s.len == 0) return .available; // No type = available
        if (std.mem.eql(u8, s, "unavailable")) return .unavailable;
        if (std.mem.eql(u8, s, "subscribe")) return .subscribe;
        if (std.mem.eql(u8, s, "subscribed")) return .subscribed;
        if (std.mem.eql(u8, s, "unsubscribe")) return .unsubscribe;
        if (std.mem.eql(u8, s, "unsubscribed")) return .unsubscribed;
        if (std.mem.eql(u8, s, "probe")) return .probe;
        if (std.mem.eql(u8, s, "error")) return .error_pres;
        return .available;
    }

    pub fn toString(self: PresenceType) []const u8 {
        return switch (self) {
            .available => "",
            .unavailable => "unavailable",
            .subscribe => "subscribe",
            .subscribed => "subscribed",
            .unsubscribe => "unsubscribe",
            .unsubscribed => "unsubscribed",
            .probe => "probe",
            .error_pres => "error",
        };
    }
};

/// IQ stanza types per RFC 6120 Section 8.2.3.
pub const IqType = enum {
    get,
    set,
    result,
    error_iq,

    pub fn fromString(s: []const u8) !IqType {
        if (std.mem.eql(u8, s, "get")) return .get;
        if (std.mem.eql(u8, s, "set")) return .set;
        if (std.mem.eql(u8, s, "result")) return .result;
        if (std.mem.eql(u8, s, "error")) return .error_iq;
        return error.InvalidIqType;
    }

    pub fn toString(self: IqType) []const u8 {
        return switch (self) {
            .get => "get",
            .set => "set",
            .result => "result",
            .error_iq => "error",
        };
    }
};

/// Presence show values per RFC 6121 Section 4.7.2.1.
pub const PresenceShow = enum {
    none,
    away,
    chat,
    dnd,
    xa,

    pub fn fromString(s: []const u8) PresenceShow {
        if (std.mem.eql(u8, s, "away")) return .away;
        if (std.mem.eql(u8, s, "chat")) return .chat;
        if (std.mem.eql(u8, s, "dnd")) return .dnd;
        if (std.mem.eql(u8, s, "xa")) return .xa;
        return .none;
    }
};

/// Common stanza header fields shared by all stanza types.
pub const StanzaHeader = struct {
    /// Stanza ID
    id: []const u8 = "",
    /// Sender JID
    from: ?Jid = null,
    /// Recipient JID
    to: ?Jid = null,
    /// Language (xml:lang)
    lang: []const u8 = "",
};

/// A parsed message stanza.
pub const Message = struct {
    header: StanzaHeader = .{},
    type: MessageType = .normal,
    /// Message body text
    body: []const u8 = "",
    /// Message subject
    subject: []const u8 = "",
    /// Thread ID
    thread: []const u8 = "",
};

/// A parsed presence stanza.
pub const Presence = struct {
    header: StanzaHeader = .{},
    type: PresenceType = .available,
    show: PresenceShow = .none,
    status: []const u8 = "",
    priority: i8 = 0,
};

/// A parsed IQ stanza.
pub const Iq = struct {
    header: StanzaHeader = .{},
    type: IqType = .get,
    /// The namespace of the child element (payload)
    payload_ns: []const u8 = "",
    /// The local name of the child element
    payload_name: []const u8 = "",
};

/// A generic stanza that can be any of the three types.
pub const Stanza = union(StanzaType) {
    message: Message,
    presence: Presence,
    iq: Iq,

    pub fn header(self: Stanza) StanzaHeader {
        return switch (self) {
            .message => |m| m.header,
            .presence => |p| p.header,
            .iq => |i| i.header,
        };
    }

    pub fn id(self: Stanza) []const u8 {
        return self.header().id;
    }

    pub fn from(self: Stanza) ?Jid {
        return self.header().from;
    }

    pub fn to(self: Stanza) ?Jid {
        return self.header().to;
    }
};

/// Serialize a stanza to XML.
pub fn serializeMessage(msg: Message, writer: anytype) !void {
    try writer.writeAll("<message");
    try writeStanzaHeader(msg.header, writer);
    if (msg.type != .normal) {
        try writer.writeAll(" type='");
        try writer.writeAll(msg.type.toString());
        try writer.writeByte('\'');
    }
    try writer.writeByte('>');

    if (msg.body.len > 0) {
        try writer.writeAll("<body>");
        try writeXmlEscaped(msg.body, writer);
        try writer.writeAll("</body>");
    }

    if (msg.subject.len > 0) {
        try writer.writeAll("<subject>");
        try writeXmlEscaped(msg.subject, writer);
        try writer.writeAll("</subject>");
    }

    if (msg.thread.len > 0) {
        try writer.writeAll("<thread>");
        try writeXmlEscaped(msg.thread, writer);
        try writer.writeAll("</thread>");
    }

    try writer.writeAll("</message>");
}

pub fn serializePresence(pres: Presence, writer: anytype) !void {
    try writer.writeAll("<presence");
    try writeStanzaHeader(pres.header, writer);
    const type_str = pres.type.toString();
    if (type_str.len > 0) {
        try writer.writeAll(" type='");
        try writer.writeAll(type_str);
        try writer.writeByte('\'');
    }

    // Self-close if no children needed
    if (pres.show == .none and pres.status.len == 0 and pres.priority == 0) {
        try writer.writeAll("/>");
        return;
    }

    try writer.writeByte('>');

    if (pres.show != .none) {
        try writer.writeAll("<show>");
        try writer.writeAll(@tagName(pres.show));
        try writer.writeAll("</show>");
    }

    if (pres.status.len > 0) {
        try writer.writeAll("<status>");
        try writeXmlEscaped(pres.status, writer);
        try writer.writeAll("</status>");
    }

    if (pres.priority != 0) {
        try writer.writeAll("<priority>");
        try std.fmt.format(writer, "{d}", .{pres.priority});
        try writer.writeAll("</priority>");
    }

    try writer.writeAll("</presence>");
}

pub fn serializeIq(iq_stanza: Iq, writer: anytype) !void {
    try writer.writeAll("<iq");
    try writeStanzaHeader(iq_stanza.header, writer);
    try writer.writeAll(" type='");
    try writer.writeAll(iq_stanza.type.toString());
    try writer.writeByte('\'');
    try writer.writeAll("/>");
}

fn writeStanzaHeader(hdr: StanzaHeader, writer: anytype) !void {
    if (hdr.id.len > 0) {
        try writer.writeAll(" id='");
        try writeXmlEscaped(hdr.id, writer);
        try writer.writeByte('\'');
    }
    if (hdr.from) |from_jid| {
        try writer.writeAll(" from='");
        try writeJid(from_jid, writer);
        try writer.writeByte('\'');
    }
    if (hdr.to) |to_jid| {
        try writer.writeAll(" to='");
        try writeJid(to_jid, writer);
        try writer.writeByte('\'');
    }
    if (hdr.lang.len > 0) {
        try writer.writeAll(" xml:lang='");
        try writer.writeAll(hdr.lang);
        try writer.writeByte('\'');
    }
}

fn writeJid(jid: Jid, writer: anytype) !void {
    if (jid.local.len > 0) {
        try writer.writeAll(jid.local);
        try writer.writeByte('@');
    }
    try writer.writeAll(jid.domain);
    if (jid.resource.len > 0) {
        try writer.writeByte('/');
        try writer.writeAll(jid.resource);
    }
}

fn writeXmlEscaped(s: []const u8, writer: anytype) !void {
    for (s) |c| {
        switch (c) {
            '<' => try writer.writeAll("&lt;"),
            '>' => try writer.writeAll("&gt;"),
            '&' => try writer.writeAll("&amp;"),
            '\'' => try writer.writeAll("&apos;"),
            '"' => try writer.writeAll("&quot;"),
            else => try writer.writeByte(c),
        }
    }
}

// --- Tests ---

test "MessageType conversion" {
    try std.testing.expectEqual(MessageType.chat, MessageType.fromString("chat"));
    try std.testing.expectEqual(MessageType.groupchat, MessageType.fromString("groupchat"));
    try std.testing.expectEqual(MessageType.normal, MessageType.fromString("unknown"));
    try std.testing.expectEqualStrings("chat", MessageType.chat.toString());
}

test "PresenceType conversion" {
    try std.testing.expectEqual(PresenceType.available, PresenceType.fromString(""));
    try std.testing.expectEqual(PresenceType.unavailable, PresenceType.fromString("unavailable"));
    try std.testing.expectEqual(PresenceType.subscribe, PresenceType.fromString("subscribe"));
}

test "IqType conversion" {
    const get = try IqType.fromString("get");
    try std.testing.expectEqual(IqType.get, get);
    try std.testing.expectEqualStrings("get", get.toString());
    try std.testing.expectError(error.InvalidIqType, IqType.fromString("bogus"));
}

test "serialize message" {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const msg = Message{
        .header = .{
            .id = "msg1",
            .from = try Jid.parse("alice@example.com/mobile"),
            .to = try Jid.parse("bob@example.com"),
        },
        .type = .chat,
        .body = "Hello, Bob!",
    };

    try serializeMessage(msg, fbs.writer());
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "<message") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "id='msg1'") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "type='chat'") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<body>Hello, Bob!</body>") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "</message>") != null);
}

test "serialize self-closing presence" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const pres = Presence{
        .header = .{
            .from = try Jid.parse("alice@example.com/mobile"),
        },
        .type = .available,
    };

    try serializePresence(pres, fbs.writer());
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "<presence") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "/>") != null);
}

test "serialize presence with show" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const pres = Presence{
        .header = .{
            .from = try Jid.parse("alice@example.com"),
        },
        .show = .dnd,
        .status = "Do not disturb",
    };

    try serializePresence(pres, fbs.writer());
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "<show>dnd</show>") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<status>Do not disturb</status>") != null);
}

test "XML escaping in message body" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const msg = Message{
        .header = .{ .id = "esc1" },
        .body = "x < y & z > w",
    };

    try serializeMessage(msg, fbs.writer());
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "x &lt; y &amp; z &gt; w") != null);
}

test "Stanza union access" {
    const msg = Stanza{ .message = Message{
        .header = .{ .id = "test1", .to = try Jid.parse("bob@example.com") },
        .type = .chat,
        .body = "hi",
    } };

    try std.testing.expectEqualStrings("test1", msg.id());
    try std.testing.expectEqualStrings("bob", msg.to().?.local);
}
