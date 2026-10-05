//! # S2S Session — Per-connection state for inbound S2S federation
//!
//! Wraps a TCP connection with an XML reader, S2S stream FSM, and
//! connection-level state for a single inbound federation session.
//!
//! Mirrors `src/core/server.zig`'s Session struct but for `jabber:server`
//! namespace. The xmppd-s2s daemon manages a table of these.

const std = @import("std");
const posix = std.posix;
const xml = @import("xml");
const stream_mod = @import("stream.zig");
const S2sStream = stream_mod.S2sStream;
const S2sStreamState = stream_mod.S2sStreamState;
const S2sStreamAction = stream_mod.S2sStreamAction;
const S2sFeatureSet = stream_mod.S2sFeatureSet;
const Role = stream_mod.Role;
const connector_mod = @import("connector.zig");
const DaneStatus = connector_mod.DaneStatus;
const ssl = @import("ssl");
const SslConn = ssl.SslConn;
const SslContext = ssl.SslContext;
const dialback_mod = @import("dialback.zig");

/// TLS handshake state for non-blocking integration with kqueue.
pub const TlsState = enum {
    handshake_want_read,
    handshake_want_write,
    established,
};

/// Read buffer size — 8KB per connection.
const READ_BUF_SIZE = 8192;

/// Write buffer size — 16KB per connection.
const WRITE_BUF_SIZE = 16384;

/// An inbound S2S federation session.
pub const S2sSession = struct {
    /// Socket file descriptor.
    fd: posix.fd_t,
    /// Unique session ID (used as kqueue udata).
    id: usize,
    /// S2S stream FSM (receiving role).
    stream: S2sStream,
    /// Whether the connection is closed.
    closed: bool = false,
    /// TLS handshake state for kqueue integration.
    tls_state: ?TlsState = null,
    /// TLS connection — null for plain TCP, set after STARTTLS.
    tls_conn: ?SslConn = null,
    /// Read buffer.
    read_buf: [READ_BUF_SIZE]u8 = undefined,
    read_start: usize = 0,
    read_end: usize = 0,
    /// Write buffer.
    write_buf: [WRITE_BUF_SIZE]u8 = undefined,
    write_start: usize = 0,
    write_end: usize = 0,
    /// Length of the pinned TLS write starting at write_start. While > 0,
    /// flushWrite retries exactly that slice: OpenSSL retains the caller
    /// buffer across WANT_READ/WANT_WRITE (AGENTS.md identical pointer and
    /// length rule), so bytes queued after the stall wait behind it (S23).
    pinned_tls_len: usize = 0,
    /// <proceed/> queued but not fully flushed: the TLS upgrade waits for
    /// the drain (T250 — a partially sent proceed must never reach the
    /// peer through the TLS record layer).
    tls_upgrade_pending: bool = false,
    pending_tls_ctx: ?SslContext = null,
    /// DANE verification status for the peer.
    dane_status: DaneStatus = .pending,
    /// Remote domain (set from stream open).
    remote_domain_buf: [256]u8 = undefined,
    remote_domain_len: usize = 0,
    /// Stream ID we assign to this session.
    stream_id_buf: [32]u8 = undefined,
    stream_id_len: usize = 0,
    /// Pending db:verify tracking for dialback callback verification.
    db_verify_from_buf: [256]u8 = undefined,
    db_verify_from_len: usize = 0,
    db_verify_to_buf: [256]u8 = undefined,
    db_verify_to_len: usize = 0,
    db_verify_id_buf: [64]u8 = undefined,
    db_verify_id_len: usize = 0,
    db_verify_pending: bool = false,

    /// Pending inbound db:result key capture (dialback: remote sends key text).
    db_result_pending: bool = false,
    db_result_from_buf: [256]u8 = undefined,
    db_result_from_len: usize = 0,
    db_result_to_buf: [256]u8 = undefined,
    db_result_to_len: usize = 0,
    db_result_key_buf: [128]u8 = undefined,
    db_result_key_len: usize = 0,

    /// Inbound dialback state tracker.
    inbound_dialback: dialback_mod.InboundDialback = .{},

    /// Inbound stanza accumulation — buffers child XML content for stanzas
    /// received on an established session, to be forwarded to xmppd-core via IPC.
    stanza_active: bool = false,
    stanza_tag_buf: [32]u8 = undefined,
    stanza_tag_len: usize = 0,
    stanza_from_buf: [512]u8 = undefined,
    stanza_from_len: usize = 0,
    stanza_to_buf: [512]u8 = undefined,
    stanza_to_len: usize = 0,
    stanza_type_buf: [32]u8 = undefined,
    stanza_type_len: usize = 0,
    stanza_id_buf: [128]u8 = undefined,
    stanza_id_len: usize = 0,
    stanza_inner_buf: [16384]u8 = undefined,
    stanza_inner_len: usize = 0,

    pub fn init(fd: posix.fd_t, id: usize, local_domain: []const u8) S2sSession {
        var session = S2sSession{
            .fd = fd,
            .id = id,
            .stream = S2sStream.init(.receiving, local_domain),
        };
        // Generate a simple stream ID
        const id_str = std.fmt.bufPrint(&session.stream_id_buf, "s2s-{d}-{d}", .{ id, std.time.milliTimestamp() }) catch "s2s-0";
        session.stream_id_len = id_str.len;
        return session;
    }

    pub fn deinit(self: *S2sSession) void {
        if (!self.closed) {
            if (self.tls_conn) |*tls| {
                tls.shutdown();
                tls.deinit();
                self.tls_conn = null;
            }
            posix.close(self.fd);
            self.closed = true;
        }
    }

    /// Get the stream ID string.
    pub fn getStreamId(self: *const S2sSession) []const u8 {
        return self.stream_id_buf[0..self.stream_id_len];
    }

    /// Get the remote domain (set after stream open).
    pub fn getRemoteDomain(self: *const S2sSession) []const u8 {
        return self.remote_domain_buf[0..self.remote_domain_len];
    }

    /// Start tracking a pending db:verify callback.
    pub fn startDbVerify(self: *S2sSession, from: []const u8, to: []const u8, id: []const u8) void {
        const f_len = @min(from.len, self.db_verify_from_buf.len);
        @memcpy(self.db_verify_from_buf[0..f_len], from[0..f_len]);
        self.db_verify_from_len = f_len;
        const t_len = @min(to.len, self.db_verify_to_buf.len);
        @memcpy(self.db_verify_to_buf[0..t_len], to[0..t_len]);
        self.db_verify_to_len = t_len;
        const i_len = @min(id.len, self.db_verify_id_buf.len);
        @memcpy(self.db_verify_id_buf[0..i_len], id[0..i_len]);
        self.db_verify_id_len = i_len;
        self.db_verify_pending = true;
    }

    pub fn getDbVerifyFrom(self: *const S2sSession) []const u8 {
        return self.db_verify_from_buf[0..self.db_verify_from_len];
    }

    pub fn getDbVerifyTo(self: *const S2sSession) []const u8 {
        return self.db_verify_to_buf[0..self.db_verify_to_len];
    }

    pub fn getDbVerifyId(self: *const S2sSession) []const u8 {
        return self.db_verify_id_buf[0..self.db_verify_id_len];
    }

    /// Start tracking an inbound db:result key submission (for dialback callback).
    pub fn startDbResult(self: *S2sSession, from: []const u8, to: []const u8) void {
        const fl = @min(from.len, self.db_result_from_buf.len);
        @memcpy(self.db_result_from_buf[0..fl], from[0..fl]);
        self.db_result_from_len = fl;
        const tl = @min(to.len, self.db_result_to_buf.len);
        @memcpy(self.db_result_to_buf[0..tl], to[0..tl]);
        self.db_result_to_len = tl;
        self.db_result_key_len = 0;
        self.db_result_pending = true;
    }

    /// Get the db:result from domain.
    pub fn getDbResultFrom(self: *const S2sSession) []const u8 {
        return self.db_result_from_buf[0..self.db_result_from_len];
    }

    /// Get the db:result to domain.
    pub fn getDbResultTo(self: *const S2sSession) []const u8 {
        return self.db_result_to_buf[0..self.db_result_to_len];
    }

    /// Get the accumulated db:result key text.
    pub fn getDbResultKey(self: *const S2sSession) []const u8 {
        return self.db_result_key_buf[0..self.db_result_key_len];
    }

    /// Set the remote domain from the stream open.
    pub fn setRemoteDomain(self: *S2sSession, domain: []const u8) void {
        const copy_len = @min(domain.len, self.remote_domain_buf.len);
        @memcpy(self.remote_domain_buf[0..copy_len], domain[0..copy_len]);
        self.remote_domain_len = copy_len;
    }

    /// Whether the session is authenticated and established.
    pub fn isEstablished(self: *const S2sSession) bool {
        return self.stream.isEstablished();
    }

    /// Whether TLS handshake is in progress.
    pub fn isTlsHandshaking(self: *const S2sSession) bool {
        if (self.tls_state) |state| {
            return state != .established;
        }
        return false;
    }

    /// Receive data from the socket into the read buffer.
    /// Returns number of bytes read, 0 for EOF.
    pub fn recv(self: *S2sSession) !usize {
        if (self.closed) return error.ConnectionClosed;
        // Compact if needed
        if (self.read_start > 0) {
            const remaining = self.read_end - self.read_start;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.read_buf[0..remaining], self.read_buf[self.read_start..self.read_end]);
            }
            self.read_end = remaining;
            self.read_start = 0;
        }
        if (self.read_end >= self.read_buf.len) return error.BufferFull;

        const buf = self.read_buf[self.read_end..];

        if (self.tls_conn) |*tls| {
            const result = tls.read(buf) catch |err| {
                return switch (err) {
                    ssl.SslError.ConnectionClosed => @as(usize, 0),
                    else => error.ConnectionReset,
                };
            };
            return switch (result) {
                .ok => |n| blk: {
                    self.read_end += n;
                    break :blk n;
                },
                .want_read => error.WouldBlock,
                .want_write => error.WouldBlock,
            };
        }

        const n = posix.read(self.fd, buf) catch |err| {
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                else => error.ConnectionReset,
            };
        };
        if (n == 0) return 0; // EOF
        self.read_end += n;
        return n;
    }

    /// Get the readable portion of the read buffer.
    pub fn readableSlice(self: *const S2sSession) []const u8 {
        return self.read_buf[self.read_start..self.read_end];
    }

    /// Mark bytes as consumed from the read buffer.
    pub fn consume(self: *S2sSession, n: usize) void {
        self.read_start += n;
    }

    /// Queue data to the write buffer.
    pub fn queueWrite(self: *S2sSession, data: []const u8) !void {
        if (self.closed) return error.ConnectionClosed;
        const available = self.write_buf.len - self.write_end;
        if (data.len > available) return error.BufferFull;
        @memcpy(self.write_buf[self.write_end .. self.write_end + data.len], data);
        self.write_end += data.len;
    }

    /// Flush the write buffer to the socket.
    /// Returns true if all data was flushed.
    ///
    /// When a TLS write stalls, this retries only the pinned prefix; bytes
    /// queued after the stall are flushed by later calls once the pin
    /// releases. The TLS record layer never sees a slice that differs from
    /// the stalled one in pointer or length (S23).
    pub fn flushWrite(self: *S2sSession) !bool {
        if (self.closed) return error.ConnectionClosed;
        if (self.write_start >= self.write_end) return true; // Nothing to write

        const flush_end = if (self.pinned_tls_len > 0)
            self.write_start + self.pinned_tls_len
        else
            self.write_end;
        const data = self.write_buf[self.write_start..flush_end];

        if (self.tls_conn) |*tls| {
            const result = tls.write(data) catch |err| {
                return switch (err) {
                    ssl.SslError.WriteFailed => error.ConnectionReset,
                    else => error.ConnectionReset,
                };
            };
            switch (result) {
                .ok => |n| {
                    self.write_start += n;
                    self.pinned_tls_len -|= n;
                    if (self.write_start >= self.write_end) {
                        self.write_start = 0;
                        self.write_end = 0;
                        self.pinned_tls_len = 0;
                        return true;
                    }
                    return false;
                },
                .want_read, .want_write => {
                    // OpenSSL retains the caller buffer across the retry;
                    // pin the exact slice and let nothing grow it.
                    self.pinned_tls_len = data.len;
                    return false;
                },
            }
        }

        const n = posix.write(self.fd, data) catch |err| {
            return switch (err) {
                error.WouldBlock => false,
                else => error.ConnectionReset,
            };
        };
        self.write_start += n;
        if (self.write_start >= self.write_end) {
            self.write_start = 0;
            self.write_end = 0;
            return true;
        }
        return false;
    }

    /// Whether there is pending write data.
    pub fn hasPendingWrite(self: *const S2sSession) bool {
        return self.write_start < self.write_end;
    }

    /// Upgrade this session to TLS using the server-side context.
    /// Initiates a non-blocking handshake.
    pub fn upgradeToTls(self: *S2sSession, ctx: SslContext) !void {
        self.tls_conn = SslConn.init(ctx, self.fd) catch return error.TlsInitFailed;
        self.tls_state = .handshake_want_read;
    }

    /// Continue a non-blocking TLS handshake.
    /// Returns true when the handshake is complete.
    pub fn continueHandshake(self: *S2sSession) !bool {
        if (self.tls_conn) |*tls| {
            const result = tls.doHandshake() catch return error.HandshakeFailed;
            switch (result) {
                .complete => {
                    self.tls_state = .established;
                    return true;
                },
                .want_read => {
                    self.tls_state = .handshake_want_read;
                    return false;
                },
                .want_write => {
                    self.tls_state = .handshake_want_write;
                    return false;
                },
            }
        }
        return error.NoTlsConnection;
    }

    /// Close the session.
    pub fn close(self: *S2sSession) void {
        if (!self.closed) {
            if (self.tls_conn) |*tls| {
                tls.shutdown();
                tls.deinit();
                self.tls_conn = null;
            }
            posix.close(self.fd);
            self.closed = true;
        }
    }

    /// Build the stream open response XML for an inbound connection.
    /// id/from are our own bytes, but `to` is the peer-supplied stream-open
    /// from= value — escaped like any client/peer-controlled attribute (S1).
    pub fn buildStreamOpenResponse(self: *const S2sSession, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("<?xml version='1.0'?><stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' from='");
        try xmlEscapeWrite(writer, self.stream.local_domain);
        try writer.writeAll("' to='");
        try xmlEscapeWrite(writer, self.getRemoteDomain());
        try writer.writeAll("' id='");
        try xmlEscapeWrite(writer, self.getStreamId());
        try writer.writeAll("' version='1.0'>");
        return fbs.getWritten();
    }

    /// Build stream features XML for the current state.
    pub fn buildFeatures(self: *const S2sSession, buf: []u8) ![]const u8 {
        const features = self.stream.getFeatures() orelse return buf[0..0];
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("<stream:features>");
        if (features.starttls_required) {
            try writer.writeAll("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>");
        }
        if (features.sasl_external) {
            try writer.writeAll("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms>");
        }
        if (features.dialback) {
            try writer.writeAll("<db:features><db:dialback/></db:features>");
        }
        try writer.writeAll("</stream:features>");
        return fbs.getWritten();
    }

    /// Build a SASL success response.
    pub fn buildSaslSuccess(_: *const S2sSession, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
        return fbs.getWritten();
    }

    /// Build a SASL failure response.
    pub fn buildSaslFailure(_: *const S2sSession, buf: []u8, reason: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><");
        try writer.writeAll(reason);
        try writer.writeAll("/></failure>");
        return fbs.getWritten();
    }

    /// Build a STARTTLS proceed response.
    pub fn buildTlsProceed(_: *const S2sSession, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
        return fbs.getWritten();
    }

    /// Build a stream error response.
    pub fn buildStreamError(_: *const S2sSession, buf: []u8, error_name: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("<stream:error><");
        try writer.writeAll(error_name);
        try writer.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>");
        return fbs.getWritten();
    }

    // ========================================================================
    // Inbound stanza accumulation
    // ========================================================================

    /// Begin accumulating a new inbound stanza. Called when element_start for
    /// message/presence/iq is seen on an established session.
    pub fn startStanza(self: *S2sSession, elem: xml.Element) void {
        self.stanza_active = true;
        self.stanza_inner_len = 0;
        // Tag name
        const tl = @min(elem.local_name.len, self.stanza_tag_buf.len);
        @memcpy(self.stanza_tag_buf[0..tl], elem.local_name[0..tl]);
        self.stanza_tag_len = tl;
        // Extract from/to/type/id attributes
        self.stanza_from_len = 0;
        self.stanza_to_len = 0;
        self.stanza_type_len = 0;
        self.stanza_id_len = 0;
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "from")) {
                const fl = @min(attr.value.len, self.stanza_from_buf.len);
                @memcpy(self.stanza_from_buf[0..fl], attr.value[0..fl]);
                self.stanza_from_len = fl;
            } else if (std.mem.eql(u8, attr.local_name, "to")) {
                const tol = @min(attr.value.len, self.stanza_to_buf.len);
                @memcpy(self.stanza_to_buf[0..tol], attr.value[0..tol]);
                self.stanza_to_len = tol;
            } else if (std.mem.eql(u8, attr.local_name, "type")) {
                const tyl = @min(attr.value.len, self.stanza_type_buf.len);
                @memcpy(self.stanza_type_buf[0..tyl], attr.value[0..tyl]);
                self.stanza_type_len = tyl;
            } else if (std.mem.eql(u8, attr.local_name, "id")) {
                const il = @min(attr.value.len, self.stanza_id_buf.len);
                @memcpy(self.stanza_id_buf[0..il], attr.value[0..il]);
                self.stanza_id_len = il;
            }
        }
    }

    /// Accumulate a child element opening tag into the stanza inner buffer.
    pub fn accumulateElement(self: *S2sSession, elem: xml.Element) void {
        var fbs = std.io.fixedBufferStream(self.stanza_inner_buf[self.stanza_inner_len..]);
        const w = fbs.writer();
        w.writeByte('<') catch return;
        w.writeAll(elem.name) catch return;
        for (elem.attributes) |attr| {
            w.writeByte(' ') catch return;
            w.writeAll(attr.name) catch return;
            w.writeAll("='") catch return;
            xmlEscapeWrite(w, attr.value) catch return;
            w.writeByte('\'') catch return;
        }
        if (elem.self_closing) {
            w.writeAll("/>") catch return;
        } else {
            w.writeByte('>') catch return;
        }
        self.stanza_inner_len += fbs.pos;
    }

    /// Accumulate text content (XML-escaped) into the stanza inner buffer.
    pub fn accumulateText(self: *S2sSession, text: []const u8) void {
        var fbs = std.io.fixedBufferStream(self.stanza_inner_buf[self.stanza_inner_len..]);
        xmlEscapeWrite(fbs.writer(), text) catch return;
        self.stanza_inner_len += fbs.pos;
    }

    /// Accumulate a child element close tag into the stanza inner buffer.
    pub fn accumulateClose(self: *S2sSession, name: []const u8) void {
        var fbs = std.io.fixedBufferStream(self.stanza_inner_buf[self.stanza_inner_len..]);
        const w = fbs.writer();
        w.writeAll("</") catch return;
        w.writeAll(name) catch return;
        w.writeByte('>') catch return;
        self.stanza_inner_len += fbs.pos;
    }

    /// Reset stanza accumulation state.
    pub fn resetStanza(self: *S2sSession) void {
        self.stanza_active = false;
        self.stanza_inner_len = 0;
        self.stanza_tag_len = 0;
        self.stanza_from_len = 0;
        self.stanza_to_len = 0;
        self.stanza_type_len = 0;
        self.stanza_id_len = 0;
    }

    /// Get the accumulated stanza tag name.
    pub fn getStanzaTag(self: *const S2sSession) []const u8 {
        return self.stanza_tag_buf[0..self.stanza_tag_len];
    }

    /// Get the accumulated stanza 'from' attribute.
    pub fn getStanzaFrom(self: *const S2sSession) []const u8 {
        return self.stanza_from_buf[0..self.stanza_from_len];
    }

    /// Get the accumulated stanza 'to' attribute.
    pub fn getStanzaTo(self: *const S2sSession) []const u8 {
        return self.stanza_to_buf[0..self.stanza_to_len];
    }

    /// Get the accumulated stanza 'type' attribute.
    pub fn getStanzaType(self: *const S2sSession) []const u8 {
        return self.stanza_type_buf[0..self.stanza_type_len];
    }

    /// Get the accumulated stanza 'id' attribute.
    pub fn getStanzaId(self: *const S2sSession) []const u8 {
        return self.stanza_id_buf[0..self.stanza_id_len];
    }

    /// Get the accumulated inner XML content.
    pub fn getStanzaInner(self: *const S2sSession) []const u8 {
        return self.stanza_inner_buf[0..self.stanza_inner_len];
    }

    /// Build the complete stanza XML from accumulated parts.
    pub fn buildStanzaXml(self: *const S2sSession, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeByte('<');
        try w.writeAll(self.getStanzaTag());
        // from/to/type/id carry peer input — entity-decoded by the parser, so
        // they must be re-escaped on the way out (S1 injection guard).
        if (self.stanza_from_len > 0) {
            try w.writeAll(" from='");
            try xmlEscapeWrite(w, self.getStanzaFrom());
            try w.writeByte('\'');
        }
        if (self.stanza_to_len > 0) {
            try w.writeAll(" to='");
            try xmlEscapeWrite(w, self.getStanzaTo());
            try w.writeByte('\'');
        }
        if (self.stanza_type_len > 0) {
            try w.writeAll(" type='");
            try xmlEscapeWrite(w, self.getStanzaType());
            try w.writeByte('\'');
        }
        if (self.stanza_id_len > 0) {
            try w.writeAll(" id='");
            try xmlEscapeWrite(w, self.getStanzaId());
            try w.writeByte('\'');
        }
        if (self.stanza_inner_len == 0) {
            try w.writeAll("/>");
        } else {
            try w.writeByte('>');
            try w.writeAll(self.getStanzaInner());
            try w.writeAll("</");
            try w.writeAll(self.getStanzaTag());
            try w.writeByte('>');
        }
        return fbs.getWritten();
    }
};

/// Re-encode text for XML output (entities like &amp; must be re-escaped).
/// Shared by the s2s builders in this directory; folds into lib/xml's
/// escapeWrite once the S1 core-side merge lands (openhands lane).
pub fn xmlEscapeWrite(writer: anytype, text: []const u8) !void {
    for (text) |c| {
        switch (c) {
            '&' => try writer.writeAll("&amp;"),
            '<' => try writer.writeAll("&lt;"),
            '>' => try writer.writeAll("&gt;"),
            '\'' => try writer.writeAll("&apos;"),
            '"' => try writer.writeAll("&quot;"),
            else => try writer.writeByte(c),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "S2sSession: init and basic state" {
    var session = S2sSession.init(-1, 42, "a.example");
    try std.testing.expectEqual(@as(usize, 42), session.id);
    try std.testing.expect(!session.isEstablished());
    try std.testing.expect(!session.isTlsHandshaking());
    try std.testing.expect(session.getStreamId().len > 0);
    session.closed = true; // prevent close() on invalid fd
}

test "S2sSession: set and get remote domain" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    session.setRemoteDomain("b.example");
    try std.testing.expectEqualStrings("b.example", session.getRemoteDomain());
}

test "S2sSession: buildStreamOpenResponse" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    session.setRemoteDomain("b.example");
    var buf: [1024]u8 = undefined;
    const out = try session.buildStreamOpenResponse(&buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "xmlns='jabber:server'") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "from='a.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "to='b.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "version='1.0'") != null);
}

test "S2sSession: buildFeatures — TLS required" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    // Set stream to features_tls state
    _ = session.stream.handleStreamOpen("b.example", "a.example", "1.0");
    var buf: [1024]u8 = undefined;
    const out = try session.buildFeatures(&buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "<starttls") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<required/>") != null);
}

test "S2sSession: buildFeatures — auth with DANE" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    _ = session.stream.handleStreamOpen("b.example", "a.example", "1.0");
    _ = session.stream.handleStarttls();
    session.stream.tlsEstablished();
    session.stream.setDaneVerified(true);
    _ = session.stream.handleStreamOpen("b.example", "a.example", "1.0");
    var buf: [1024]u8 = undefined;
    const out = try session.buildFeatures(&buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "EXTERNAL") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "dialback") == null);
}

test "S2sSession: buildFeatures — auth without DANE" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    _ = session.stream.handleStreamOpen("b.example", "a.example", "1.0");
    _ = session.stream.handleStarttls();
    session.stream.tlsEstablished();
    session.stream.setDaneVerified(false);
    _ = session.stream.handleStreamOpen("b.example", "a.example", "1.0");
    var buf: [1024]u8 = undefined;
    const out = try session.buildFeatures(&buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "dialback") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "EXTERNAL") == null);
}

test "S2sSession: buildSaslSuccess" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    var buf: [256]u8 = undefined;
    const out = try session.buildSaslSuccess(&buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "<success") != null);
}

test "S2sSession: buildSaslFailure" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    var buf: [256]u8 = undefined;
    const out = try session.buildSaslFailure(&buf, "not-authorized");
    try std.testing.expect(std.mem.indexOf(u8, out, "not-authorized") != null);
}

test "S2sSession: buildTlsProceed" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    var buf: [256]u8 = undefined;
    const out = try session.buildTlsProceed(&buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "<proceed") != null);
}

test "S2sSession: stream-open response escapes peer-controlled and local attrs (S1)" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true; // no real fd — nothing to close on teardown
    session.setRemoteDomain("bad' to='injected.attacker.example' x='");
    var buf: [512]u8 = undefined;
    const out = try session.buildStreamOpenResponse(&buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "&apos;") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "injected.attacker.example' x='") == null);
}

test "S2sSession: stanza from/to/type/id attrs are re-escaped (S1)" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true; // no real fd
    session.startStanza(.{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:client",
        .attributes = &.{.{ .name = "to", .local_name = "to", .prefix = "", .value = "x'=x'" }},
        .self_closing = false,
    });
    var buf: [512]u8 = undefined;
    const out = try session.buildStanzaXml(&buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "x&apos;=x&apos;") != null);
}

test "S2sSession: buildStreamError" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    var buf: [512]u8 = undefined;
    const out = try session.buildStreamError(&buf, "host-unknown");
    try std.testing.expect(std.mem.indexOf(u8, out, "host-unknown") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "</stream:stream>") != null);
}

test "S2sSession: write buffer operations" {
    // Use a socketpair for testing
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[1]);

    var session = S2sSession.init(fds[0], 1, "a.example");
    defer session.close();

    try session.queueWrite("hello");
    try std.testing.expect(session.hasPendingWrite());

    const flushed = try session.flushWrite();
    try std.testing.expect(flushed);
    try std.testing.expect(!session.hasPendingWrite());
}

test "S2sSession: recv into read buffer" {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[1]);

    var session = S2sSession.init(fds[0], 1, "a.example");
    defer session.close();

    // Write to the other end
    _ = try posix.write(fds[1], "test data");
    std.Thread.sleep(5 * std.time.ns_per_ms);

    const n = try session.recv();
    try std.testing.expect(n > 0);
    const data = session.readableSlice();
    try std.testing.expectEqualStrings("test data", data[0..9]);
    session.consume(9);
}

// --- S23: pinned TLS write retry under backpressure -----------------------

/// Self-signed throwaway cert+key for "localhost" via the openssl CLI (no
/// key material in the tree). error.SkipZigTest when the tool is missing.
fn genTestTlsCert(dir: std.fs.Dir) !void {
    const r = std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{ "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1", "-keyout", "key.pem", "-out", "cert.pem" },
        .cwd_dir = dir,
        .max_output_bytes = 4096,
    }) catch return error.SkipZigTest;
    defer std.testing.allocator.free(r.stdout);
    defer std.testing.allocator.free(r.stderr);
    switch (r.term) {
        .Exited => |code| {
            if (code != 0) return error.SkipZigTest;
        },
        else => return error.SkipZigTest,
    }
}

/// Drive both ends of a non-blocking TLS pair until the handshake finishes.
fn driveTestTlsHandshake(server: *SslConn, client: *SslConn) !void {
    const deadline = std.time.milliTimestamp() + 5000;
    var s_done = false;
    var c_done = false;
    while ((!s_done or !c_done) and std.time.milliTimestamp() < deadline) {
        if (!s_done) s_done = (try server.doHandshake()) == .complete;
        if (!c_done) c_done = (try client.doHandshake()) == .complete;
    }
    if (!s_done or !c_done) return error.TlsHandshakeTimeout;
}

/// Connected non-blocking TCP loopback pair for TLS test rigs. AF_UNIX
/// socketpairs do not enforce SO_SNDBUF strictly on stream sockets, so the
/// backpressure rig needs real TCP.
fn makeTestTcpPair() ![2]posix.fd_t {
    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return error.SocketFailed;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return error.BindFailed;
    posix.listen(listen_fd, 1) catch return error.ListenFailed;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return error.GetSockNameFailed;

    const client_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0) catch return error.SocketFailed;
    errdefer posix.close(client_fd);
    posix.connect(client_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch |err| switch (err) {
        error.WouldBlock => {},
        else => return error.ConnectFailed,
    };
    const server_fd = posix.accept(listen_fd, null, null, posix.SOCK.NONBLOCK) catch return error.AcceptFailed;
    errdefer posix.close(server_fd);

    // nodelay keeps the interleaved drive loop free of delayed-ACK stalls.
    const nodelay: c_int = 1;
    try posix.setsockopt(client_fd, 6, 1, std.mem.asBytes(&nodelay)); // IPPROTO_TCP, TCP_NODELAY
    try posix.setsockopt(server_fd, 6, 1, std.mem.asBytes(&nodelay));
    return .{ client_fd, server_fd };
}

test "S2sSession: stalled TLS write pins its slice; bytes queued behind it still arrive (S23)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestTlsCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/cert.pem", .{base}, 0);
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/key.pem", .{base}, 0);
    defer std.testing.allocator.free(key_path);

    const fds = try makeTestTcpPair();

    // Tiny send buffer on the session side forces TLS write backpressure.
    const head_len = 8192;
    const sndbuf: c_int = 2048;
    try posix.setsockopt(fds[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf));
    var actual_sndbuf: c_int = 0;
    var optlen: posix.socklen_t = @sizeOf(c_int);
    if (std.c.getsockopt(fds[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&actual_sndbuf), &optlen) != 0)
        return error.SkipZigTest;
    // One ~8 KiB TLS record must not fit, or the rig cannot stall the write.
    if (actual_sndbuf >= head_len) return error.SkipZigTest;

    // kTLS stays off on both ends: two kTLS peers over lo0 hit FreeBSD
    // PR 296498 (EBADMSG). This rig is entirely userland TLS.
    var server_ctx = try SslContext.initServer(cert_path, key_path);
    defer server_ctx.deinit();
    server_ctx.disableKtls();
    var client_ctx = try SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls();

    var session = S2sSession.init(fds[0], 1, "a.example");
    defer session.close(); // also closes fds[0]
    session.tls_conn = try SslConn.init(server_ctx, fds[0]);
    session.tls_state = .established;
    var client = try SslConn.initClient(client_ctx, fds[1], null);
    defer {
        client.deinit();
        posix.close(fds[1]);
    }
    try driveTestTlsHandshake(&session.tls_conn.?, &client);

    var head: [head_len]u8 = undefined;
    for (&head, 0..) |*b, i| b.* = @truncate(i);
    const tail = "TAIL-AFTER-PINNED-WRITE";

    // First flush exceeds the send buffer: it must stall and pin the slice.
    try session.queueWrite(&head);
    try std.testing.expect(!(try session.flushWrite()));
    try std.testing.expectEqual(@as(usize, head_len), session.pinned_tls_len);

    // Queue while pinned: the tail must wait behind the pinned slice, not
    // grow the retry.
    try session.queueWrite(tail);

    var received: [head_len + tail.len]u8 = undefined;
    var got: usize = 0;
    var chunk: [4096]u8 = undefined;
    const deadline = std.time.milliTimestamp() + 5000;
    while (got < received.len and std.time.milliTimestamp() < deadline) {
        if (session.hasPendingWrite()) {
            _ = session.flushWrite() catch return error.FlushFailed;
        }
        const rr = client.read(&chunk) catch return error.PeerReadFailed;
        switch (rr) {
            .ok => |n| {
                @memcpy(received[got .. got + n], chunk[0..n]);
                got += n;
            },
            .want_read, .want_write => {},
        }
    }
    try std.testing.expectEqual(received.len, got);
    try std.testing.expect(std.mem.eql(u8, &head, received[0..head_len]));
    try std.testing.expectEqualStrings(tail, received[head_len..][0..tail.len]);
    try std.testing.expectEqual(@as(usize, 0), session.pinned_tls_len);
    try std.testing.expect(!session.hasPendingWrite());
}

test "S2sSession: isTlsHandshaking" {
    var session = S2sSession.init(-1, 1, "a.example");
    session.closed = true;
    try std.testing.expect(!session.isTlsHandshaking());

    session.tls_state = .handshake_want_read;
    try std.testing.expect(session.isTlsHandshaking());

    session.tls_state = .established;
    try std.testing.expect(!session.isTlsHandshaking());
}
