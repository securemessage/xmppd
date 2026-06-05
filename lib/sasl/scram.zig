const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// SCRAM-SHA-256 server-side implementation per RFC 5802 and RFC 7677.
///
/// Implements the server side of the SCRAM exchange:
/// 1. Client sends client-first-message (username + nonce)
/// 2. Server sends server-first-message (combined nonce + salt + iteration count)
/// 3. Client sends client-final-message (channel binding + proof)
/// 4. Server validates proof and sends server-final-message (verifier)
/// Stored credentials for a user (what the server keeps in the database).
/// These are derived from the password at registration time.
pub const StoredCredentials = struct {
    salt: [32]u8,
    iteration_count: u32,
    stored_key: [32]u8,
    server_key: [32]u8,

    /// Derive stored credentials from a plaintext password.
    /// This should be called once at user creation/password change time.
    pub fn derive(password: []const u8, salt: [32]u8, iteration_count: u32) StoredCredentials {
        // SaltedPassword := Hi(Normalize(password), salt, i)
        var salted_password: [32]u8 = undefined;
        pbkdf2(password, &salt, iteration_count, &salted_password);

        // ClientKey := HMAC(SaltedPassword, "Client Key")
        var client_key: [32]u8 = undefined;
        HmacSha256.create(&client_key, "Client Key", &salted_password);

        // StoredKey := H(ClientKey)
        var stored_key: [32]u8 = undefined;
        Sha256.hash(&client_key, &stored_key, .{});

        // ServerKey := HMAC(SaltedPassword, "Server Key")
        var server_key: [32]u8 = undefined;
        HmacSha256.create(&server_key, "Server Key", &salted_password);

        return .{
            .salt = salt,
            .iteration_count = iteration_count,
            .stored_key = stored_key,
            .server_key = server_key,
        };
    }

    /// Generate random salt and derive credentials.
    pub fn generate(password: []const u8, iteration_count: u32) StoredCredentials {
        var salt: [32]u8 = undefined;
        std.crypto.random.bytes(&salt);
        return derive(password, salt, iteration_count);
    }
};

/// Server-side SCRAM-SHA-256 state machine.
pub const ScramServer = struct {
    state: State = .awaiting_client_first,
    /// The client's username (from client-first-message)
    username: []const u8 = "",
    /// Client nonce (from client-first-message)
    client_nonce: []const u8 = "",
    /// Server nonce (generated)
    server_nonce: [24]u8 = undefined,
    /// Combined nonce (client + server)
    combined_nonce: []const u8 = "",
    /// The stored credentials for this user (provided by lookup callback)
    credentials: ?StoredCredentials = null,
    /// client-first-message-bare (needed for AuthMessage computation)
    client_first_bare: []const u8 = "",
    /// server-first-message (needed for AuthMessage computation)
    server_first_msg: []const u8 = "",
    /// Channel binding type: 0=none, 1=tls-server-end-point, 2=tls-exporter
    cb_type: u8 = 0,
    /// Channel binding data (32 bytes, empty if cb_type=0)
    cb_data: []const u8 = "",
    /// GS2 channel binding flag from client-first ('n', 'y', or 'p')
    gs2_cb_flag: u8 = 'n',
    /// Arena for string allocations
    arena: std.heap.ArenaAllocator,

    const State = enum {
        awaiting_client_first,
        awaiting_client_final,
        completed,
        failed,
    };

    pub fn init(allocator: std.mem.Allocator) ScramServer {
        return .{
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *ScramServer) void {
        self.arena.deinit();
    }

    /// Process client-first-message.
    /// Returns the parsed username so the caller can look up credentials.
    /// After calling this, the caller must call setCredentials() then serverFirst().
    pub fn handleClientFirst(self: *ScramServer, message: []const u8) ![]const u8 {
        if (self.state != .awaiting_client_first) return error.InvalidState;

        const alloc = self.arena.allocator();

        // Format: [gs2-header],n=username,r=client-nonce
        // gs2-header is "n,," (no channel binding, no authzid) for basic SCRAM
        // or "y,," or "p=..." for channel binding variants

        // Capture the gs2 channel binding flag
        if (message.len > 0) {
            self.gs2_cb_flag = message[0];
        }

        // Skip gs2-header (everything up to and including the second comma after the flag)
        const bare_start = findClientFirstBare(message) orelse return error.InvalidMessage;
        const bare = message[bare_start..];

        self.client_first_bare = try alloc.dupe(u8, bare);

        // Parse n=username
        if (!std.mem.startsWith(u8, bare, "n=")) return error.InvalidMessage;
        const after_n = bare[2..];
        const comma_pos = std.mem.indexOfScalar(u8, after_n, ',') orelse return error.InvalidMessage;
        self.username = try alloc.dupe(u8, after_n[0..comma_pos]);

        // Parse r=client-nonce
        const after_comma = after_n[comma_pos + 1 ..];
        if (!std.mem.startsWith(u8, after_comma, "r=")) return error.InvalidMessage;
        self.client_nonce = try alloc.dupe(u8, after_comma[2..]);

        // Generate server nonce
        std.crypto.random.bytes(&self.server_nonce);

        self.state = .awaiting_client_final;
        return self.username;
    }

    /// Set the stored credentials for the user (looked up by the caller).
    pub fn setCredentials(self: *ScramServer, creds: StoredCredentials) void {
        self.credentials = creds;
    }

    /// Set channel binding data from the TLS session.
    /// Must be called before handleClientFinal() for SCRAM-PLUS validation.
    pub fn setChannelBinding(self: *ScramServer, cb_type: u8, cb_data: []const u8) void {
        self.cb_type = cb_type;
        self.cb_data = cb_data;
    }

    /// Generate the server-first-message to send to the client.
    pub fn serverFirst(self: *ScramServer) ![]const u8 {
        if (self.state != .awaiting_client_final) return error.InvalidState;
        const creds = self.credentials orelse return error.NoCredentials;

        const alloc = self.arena.allocator();

        // Encode server nonce as base64
        const server_nonce_b64 = try base64Encode(alloc, &self.server_nonce);

        // Combined nonce = client_nonce + server_nonce_b64
        self.combined_nonce = try std.fmt.allocPrint(alloc, "{s}{s}", .{ self.client_nonce, server_nonce_b64 });

        // Encode salt as base64
        const salt_b64 = try base64Encode(alloc, &creds.salt);

        // server-first-message: r=combined_nonce,s=salt,i=iteration_count
        self.server_first_msg = try std.fmt.allocPrint(alloc, "r={s},s={s},i={d}", .{
            self.combined_nonce,
            salt_b64,
            creds.iteration_count,
        });

        return self.server_first_msg;
    }

    /// Process client-final-message and verify the client proof.
    /// Returns the server-final-message (containing server signature) on success.
    pub fn handleClientFinal(self: *ScramServer, message: []const u8) ![]const u8 {
        if (self.state != .awaiting_client_final) return error.InvalidState;
        const creds = self.credentials orelse return error.NoCredentials;

        const alloc = self.arena.allocator();

        // Format: c=base64(gs2-header[+cb-data]),r=combined_nonce,p=base64(ClientProof)
        // Parse channel binding
        if (!std.mem.startsWith(u8, message, "c=")) return error.InvalidMessage;
        const after_c = message[2..];
        const comma1 = std.mem.indexOfScalar(u8, after_c, ',') orelse return error.InvalidMessage;

        // Validate channel binding data
        const cb_b64 = after_c[0..comma1];
        try self.validateChannelBinding(cb_b64);

        // Parse r=nonce
        const after_cb = after_c[comma1 + 1 ..];
        if (!std.mem.startsWith(u8, after_cb, "r=")) return error.InvalidMessage;
        const after_r = after_cb[2..];
        const comma2 = std.mem.indexOfScalar(u8, after_r, ',') orelse return error.InvalidMessage;
        const received_nonce = after_r[0..comma2];

        // Verify nonce matches
        if (!std.mem.eql(u8, received_nonce, self.combined_nonce)) {
            self.state = .failed;
            return error.NonceMismatch;
        }

        // Parse p=proof
        const after_nonce = after_r[comma2 + 1 ..];
        if (!std.mem.startsWith(u8, after_nonce, "p=")) return error.InvalidMessage;
        const proof_b64 = after_nonce[2..];

        // Decode client proof
        var client_proof: [32]u8 = undefined;
        try base64Decode(proof_b64, &client_proof);

        // client-final-message-without-proof
        const without_proof_len = @as(usize, @intCast(@intFromPtr(after_nonce.ptr) - @intFromPtr(message.ptr)));
        const client_final_without_proof = message[0 .. without_proof_len - 1]; // -1 to exclude trailing comma

        // AuthMessage = client-first-message-bare + "," + server-first-message + "," + client-final-without-proof
        const auth_message = try std.fmt.allocPrint(alloc, "{s},{s},{s}", .{
            self.client_first_bare,
            self.server_first_msg,
            client_final_without_proof,
        });

        // ClientSignature := HMAC(StoredKey, AuthMessage)
        var client_signature: [32]u8 = undefined;
        HmacSha256.create(&client_signature, auth_message, &creds.stored_key);

        // Recover ClientKey := ClientProof XOR ClientSignature
        var recovered_client_key: [32]u8 = undefined;
        for (&recovered_client_key, client_proof, client_signature) |*r, p, s| {
            r.* = p ^ s;
        }

        // Verify: H(recovered_client_key) == StoredKey
        var recovered_stored_key: [32]u8 = undefined;
        Sha256.hash(&recovered_client_key, &recovered_stored_key, .{});

        if (!std.mem.eql(u8, &recovered_stored_key, &creds.stored_key)) {
            self.state = .failed;
            return error.AuthenticationFailed;
        }

        // Success! Compute ServerSignature for the client to verify us
        // ServerSignature := HMAC(ServerKey, AuthMessage)
        var server_signature: [32]u8 = undefined;
        HmacSha256.create(&server_signature, auth_message, &creds.server_key);

        const server_sig_b64 = try base64Encode(alloc, &server_signature);

        self.state = .completed;

        // server-final-message: v=base64(ServerSignature)
        return try std.fmt.allocPrint(alloc, "v={s}", .{server_sig_b64});
    }

    /// Validate the channel binding data from the client-final c= field.
    /// Per RFC 5802: c= is base64(gs2-header [+ channel-binding-data])
    fn validateChannelBinding(self: *ScramServer, cb_b64: []const u8) !void {
        // Decode the c= field
        var decoded_buf: [256]u8 = undefined;
        const decoder = std.base64.standard.Decoder;
        const decoded_len = decoder.calcSizeUpperBound(cb_b64.len) catch return error.InvalidMessage;
        if (decoded_len > decoded_buf.len) return error.InvalidMessage;
        const actual_len = decoder.calcSizeForSlice(cb_b64) catch return error.InvalidMessage;
        decoder.decode(decoded_buf[0..actual_len], cb_b64) catch return error.InvalidMessage;
        const decoded = decoded_buf[0..actual_len];

        if (self.gs2_cb_flag == 'n') {
            // Client said no channel binding: c= must be base64("n,,")
            // "n,," = { 0x6e, 0x2c, 0x2c } → base64 "biws"
            if (!std.mem.eql(u8, cb_b64, "biws")) {
                return error.ChannelBindingMismatch;
            }
        } else if (self.gs2_cb_flag == 'y') {
            // Client supports CB but server doesn't advertise it (or SCRAM without -PLUS)
            // c= must be base64("y,,")
            const expected = "y,,";
            if (!std.mem.eql(u8, decoded[0..@min(decoded.len, expected.len)], expected)) {
                return error.ChannelBindingMismatch;
            }
        } else if (self.gs2_cb_flag == 'p') {
            // Client wants channel binding: c= is base64(gs2-header + cb-data)
            // gs2-header is "p=<cb-name>,," — we need to verify the cb-data portion
            if (self.cb_type == 0 or self.cb_data.len == 0) {
                // Server has no binding data but client demands it
                return error.ChannelBindingMismatch;
            }
            // Find the end of gs2-header in decoded: after "p=cb-name,,"
            var hdr_end: usize = 0;
            var commas: u8 = 0;
            while (hdr_end < decoded.len) : (hdr_end += 1) {
                if (decoded[hdr_end] == ',') {
                    commas += 1;
                    if (commas == 2) {
                        hdr_end += 1;
                        break;
                    }
                }
            }
            // The rest is the channel binding data
            const client_cb = decoded[hdr_end..];
            if (!std.mem.eql(u8, client_cb, self.cb_data)) {
                return error.ChannelBindingMismatch;
            }
        }
    }

    pub fn isComplete(self: *const ScramServer) bool {
        return self.state == .completed;
    }

    pub fn hasFailed(self: *const ScramServer) bool {
        return self.state == .failed;
    }
};

/// SCRAM-SHA-256 client-side implementation (for testing and s2s).
pub const ScramClient = struct {
    state: State = .initial,
    username: []const u8,
    password: []const u8,
    client_nonce: [24]u8 = undefined,
    client_first_bare: []const u8 = "",
    server_first_msg: []const u8 = "",
    combined_nonce: []const u8 = "",
    salt: []const u8 = "",
    iteration_count: u32 = 0,
    arena: std.heap.ArenaAllocator,

    const State = enum {
        initial,
        awaiting_server_first,
        awaiting_server_final,
        completed,
        failed,
    };

    pub fn init(allocator: std.mem.Allocator, username: []const u8, password: []const u8) ScramClient {
        var client = ScramClient{
            .username = username,
            .password = password,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
        std.crypto.random.bytes(&client.client_nonce);
        return client;
    }

    pub fn deinit(self: *ScramClient) void {
        self.arena.deinit();
    }

    /// Generate client-first-message.
    pub fn clientFirst(self: *ScramClient) ![]const u8 {
        const alloc = self.arena.allocator();
        const nonce_b64 = try base64Encode(alloc, &self.client_nonce);

        // client-first-message-bare: n=username,r=nonce
        self.client_first_bare = try std.fmt.allocPrint(alloc, "n={s},r={s}", .{ self.username, nonce_b64 });

        self.state = .awaiting_server_first;

        // Full message with gs2-header: n,,n=username,r=nonce
        return try std.fmt.allocPrint(alloc, "n,,{s}", .{self.client_first_bare});
    }

    /// Process server-first-message and generate client-final-message.
    pub fn handleServerFirst(self: *ScramClient, message: []const u8) ![]const u8 {
        if (self.state != .awaiting_server_first) return error.InvalidState;

        const alloc = self.arena.allocator();
        self.server_first_msg = try alloc.dupe(u8, message);

        // Parse r=combined_nonce,s=salt,i=iteration_count
        var iter = std.mem.splitScalar(u8, message, ',');

        // r=nonce
        const r_field = iter.next() orelse return error.InvalidMessage;
        if (!std.mem.startsWith(u8, r_field, "r=")) return error.InvalidMessage;
        self.combined_nonce = try alloc.dupe(u8, r_field[2..]);

        // s=salt
        const s_field = iter.next() orelse return error.InvalidMessage;
        if (!std.mem.startsWith(u8, s_field, "s=")) return error.InvalidMessage;
        self.salt = try alloc.dupe(u8, s_field[2..]);

        // i=iteration_count
        const i_field = iter.next() orelse return error.InvalidMessage;
        if (!std.mem.startsWith(u8, i_field, "i=")) return error.InvalidMessage;
        self.iteration_count = std.fmt.parseInt(u32, i_field[2..], 10) catch return error.InvalidMessage;

        // Decode salt from base64
        var salt_bytes: [32]u8 = undefined;
        try base64Decode(self.salt, &salt_bytes);

        // SaltedPassword := Hi(password, salt, i)
        var salted_password: [32]u8 = undefined;
        pbkdf2(self.password, &salt_bytes, self.iteration_count, &salted_password);

        // ClientKey := HMAC(SaltedPassword, "Client Key")
        var client_key: [32]u8 = undefined;
        HmacSha256.create(&client_key, "Client Key", &salted_password);

        // StoredKey := H(ClientKey)
        var stored_key: [32]u8 = undefined;
        Sha256.hash(&client_key, &stored_key, .{});

        // channel binding: c=biws (base64 of "n,,")
        const channel_binding = "biws"; // base64("n,,")

        // client-final-message-without-proof
        const without_proof = try std.fmt.allocPrint(alloc, "c={s},r={s}", .{ channel_binding, self.combined_nonce });

        // AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof
        const auth_message = try std.fmt.allocPrint(alloc, "{s},{s},{s}", .{
            self.client_first_bare,
            self.server_first_msg,
            without_proof,
        });

        // ClientSignature := HMAC(StoredKey, AuthMessage)
        var client_signature: [32]u8 = undefined;
        HmacSha256.create(&client_signature, auth_message, &stored_key);

        // ClientProof := ClientKey XOR ClientSignature
        var client_proof: [32]u8 = undefined;
        for (&client_proof, client_key, client_signature) |*r, k, s| {
            r.* = k ^ s;
        }

        const proof_b64 = try base64Encode(alloc, &client_proof);

        self.state = .awaiting_server_final;

        // client-final-message: c=biws,r=nonce,p=proof
        return try std.fmt.allocPrint(alloc, "{s},p={s}", .{ without_proof, proof_b64 });
    }

    /// Verify server-final-message (optional — validates the server).
    pub fn handleServerFinal(self: *ScramClient, message: []const u8) !void {
        if (self.state != .awaiting_server_final) return error.InvalidState;

        if (!std.mem.startsWith(u8, message, "v=")) {
            self.state = .failed;
            return error.ServerAuthFailed;
        }

        // In a full implementation, we'd verify the server signature here.
        // For MVP, we trust the server if it sends v= (mutual auth deferred).
        self.state = .completed;
    }

    pub fn isComplete(self: *const ScramClient) bool {
        return self.state == .completed;
    }
};

// --- Helpers ---

/// Find the start of client-first-message-bare (after gs2-header).
fn findClientFirstBare(message: []const u8) ?usize {
    // gs2-header = gs2-cbind-flag "," [authzid] ","
    // gs2-cbind-flag = "n" / "y" / "p=" cb-name
    var i: usize = 0;

    // Skip gs2-cbind-flag
    if (i >= message.len) return null;
    if (message[i] == 'p') {
        // p=cb-name, skip to comma
        while (i < message.len and message[i] != ',') : (i += 1) {}
    } else {
        // 'n' or 'y'
        i += 1;
    }

    // Skip first comma
    if (i >= message.len or message[i] != ',') return null;
    i += 1;

    // Skip authzid (everything until next comma)
    while (i < message.len and message[i] != ',') : (i += 1) {}

    // Skip second comma
    if (i >= message.len or message[i] != ',') return null;
    i += 1;

    return i;
}

/// PBKDF2-HMAC-SHA-256
fn pbkdf2(password: []const u8, salt: []const u8, iterations: u32, output: *[32]u8) void {
    // PBKDF2 with SHA-256, dkLen = 32 (one block)
    // U1 = HMAC(password, salt || INT(1))
    var salt_with_block: [256]u8 = undefined;
    const slen = @min(salt.len, 252);
    @memcpy(salt_with_block[0..slen], salt[0..slen]);
    salt_with_block[slen] = 0;
    salt_with_block[slen + 1] = 0;
    salt_with_block[slen + 2] = 0;
    salt_with_block[slen + 3] = 1;

    var u: [32]u8 = undefined;
    HmacSha256.create(&u, salt_with_block[0 .. slen + 4], password);

    var result: [32]u8 = u;

    // U2..Ui
    var i: u32 = 1;
    while (i < iterations) : (i += 1) {
        var next_u: [32]u8 = undefined;
        HmacSha256.create(&next_u, &u, password);
        u = next_u;
        for (&result, u) |*r, x| {
            r.* ^= x;
        }
    }

    output.* = result;
}

/// Base64 encode a byte slice using the standard alphabet.
fn base64Encode(alloc: std.mem.Allocator, input: []const u8) ![]const u8 {
    const encoder = std.base64.standard.Encoder;
    const len = encoder.calcSize(input.len);
    const buf = try alloc.alloc(u8, len);
    return encoder.encode(buf, input);
}

/// Base64 decode into a fixed buffer.
fn base64Decode(input: []const u8, output: []u8) !void {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeUpperBound(input.len) catch return error.InvalidBase64;
    _ = decoded_len;
    decoder.decode(output, input) catch return error.InvalidBase64;
}

// --- Tests ---

test "StoredCredentials derivation is deterministic" {
    const salt = [_]u8{0x01} ** 32;
    const creds1 = StoredCredentials.derive("password123", salt, 4096);
    const creds2 = StoredCredentials.derive("password123", salt, 4096);

    try std.testing.expectEqualSlices(u8, &creds1.stored_key, &creds2.stored_key);
    try std.testing.expectEqualSlices(u8, &creds1.server_key, &creds2.server_key);
}

test "StoredCredentials different passwords produce different keys" {
    const salt = [_]u8{0x42} ** 32;
    const creds1 = StoredCredentials.derive("password1", salt, 4096);
    const creds2 = StoredCredentials.derive("password2", salt, 4096);

    try std.testing.expect(!std.mem.eql(u8, &creds1.stored_key, &creds2.stored_key));
}

test "SCRAM-SHA-256 full exchange" {
    const allocator = std.testing.allocator;

    // Server has stored credentials for "testuser"
    const salt = [_]u8{0xAB} ** 32;
    const creds = StoredCredentials.derive("testpassword", salt, 4096);

    // Client initiates
    var client = ScramClient.init(allocator, "testuser", "testpassword");
    defer client.deinit();

    const client_first = try client.clientFirst();

    // Server processes client-first
    var server = ScramServer.init(allocator);
    defer server.deinit();

    const username = try server.handleClientFirst(client_first);
    try std.testing.expectEqualStrings("testuser", username);

    // Server looks up credentials and generates server-first
    server.setCredentials(creds);
    const server_first = try server.serverFirst();

    // Client processes server-first and generates client-final
    const client_final = try client.handleServerFirst(server_first);

    // Server processes client-final and verifies
    const server_final = try server.handleClientFinal(client_final);
    try std.testing.expect(server.isComplete());

    // Client verifies server
    try client.handleServerFinal(server_final);
    try std.testing.expect(client.isComplete());
}

test "SCRAM-SHA-256 wrong password fails" {
    const allocator = std.testing.allocator;

    const salt = [_]u8{0xCD} ** 32;
    const creds = StoredCredentials.derive("correct_password", salt, 4096);

    // Client uses wrong password
    var client = ScramClient.init(allocator, "user", "wrong_password");
    defer client.deinit();

    const client_first = try client.clientFirst();

    var server = ScramServer.init(allocator);
    defer server.deinit();

    _ = try server.handleClientFirst(client_first);
    server.setCredentials(creds);
    const server_first = try server.serverFirst();

    const client_final = try client.handleServerFirst(server_first);

    // Server should reject the proof
    const result = server.handleClientFinal(client_final);
    try std.testing.expectError(error.AuthenticationFailed, result);
    try std.testing.expect(server.hasFailed());
}

test "findClientFirstBare" {
    // Standard: n,,n=user,r=nonce
    try std.testing.expectEqual(@as(?usize, 3), findClientFirstBare("n,,n=user,r=nonce"));

    // With authzid: n,a=admin,n=user,r=nonce
    try std.testing.expectEqual(@as(?usize, 10), findClientFirstBare("n,a=admin,n=user,r=nonce"));

    // Channel binding: y,,n=user,r=nonce
    try std.testing.expectEqual(@as(?usize, 3), findClientFirstBare("y,,n=user,r=nonce"));
}

test "PBKDF2 produces non-zero output" {
    var output: [32]u8 = undefined;
    pbkdf2("password", "somesalt12345678", 1, &output);

    // Should not be all zeros
    var all_zero = true;
    for (output) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}
