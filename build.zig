const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const op_storage = b.option([]const u8, "op-storage", "Operational storage backend: lmdb (default), rocksdb, sqlite") orelse "lmdb";
    const archive_storage = b.option([]const u8, "archive-storage", "Archive storage backend: rocksdb (default), lmdb, sqlite") orelse "rocksdb";

    // --- Protocol Library Modules ---

    const xml_mod = b.createModule(.{
        .root_source_file = b.path("lib/xml/reader.zig"),
        .target = target,
        .optimize = optimize,
    });

    const xmpp_mod = b.createModule(.{
        .root_source_file = b.path("lib/xmpp/xmpp.zig"),
        .target = target,
        .optimize = optimize,
    });
    xmpp_mod.addImport("xml", xml_mod);

    const sasl_mod = b.createModule(.{
        .root_source_file = b.path("lib/sasl/sasl.zig"),
        .target = target,
        .optimize = optimize,
    });

    _ = b.createModule(.{
        .root_source_file = b.path("lib/tls/tls.zig"),
        .target = target,
        .optimize = optimize,
    });

    _ = b.createModule(.{
        .root_source_file = b.path("lib/tls/ssl.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    _ = b.createModule(.{
        .root_source_file = b.path("lib/dns/dns.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- Tests ---

    const xml_test_mod = b.createModule(.{
        .root_source_file = b.path("lib/xml/reader.zig"),
        .target = target,
        .optimize = optimize,
    });

    const xmpp_test_mod = b.createModule(.{
        .root_source_file = b.path("lib/xmpp/xmpp.zig"),
        .target = target,
        .optimize = optimize,
    });
    xmpp_test_mod.addImport("xml", xml_mod);

    const sasl_test_mod = b.createModule(.{
        .root_source_file = b.path("lib/sasl/sasl.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tls_test_mod = b.createModule(.{
        .root_source_file = b.path("lib/tls/tls.zig"),
        .target = target,
        .optimize = optimize,
    });

    const ssl_test_mod = b.createModule(.{
        .root_source_file = b.path("lib/tls/ssl.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ssl_test_mod.linkSystemLibrary("ssl", .{});
    ssl_test_mod.linkSystemLibrary("crypto", .{});

    const dns_test_mod = b.createModule(.{
        .root_source_file = b.path("lib/dns/dns.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const xml_tests = b.addTest(.{
        .name = "xml-tests",
        .root_module = xml_test_mod,
    });

    const xmpp_tests = b.addTest(.{
        .name = "xmpp-tests",
        .root_module = xmpp_test_mod,
    });

    const sasl_tests = b.addTest(.{
        .name = "sasl-tests",
        .root_module = sasl_test_mod,
    });

    const tls_tests = b.addTest(.{
        .name = "tls-tests",
        .root_module = tls_test_mod,
    });

    const ssl_tests = b.addTest(.{
        .name = "ssl-tests",
        .root_module = ssl_test_mod,
    });

    const dns_tests = b.addTest(.{
        .name = "dns-tests",
        .root_module = dns_test_mod,
    });

    const run_xml_tests = b.addRunArtifact(xml_tests);
    const run_xmpp_tests = b.addRunArtifact(xmpp_tests);
    const run_sasl_tests = b.addRunArtifact(sasl_tests);
    const run_tls_tests = b.addRunArtifact(tls_tests);
    const run_ssl_tests = b.addRunArtifact(ssl_tests);
    const run_dns_tests = b.addRunArtifact(dns_tests);

    // --- Core daemon tests ---

    const event_loop_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/event_loop.zig"),
        .target = target,
        .optimize = optimize,
    });

    const event_loop_tests = b.addTest(.{
        .name = "event-loop-tests",
        .root_module = event_loop_test_mod,
    });

    const run_event_loop_tests = b.addRunArtifact(event_loop_tests);

    const connection_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/connection.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    connection_test_mod.addImport("ssl", ssl_test_mod);
    connection_test_mod.linkSystemLibrary("ssl", .{});
    connection_test_mod.linkSystemLibrary("crypto", .{});

    const connection_tests = b.addTest(.{
        .name = "connection-tests",
        .root_module = connection_test_mod,
    });

    const run_connection_tests = b.addRunArtifact(connection_tests);

    const listener_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/listener.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    listener_test_mod.addImport("ssl", ssl_test_mod);
    listener_test_mod.linkSystemLibrary("ssl", .{});
    listener_test_mod.linkSystemLibrary("crypto", .{});

    const listener_tests = b.addTest(.{
        .name = "listener-tests",
        .root_module = listener_test_mod,
    });

    const run_listener_tests = b.addRunArtifact(listener_tests);

    // --- IPC tests (before server tests — server depends on IPC modules) ---

    const ipc_protocol_test_mod = b.createModule(.{
        .root_source_file = b.path("src/ipc/protocol.zig"),
        .target = target,
        .optimize = optimize,
    });

    const ipc_protocol_tests = b.addTest(.{
        .name = "ipc-protocol-tests",
        .root_module = ipc_protocol_test_mod,
    });

    const run_ipc_protocol_tests = b.addRunArtifact(ipc_protocol_tests);

    const ipc_client_test_mod = b.createModule(.{
        .root_source_file = b.path("src/ipc/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    ipc_client_test_mod.addImport("ipc_protocol", ipc_protocol_test_mod);

    const ipc_client_tests = b.addTest(.{
        .name = "ipc-client-tests",
        .root_module = ipc_client_test_mod,
    });

    const run_ipc_client_tests = b.addRunArtifact(ipc_client_tests);

    const ipc_server_test_mod = b.createModule(.{
        .root_source_file = b.path("src/ipc/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    ipc_server_test_mod.addImport("ipc_protocol", ipc_protocol_test_mod);

    const ipc_server_tests = b.addTest(.{
        .name = "ipc-server-tests",
        .root_module = ipc_server_test_mod,
    });

    const run_ipc_server_tests = b.addRunArtifact(ipc_server_tests);

    // --- Storage dependency (needed early for server module) ---

    const lmdb_dep = b.dependency("lmdb", .{ .target = target, .optimize = optimize });

    // --- Server tests (depends on IPC modules) ---

    const server_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/server.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const server_backend_mod = b.createModule(.{
        .root_source_file = b.path("src/store/backend.zig"),
        .target = target,
        .optimize = optimize,
    });
    const roster_store_mod_for_server = b.createModule(.{
        .root_source_file = b.path("src/store/roster_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    roster_store_mod_for_server.addImport("backend", server_backend_mod);
    const session_registry_mod_for_server = b.createModule(.{
        .root_source_file = b.path("src/core/session_registry.zig"),
        .target = target,
        .optimize = optimize,
    });
    const server_op_backend_mod = createBackendMod(b, op_storage, target, optimize, server_backend_mod, lmdb_dep);
    const server_archive_backend_mod = createBackendMod(b, archive_storage, target, optimize, server_backend_mod, lmdb_dep);
    const server_archive_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/archive_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_archive_store_mod.addImport("backend", server_backend_mod);
    const server_vcard_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/vcard_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_vcard_store_mod.addImport("backend", server_backend_mod);
    const server_generic_offline_mod = b.createModule(.{
        .root_source_file = b.path("src/store/offline_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_generic_offline_mod.addImport("backend", server_backend_mod);
    const server_mam_handler_mod = b.createModule(.{
        .root_source_file = b.path("src/store/mam_handler.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mam_handler_mod.addImport("backend", server_backend_mod);
    server_mam_handler_mod.addImport("archive_store", server_archive_store_mod);
    server_test_mod.addImport("xml", xml_mod);
    server_test_mod.addImport("xmpp", xmpp_mod);
    server_test_mod.addImport("sasl", sasl_mod);
    server_test_mod.addImport("ssl", ssl_test_mod);
    server_test_mod.addImport("ipc_protocol", ipc_protocol_test_mod);
    server_test_mod.addImport("ipc_client", ipc_client_test_mod);
    server_test_mod.addImport("roster_store", roster_store_mod_for_server);
    server_test_mod.addImport("session_registry", session_registry_mod_for_server);
    server_test_mod.addImport("generic_offline_store", server_generic_offline_mod);
    server_test_mod.addImport("archive_store", server_archive_store_mod);
    server_test_mod.addImport("backend", server_backend_mod);
    server_test_mod.addImport("op_backend", server_op_backend_mod);
    server_test_mod.addImport("archive_backend", server_archive_backend_mod);
    server_test_mod.addImport("mam_handler", server_mam_handler_mod);
    server_test_mod.addImport("vcard_store", server_vcard_store_mod);
    const server_room_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/room_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_room_store_mod.addImport("backend", server_backend_mod);
    const server_room_registry_mod = b.createModule(.{
        .root_source_file = b.path("src/core/room_registry.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_room_registry_mod.addImport("room_store", server_room_store_mod);
    server_test_mod.addImport("room_store", server_room_store_mod);
    server_test_mod.addImport("room_registry", server_room_registry_mod);
    server_test_mod.linkSystemLibrary("ssl", .{});
    server_test_mod.linkSystemLibrary("crypto", .{});

    const server_tests = b.addTest(.{
        .name = "server-tests",
        .root_module = server_test_mod,
    });

    const run_server_tests = b.addRunArtifact(server_tests);

    // --- Storage backend module (needed by auth + ctl tests and executables) ---

    const backend_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/backend.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- Auth tests ---

    // Legacy flat-file user store tests (backward compat)
    const user_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/user_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    user_store_test_mod.addImport("sasl", sasl_mod);

    const user_store_tests = b.addTest(.{
        .name = "user-store-tests",
        .root_module = user_store_test_mod,
    });

    const run_user_store_tests = b.addRunArtifact(user_store_tests);

    // Generic user store tests (uses MemoryBackend)
    const generic_user_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/user_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    generic_user_store_test_mod.addImport("sasl", sasl_mod);
    generic_user_store_test_mod.addImport("backend", backend_test_mod);

    const generic_user_store_tests = b.addTest(.{
        .name = "generic-user-store-tests",
        .root_module = generic_user_store_test_mod,
    });

    const run_generic_user_store_tests = b.addRunArtifact(generic_user_store_tests);

    const rate_limiter_test_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/rate_limiter.zig"),
        .target = target,
        .optimize = optimize,
    });

    const rate_limiter_tests = b.addTest(.{
        .name = "rate-limiter-tests",
        .root_module = rate_limiter_test_mod,
    });

    const run_rate_limiter_tests = b.addRunArtifact(rate_limiter_tests);

    const lock_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/lock_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    lock_store_test_mod.addImport("backend", backend_test_mod);

    const lock_store_tests = b.addTest(.{
        .name = "lock-store-tests",
        .root_module = lock_store_test_mod,
    });

    const run_lock_store_tests = b.addRunArtifact(lock_store_tests);

    const invite_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/invite_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    invite_store_test_mod.addImport("backend", backend_test_mod);

    const invite_store_tests = b.addTest(.{
        .name = "invite-store-tests",
        .root_module = invite_store_test_mod,
    });

    const run_invite_store_tests = b.addRunArtifact(invite_store_tests);

    const auth_handler_test_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/handler.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_handler_test_mod.addImport("sasl", sasl_mod);
    auth_handler_test_mod.addImport("ipc_protocol", ipc_protocol_test_mod);
    auth_handler_test_mod.addImport("rate_limiter", rate_limiter_test_mod);
    auth_handler_test_mod.addImport("lock_store", lock_store_test_mod);
    auth_handler_test_mod.addImport("invite_store", invite_store_test_mod);
    auth_handler_test_mod.addImport("user_store", generic_user_store_test_mod);
    auth_handler_test_mod.addImport("backend", backend_test_mod);

    const auth_handler_tests = b.addTest(.{
        .name = "auth-handler-tests",
        .root_module = auth_handler_test_mod,
    });

    const run_auth_handler_tests = b.addRunArtifact(auth_handler_tests);

    // --- Generic roster store tests ---

    const generic_roster_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/roster_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    generic_roster_store_test_mod.addImport("backend", backend_test_mod);

    const generic_roster_store_tests = b.addTest(.{
        .name = "generic-roster-store-tests",
        .root_module = generic_roster_store_test_mod,
    });

    const run_generic_roster_store_tests = b.addRunArtifact(generic_roster_store_tests);

    // --- VCard store tests ---

    const vcard_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/vcard_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    vcard_store_test_mod.addImport("backend", backend_test_mod);

    const vcard_store_tests = b.addTest(.{
        .name = "vcard-store-tests",
        .root_module = vcard_store_test_mod,
    });

    const run_vcard_store_tests = b.addRunArtifact(vcard_store_tests);

    // --- Legacy roster store tests ---

    const roster_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/roster_store.zig"),
        .target = target,
        .optimize = optimize,
    });

    const roster_store_tests = b.addTest(.{
        .name = "roster-store-tests",
        .root_module = roster_store_test_mod,
    });

    const run_roster_store_tests = b.addRunArtifact(roster_store_tests);

    // --- Session registry tests ---

    const session_registry_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/session_registry.zig"),
        .target = target,
        .optimize = optimize,
    });

    const session_registry_tests = b.addTest(.{
        .name = "session-registry-tests",
        .root_module = session_registry_test_mod,
    });

    const run_session_registry_tests = b.addRunArtifact(session_registry_tests);

    // --- Offline store tests ---

    const offline_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/offline_store.zig"),
        .target = target,
        .optimize = optimize,
    });

    const offline_store_tests = b.addTest(.{
        .name = "offline-store-tests",
        .root_module = offline_store_test_mod,
    });

    const run_offline_store_tests = b.addRunArtifact(offline_store_tests);

    // --- S2S stream tests ---

    const s2s_stream_test_mod = b.createModule(.{
        .root_source_file = b.path("src/s2s/stream.zig"),
        .target = target,
        .optimize = optimize,
    });

    const s2s_stream_tests = b.addTest(.{
        .name = "s2s-stream-tests",
        .root_module = s2s_stream_test_mod,
    });

    const run_s2s_stream_tests = b.addRunArtifact(s2s_stream_tests);

    // --- S2S connector tests ---

    const s2s_connector_test_mod = b.createModule(.{
        .root_source_file = b.path("src/s2s/connector.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    s2s_connector_test_mod.addImport("ssl", ssl_test_mod);
    s2s_connector_test_mod.linkSystemLibrary("ssl", .{});
    s2s_connector_test_mod.linkSystemLibrary("crypto", .{});

    const s2s_connector_tests = b.addTest(.{
        .name = "s2s-connector-tests",
        .root_module = s2s_connector_test_mod,
    });

    const run_s2s_connector_tests = b.addRunArtifact(s2s_connector_tests);

    // --- S2S DANE tests ---

    const s2s_dane_test_mod = b.createModule(.{
        .root_source_file = b.path("src/s2s/dane.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    s2s_dane_test_mod.addImport("ssl", ssl_test_mod);
    s2s_dane_test_mod.linkSystemLibrary("ssl", .{});
    s2s_dane_test_mod.linkSystemLibrary("crypto", .{});

    const s2s_dane_tests = b.addTest(.{
        .name = "s2s-dane-tests",
        .root_module = s2s_dane_test_mod,
    });

    const run_s2s_dane_tests = b.addRunArtifact(s2s_dane_tests);

    // --- S2S dialback tests ---

    const s2s_dialback_test_mod = b.createModule(.{
        .root_source_file = b.path("src/s2s/dialback.zig"),
        .target = target,
        .optimize = optimize,
    });

    const s2s_dialback_tests = b.addTest(.{
        .name = "s2s-dialback-tests",
        .root_module = s2s_dialback_test_mod,
    });

    const run_s2s_dialback_tests = b.addRunArtifact(s2s_dialback_tests);

    // --- S2S session tests ---

    const s2s_session_test_mod = b.createModule(.{
        .root_source_file = b.path("src/s2s/session.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    s2s_session_test_mod.addImport("ssl", ssl_test_mod);
    s2s_session_test_mod.linkSystemLibrary("ssl", .{});
    s2s_session_test_mod.linkSystemLibrary("crypto", .{});

    const s2s_session_tests = b.addTest(.{
        .name = "s2s-session-tests",
        .root_module = s2s_session_test_mod,
    });

    const run_s2s_session_tests = b.addRunArtifact(s2s_session_tests);

    // --- S2S main (daemon) tests ---

    const s2s_event_loop_mod = b.createModule(.{
        .root_source_file = b.path("src/core/event_loop.zig"),
        .target = target,
        .optimize = optimize,
    });

    const s2s_main_test_mod = b.createModule(.{
        .root_source_file = b.path("src/s2s/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    s2s_main_test_mod.addImport("ipc_protocol", ipc_protocol_test_mod);
    s2s_main_test_mod.addImport("ipc_server", ipc_server_test_mod);
    s2s_main_test_mod.addImport("event_loop", s2s_event_loop_mod);
    s2s_main_test_mod.addImport("xml", xml_mod);
    s2s_main_test_mod.addImport("ssl", ssl_test_mod);
    s2s_main_test_mod.addImport("dns", dns_test_mod);
    s2s_main_test_mod.linkSystemLibrary("ssl", .{});
    s2s_main_test_mod.linkSystemLibrary("crypto", .{});

    const s2s_main_tests = b.addTest(.{
        .name = "s2s-main-tests",
        .root_module = s2s_main_test_mod,
    });

    const run_s2s_main_tests = b.addRunArtifact(s2s_main_tests);

    // --- Storage backend tests ---

    const backend_tests = b.addTest(.{
        .name = "storage-backend-tests",
        .root_module = backend_test_mod,
    });

    const run_backend_tests = b.addRunArtifact(backend_tests);

    // --- LMDB backend tests ---

    const lmdb_backend_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/lmdb.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lmdb_backend_test_mod.addImport("lmdb", lmdb_dep.module("lmdb"));
    lmdb_backend_test_mod.addImport("backend", backend_test_mod);

    const lmdb_backend_tests = b.addTest(.{
        .name = "lmdb-backend-tests",
        .root_module = lmdb_backend_test_mod,
    });

    const run_lmdb_backend_tests = b.addRunArtifact(lmdb_backend_tests);

    // --- Archive store tests ---

    const archive_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/archive_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    archive_store_test_mod.addImport("backend", backend_test_mod);

    const archive_store_tests = b.addTest(.{
        .name = "archive-store-tests",
        .root_module = archive_store_test_mod,
    });

    const run_archive_store_tests = b.addRunArtifact(archive_store_tests);

    // --- MAM handler tests ---

    const mam_handler_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/mam_handler.zig"),
        .target = target,
        .optimize = optimize,
    });
    mam_handler_test_mod.addImport("backend", backend_test_mod);
    mam_handler_test_mod.addImport("archive_store", archive_store_test_mod);

    const mam_handler_tests = b.addTest(.{
        .name = "mam-handler-tests",
        .root_module = mam_handler_test_mod,
    });

    const run_mam_handler_tests = b.addRunArtifact(mam_handler_tests);

    // --- Generic offline store tests ---

    const generic_offline_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/offline_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    generic_offline_store_test_mod.addImport("backend", backend_test_mod);

    const generic_offline_store_tests = b.addTest(.{
        .name = "generic-offline-store-tests",
        .root_module = generic_offline_store_test_mod,
    });

    const run_generic_offline_store_tests = b.addRunArtifact(generic_offline_store_tests);

    // --- Room store tests ---

    const room_store_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/room_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    room_store_test_mod.addImport("backend", backend_test_mod);

    const room_store_tests = b.addTest(.{
        .name = "room-store-tests",
        .root_module = room_store_test_mod,
    });

    const run_room_store_tests = b.addRunArtifact(room_store_tests);

    // --- Room registry tests ---

    const room_registry_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/room_registry.zig"),
        .target = target,
        .optimize = optimize,
    });
    room_registry_test_mod.addImport("room_store", room_store_test_mod);

    const room_registry_tests = b.addTest(.{
        .name = "room-registry-tests",
        .root_module = room_registry_test_mod,
    });

    const run_room_registry_tests = b.addRunArtifact(room_registry_tests);

    // --- Fan-out tests ---

    const fanout_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/fanout.zig"),
        .target = target,
        .optimize = optimize,
    });
    fanout_test_mod.addImport("room_registry", room_registry_test_mod);
    fanout_test_mod.addImport("room_store", room_store_test_mod);

    const fanout_tests = b.addTest(.{
        .name = "fanout-tests",
        .root_module = fanout_test_mod,
    });

    const run_fanout_tests = b.addRunArtifact(fanout_tests);

    // --- RocksDB backend tests ---

    const rocksdb_backend_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/rocksdb.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    rocksdb_backend_test_mod.addImport("backend", backend_test_mod);
    rocksdb_backend_test_mod.linkSystemLibrary("rocksdb", .{});
    rocksdb_backend_test_mod.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
    rocksdb_backend_test_mod.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });

    const rocksdb_backend_tests = b.addTest(.{
        .name = "rocksdb-backend-tests",
        .root_module = rocksdb_backend_test_mod,
    });

    const run_rocksdb_backend_tests = b.addRunArtifact(rocksdb_backend_tests);

    // --- SQLite backend tests ---

    const sqlite_backend_test_mod = b.createModule(.{
        .root_source_file = b.path("src/store/sqlite.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sqlite_backend_test_mod.addImport("backend", backend_test_mod);
    sqlite_backend_test_mod.linkSystemLibrary("sqlite3", .{});

    const sqlite_backend_tests = b.addTest(.{
        .name = "sqlite-backend-tests",
        .root_module = sqlite_backend_test_mod,
    });

    const run_sqlite_backend_tests = b.addRunArtifact(sqlite_backend_tests);

    // --- Supervisor tests ---

    const supervisor_test_mod = b.createModule(.{
        .root_source_file = b.path("src/master/supervisor.zig"),
        .target = target,
        .optimize = optimize,
    });

    const supervisor_tests = b.addTest(.{
        .name = "supervisor-tests",
        .root_module = supervisor_test_mod,
    });

    const run_supervisor_tests = b.addRunArtifact(supervisor_tests);

    // --- Config module (shared by all daemons) ---

    const config_mod = b.createModule(.{
        .root_source_file = b.path("src/config/parser.zig"),
        .target = target,
        .optimize = optimize,
    });

    const config_test_mod = b.createModule(.{
        .root_source_file = b.path("src/config/parser.zig"),
        .target = target,
        .optimize = optimize,
    });

    const config_tests = b.addTest(.{
        .name = "config-tests",
        .root_module = config_test_mod,
    });

    const run_config_tests = b.addRunArtifact(config_tests);

    // --- HTTP client module (for OIDC backend) ---

    const http_mod = b.createModule(.{
        .root_source_file = b.path("lib/http/client.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    http_mod.linkSystemLibrary("ssl", .{});
    http_mod.linkSystemLibrary("crypto", .{});

    const http_test_mod = b.createModule(.{
        .root_source_file = b.path("lib/http/client.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    http_test_mod.linkSystemLibrary("ssl", .{});
    http_test_mod.linkSystemLibrary("crypto", .{});

    const http_tests = b.addTest(.{
        .name = "http-client-tests",
        .root_module = http_test_mod,
    });

    const run_http_tests = b.addRunArtifact(http_tests);

    // --- JWT module (for OIDC backend) ---

    const jwt_mod = b.createModule(.{
        .root_source_file = b.path("lib/jwt/jwt.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    jwt_mod.linkSystemLibrary("ssl", .{});
    jwt_mod.linkSystemLibrary("crypto", .{});

    const jwt_test_mod = b.createModule(.{
        .root_source_file = b.path("lib/jwt/jwt.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    jwt_test_mod.linkSystemLibrary("ssl", .{});
    jwt_test_mod.linkSystemLibrary("crypto", .{});

    const jwt_tests = b.addTest(.{
        .name = "jwt-tests",
        .root_module = jwt_test_mod,
    });

    const run_jwt_tests = b.addRunArtifact(jwt_tests);

    // --- Executables ---

    // xmppd-core: the connection handler worker
    const core_mod = b.createModule(.{
        .root_source_file = b.path("src/core/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    core_mod.addImport("xml", xml_mod);
    core_mod.addImport("xmpp", xmpp_mod);
    core_mod.addImport("sasl", sasl_mod);
    core_mod.addImport("ssl", ssl_test_mod);
    core_mod.addImport("ipc_protocol", ipc_protocol_test_mod);
    core_mod.addImport("ipc_client", ipc_client_test_mod);
    core_mod.addImport("roster_store", roster_store_mod_for_server);
    core_mod.addImport("session_registry", session_registry_mod_for_server);
    core_mod.addImport("generic_offline_store", server_generic_offline_mod);
    core_mod.addImport("archive_store", server_archive_store_mod);
    core_mod.addImport("backend", server_backend_mod);
    core_mod.addImport("op_backend", server_op_backend_mod);
    core_mod.addImport("archive_backend", server_archive_backend_mod);
    core_mod.addImport("mam_handler", server_mam_handler_mod);
    core_mod.addImport("vcard_store", server_vcard_store_mod);
    core_mod.addImport("room_store", server_room_store_mod);
    core_mod.addImport("room_registry", server_room_registry_mod);
    core_mod.addImport("config", config_mod);
    core_mod.linkSystemLibrary("ssl", .{});
    core_mod.linkSystemLibrary("crypto", .{});

    const core_exe = b.addExecutable(.{
        .name = "xmppd-core",
        .root_module = core_mod,
    });
    b.installArtifact(core_exe);

    // xmppd: the master supervisor
    const master_event_loop_mod = b.createModule(.{
        .root_source_file = b.path("src/core/event_loop.zig"),
        .target = target,
        .optimize = optimize,
    });

    const master_mod = b.createModule(.{
        .root_source_file = b.path("src/master/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    master_mod.addImport("event_loop", master_event_loop_mod);
    master_mod.addImport("config", config_mod);

    const master_exe = b.addExecutable(.{
        .name = "xmppd",
        .root_module = master_mod,
    });
    b.installArtifact(master_exe);

    // xmppd-auth: the authentication daemon
    const auth_ipc_protocol_mod = b.createModule(.{
        .root_source_file = b.path("src/ipc/protocol.zig"),
        .target = target,
        .optimize = optimize,
    });

    const auth_ipc_server_mod = b.createModule(.{
        .root_source_file = b.path("src/ipc/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_ipc_server_mod.addImport("ipc_protocol", auth_ipc_protocol_mod);

    const auth_backend_mod = b.createModule(.{
        .root_source_file = b.path("src/store/backend.zig"),
        .target = target,
        .optimize = optimize,
    });

    const auth_op_backend_mod = createBackendMod(b, op_storage, target, optimize, auth_backend_mod, lmdb_dep);

    const auth_user_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/user_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_user_store_mod.addImport("sasl", sasl_mod);
    auth_user_store_mod.addImport("backend", auth_backend_mod);

    const auth_rate_limiter_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/rate_limiter.zig"),
        .target = target,
        .optimize = optimize,
    });

    const auth_handler_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/handler.zig"),
        .target = target,
        .optimize = optimize,
    });
    const auth_lock_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/lock_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_lock_store_mod.addImport("backend", auth_backend_mod);

    auth_handler_mod.addImport("sasl", sasl_mod);
    auth_handler_mod.addImport("ipc_protocol", auth_ipc_protocol_mod);
    auth_handler_mod.addImport("rate_limiter", auth_rate_limiter_mod);
    auth_handler_mod.addImport("lock_store", auth_lock_store_mod);

    const auth_invite_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/invite_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_invite_store_mod.addImport("backend", auth_backend_mod);
    auth_handler_mod.addImport("invite_store", auth_invite_store_mod);

    const auth_event_loop_mod = b.createModule(.{
        .root_source_file = b.path("src/core/event_loop.zig"),
        .target = target,
        .optimize = optimize,
    });

    const auth_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    auth_mod.addImport("sasl", sasl_mod);
    auth_mod.addImport("ipc_protocol", auth_ipc_protocol_mod);
    auth_mod.addImport("ipc_server", auth_ipc_server_mod);
    auth_mod.addImport("user_store", auth_user_store_mod);
    auth_mod.addImport("handler", auth_handler_mod);
    auth_mod.addImport("rate_limiter", auth_rate_limiter_mod);
    auth_mod.addImport("lock_store", auth_lock_store_mod);
    auth_mod.addImport("invite_store", auth_invite_store_mod);
    auth_mod.addImport("op_backend", auth_op_backend_mod);
    auth_mod.addImport("event_loop", auth_event_loop_mod);
    auth_mod.addImport("config", config_mod);
    auth_mod.addImport("backend", auth_backend_mod);

    const auth_exe = b.addExecutable(.{
        .name = "xmppd-auth",
        .root_module = auth_mod,
    });
    b.installArtifact(auth_exe);

    // xmppd-auth-oidc: the OIDC authentication daemon
    const oidc_ipc_protocol_mod = b.createModule(.{
        .root_source_file = b.path("src/ipc/protocol.zig"),
        .target = target,
        .optimize = optimize,
    });

    const oidc_ipc_server_mod = b.createModule(.{
        .root_source_file = b.path("src/ipc/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    oidc_ipc_server_mod.addImport("ipc_protocol", oidc_ipc_protocol_mod);

    const oidc_rate_limiter_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/rate_limiter.zig"),
        .target = target,
        .optimize = optimize,
    });

    const oidc_store_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/oidc.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    oidc_store_mod.addImport("http", http_mod);
    oidc_store_mod.addImport("jwt", jwt_mod);
    oidc_store_mod.linkSystemLibrary("ssl", .{});
    oidc_store_mod.linkSystemLibrary("crypto", .{});

    const oidc_handler_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/handler.zig"),
        .target = target,
        .optimize = optimize,
    });
    oidc_handler_mod.addImport("sasl", sasl_mod);
    oidc_handler_mod.addImport("ipc_protocol", oidc_ipc_protocol_mod);
    oidc_handler_mod.addImport("rate_limiter", oidc_rate_limiter_mod);
    oidc_handler_mod.addImport("lock_store", auth_lock_store_mod);
    oidc_handler_mod.addImport("invite_store", auth_invite_store_mod);

    const oidc_event_loop_mod = b.createModule(.{
        .root_source_file = b.path("src/core/event_loop.zig"),
        .target = target,
        .optimize = optimize,
    });

    const oidc_main_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/oidc_main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    oidc_main_mod.addImport("ipc_protocol", oidc_ipc_protocol_mod);
    oidc_main_mod.addImport("ipc_server", oidc_ipc_server_mod);
    oidc_main_mod.addImport("handler", oidc_handler_mod);
    oidc_main_mod.addImport("oidc", oidc_store_mod);
    oidc_main_mod.addImport("rate_limiter", oidc_rate_limiter_mod);
    oidc_main_mod.addImport("event_loop", oidc_event_loop_mod);
    oidc_main_mod.addImport("config", config_mod);
    oidc_main_mod.linkSystemLibrary("ssl", .{});
    oidc_main_mod.linkSystemLibrary("crypto", .{});

    const oidc_exe = b.addExecutable(.{
        .name = "xmppd-auth-oidc",
        .root_module = oidc_main_mod,
    });
    b.installArtifact(oidc_exe);

    // xmppd-s2s: the S2S federation daemon
    const s2s_ipc_protocol_mod = b.createModule(.{
        .root_source_file = b.path("src/ipc/protocol.zig"),
        .target = target,
        .optimize = optimize,
    });

    const s2s_ipc_server_mod = b.createModule(.{
        .root_source_file = b.path("src/ipc/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    s2s_ipc_server_mod.addImport("ipc_protocol", s2s_ipc_protocol_mod);

    const s2s_event_loop_exe_mod = b.createModule(.{
        .root_source_file = b.path("src/core/event_loop.zig"),
        .target = target,
        .optimize = optimize,
    });

    const s2s_main_mod = b.createModule(.{
        .root_source_file = b.path("src/s2s/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    s2s_main_mod.addImport("ipc_protocol", s2s_ipc_protocol_mod);
    s2s_main_mod.addImport("ipc_server", s2s_ipc_server_mod);
    s2s_main_mod.addImport("event_loop", s2s_event_loop_exe_mod);
    s2s_main_mod.addImport("xml", xml_mod);
    s2s_main_mod.addImport("ssl", ssl_test_mod);
    s2s_main_mod.addImport("dns", dns_test_mod);
    s2s_main_mod.linkSystemLibrary("ssl", .{});
    s2s_main_mod.linkSystemLibrary("crypto", .{});

    const s2s_exe = b.addExecutable(.{
        .name = "xmppd-s2s",
        .root_module = s2s_main_mod,
    });
    b.installArtifact(s2s_exe);

    // xmppctl: user management CLI
    const ctl_backend_mod = b.createModule(.{
        .root_source_file = b.path("src/store/backend.zig"),
        .target = target,
        .optimize = optimize,
    });

    const ctl_op_backend_mod = createBackendMod(b, op_storage, target, optimize, ctl_backend_mod, lmdb_dep);

    const ctl_user_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/user_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    ctl_user_store_mod.addImport("sasl", sasl_mod);
    ctl_user_store_mod.addImport("backend", ctl_backend_mod);

    const ctl_mod = b.createModule(.{
        .root_source_file = b.path("src/ctl/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const ctl_lock_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/lock_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    ctl_lock_store_mod.addImport("backend", ctl_backend_mod);

    ctl_mod.addImport("user_store", ctl_user_store_mod);
    const ctl_invite_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/invite_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    ctl_invite_store_mod.addImport("backend", ctl_backend_mod);

    ctl_mod.addImport("lock_store", ctl_lock_store_mod);
    ctl_mod.addImport("invite_store", ctl_invite_store_mod);
    ctl_mod.addImport("op_backend", ctl_op_backend_mod);
    ctl_mod.addImport("ipc_protocol", ipc_protocol_test_mod);

    const ctl_exe = b.addExecutable(.{
        .name = "xmppctl",
        .root_module = ctl_mod,
    });
    b.installArtifact(ctl_exe);

    // xmppctl tests
    const ctl_test_mod = b.createModule(.{
        .root_source_file = b.path("src/ctl/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ctl_test_mod.addImport("user_store", ctl_user_store_mod);
    ctl_test_mod.addImport("lock_store", ctl_lock_store_mod);
    ctl_test_mod.addImport("invite_store", ctl_invite_store_mod);
    ctl_test_mod.addImport("op_backend", ctl_op_backend_mod);
    ctl_test_mod.addImport("ipc_protocol", ipc_protocol_test_mod);

    const ctl_tests = b.addTest(.{
        .name = "xmppctl-tests",
        .root_module = ctl_test_mod,
    });

    const run_ctl_tests = b.addRunArtifact(ctl_tests);

    // --- Test step ---

    const test_step = b.step("test", "Run all library tests");
    test_step.dependOn(&run_xml_tests.step);
    test_step.dependOn(&run_xmpp_tests.step);
    test_step.dependOn(&run_sasl_tests.step);
    test_step.dependOn(&run_tls_tests.step);
    test_step.dependOn(&run_ssl_tests.step);
    test_step.dependOn(&run_dns_tests.step);
    test_step.dependOn(&run_event_loop_tests.step);
    test_step.dependOn(&run_connection_tests.step);
    test_step.dependOn(&run_listener_tests.step);
    test_step.dependOn(&run_server_tests.step);
    test_step.dependOn(&run_ipc_protocol_tests.step);
    test_step.dependOn(&run_ipc_client_tests.step);
    test_step.dependOn(&run_ipc_server_tests.step);
    test_step.dependOn(&run_user_store_tests.step);
    test_step.dependOn(&run_auth_handler_tests.step);
    test_step.dependOn(&run_ctl_tests.step);
    test_step.dependOn(&run_supervisor_tests.step);
    test_step.dependOn(&run_roster_store_tests.step);
    test_step.dependOn(&run_session_registry_tests.step);
    test_step.dependOn(&run_offline_store_tests.step);
    test_step.dependOn(&run_s2s_stream_tests.step);
    test_step.dependOn(&run_s2s_connector_tests.step);
    test_step.dependOn(&run_s2s_dane_tests.step);
    test_step.dependOn(&run_s2s_dialback_tests.step);
    test_step.dependOn(&run_s2s_session_tests.step);
    test_step.dependOn(&run_s2s_main_tests.step);
    test_step.dependOn(&run_backend_tests.step);
    test_step.dependOn(&run_lmdb_backend_tests.step);
    test_step.dependOn(&run_rocksdb_backend_tests.step);
    test_step.dependOn(&run_sqlite_backend_tests.step);
    test_step.dependOn(&run_generic_user_store_tests.step);
    test_step.dependOn(&run_generic_roster_store_tests.step);
    test_step.dependOn(&run_vcard_store_tests.step);
    test_step.dependOn(&run_archive_store_tests.step);
    test_step.dependOn(&run_mam_handler_tests.step);
    test_step.dependOn(&run_generic_offline_store_tests.step);
    test_step.dependOn(&run_rate_limiter_tests.step);
    test_step.dependOn(&run_lock_store_tests.step);
    test_step.dependOn(&run_invite_store_tests.step);
    test_step.dependOn(&run_room_store_tests.step);
    test_step.dependOn(&run_room_registry_tests.step);
    test_step.dependOn(&run_fanout_tests.step);
    test_step.dependOn(&run_config_tests.step);
    test_step.dependOn(&run_http_tests.step);
    test_step.dependOn(&run_jwt_tests.step);
}

/// Create a storage backend module based on the given storage flag value.
/// Returns a module that exports the selected backend type via its public API.
fn createBackendMod(
    b: *std.Build,
    storage: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    backend_mod: *std.Build.Module,
    lmdb_dep: *std.Build.Dependency,
) *std.Build.Module {
    if (std.mem.eql(u8, storage, "lmdb")) {
        const mod = b.createModule(.{
            .root_source_file = b.path("src/store/lmdb.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        mod.addImport("lmdb", lmdb_dep.module("lmdb"));
        mod.addImport("backend", backend_mod);
        return mod;
    } else if (std.mem.eql(u8, storage, "rocksdb")) {
        const mod = b.createModule(.{
            .root_source_file = b.path("src/store/rocksdb.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        mod.addImport("backend", backend_mod);
        mod.linkSystemLibrary("rocksdb", .{});
        mod.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        mod.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
        return mod;
    } else if (std.mem.eql(u8, storage, "sqlite")) {
        const mod = b.createModule(.{
            .root_source_file = b.path("src/store/sqlite.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        mod.addImport("backend", backend_mod);
        mod.linkSystemLibrary("sqlite3", .{});
        return mod;
    } else {
        std.debug.print("error: unknown storage backend value: '{s}' (valid: lmdb, rocksdb, sqlite)\n", .{storage});
        @panic("invalid storage backend value");
    }
}
