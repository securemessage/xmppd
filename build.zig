const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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

    // --- Server tests (depends on IPC modules) ---

    const server_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/server.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const roster_store_mod_for_server = b.createModule(.{
        .root_source_file = b.path("src/core/roster_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    const session_registry_mod_for_server = b.createModule(.{
        .root_source_file = b.path("src/core/session_registry.zig"),
        .target = target,
        .optimize = optimize,
    });
    const offline_store_mod_for_server = b.createModule(.{
        .root_source_file = b.path("src/core/offline_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_test_mod.addImport("xml", xml_mod);
    server_test_mod.addImport("xmpp", xmpp_mod);
    server_test_mod.addImport("sasl", sasl_mod);
    server_test_mod.addImport("ssl", ssl_test_mod);
    server_test_mod.addImport("ipc_protocol", ipc_protocol_test_mod);
    server_test_mod.addImport("ipc_client", ipc_client_test_mod);
    server_test_mod.addImport("roster_store", roster_store_mod_for_server);
    server_test_mod.addImport("session_registry", session_registry_mod_for_server);
    server_test_mod.addImport("offline_store", offline_store_mod_for_server);
    server_test_mod.linkSystemLibrary("ssl", .{});
    server_test_mod.linkSystemLibrary("crypto", .{});

    const server_tests = b.addTest(.{
        .name = "server-tests",
        .root_module = server_test_mod,
    });

    const run_server_tests = b.addRunArtifact(server_tests);

    // --- Auth tests ---

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

    const auth_handler_test_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/handler.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_handler_test_mod.addImport("sasl", sasl_mod);
    auth_handler_test_mod.addImport("ipc_protocol", ipc_protocol_test_mod);
    auth_handler_test_mod.addImport("user_store", user_store_test_mod);

    const auth_handler_tests = b.addTest(.{
        .name = "auth-handler-tests",
        .root_module = auth_handler_test_mod,
    });

    const run_auth_handler_tests = b.addRunArtifact(auth_handler_tests);

    // --- Roster store tests ---

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
    });

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
    });

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
    s2s_main_test_mod.linkSystemLibrary("ssl", .{});
    s2s_main_test_mod.linkSystemLibrary("crypto", .{});

    const s2s_main_tests = b.addTest(.{
        .name = "s2s-main-tests",
        .root_module = s2s_main_test_mod,
    });

    const run_s2s_main_tests = b.addRunArtifact(s2s_main_tests);

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
    core_mod.addImport("offline_store", offline_store_mod_for_server);
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

    const auth_user_store_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/user_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_user_store_mod.addImport("sasl", sasl_mod);

    const auth_handler_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/handler.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_handler_mod.addImport("sasl", sasl_mod);
    auth_handler_mod.addImport("ipc_protocol", auth_ipc_protocol_mod);
    auth_handler_mod.addImport("user_store", auth_user_store_mod);

    const auth_event_loop_mod = b.createModule(.{
        .root_source_file = b.path("src/core/event_loop.zig"),
        .target = target,
        .optimize = optimize,
    });

    const auth_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_mod.addImport("sasl", sasl_mod);
    auth_mod.addImport("ipc_protocol", auth_ipc_protocol_mod);
    auth_mod.addImport("ipc_server", auth_ipc_server_mod);
    auth_mod.addImport("user_store", auth_user_store_mod);
    auth_mod.addImport("handler", auth_handler_mod);
    auth_mod.addImport("event_loop", auth_event_loop_mod);

    const auth_exe = b.addExecutable(.{
        .name = "xmppd-auth",
        .root_module = auth_mod,
    });
    b.installArtifact(auth_exe);

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
    s2s_main_mod.linkSystemLibrary("ssl", .{});
    s2s_main_mod.linkSystemLibrary("crypto", .{});

    const s2s_exe = b.addExecutable(.{
        .name = "xmppd-s2s",
        .root_module = s2s_main_mod,
    });
    b.installArtifact(s2s_exe);

    // xmppctl: user management CLI
    const ctl_user_store_mod = b.createModule(.{
        .root_source_file = b.path("src/auth/user_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    ctl_user_store_mod.addImport("sasl", sasl_mod);

    const ctl_mod = b.createModule(.{
        .root_source_file = b.path("src/ctl/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ctl_mod.addImport("user_store", ctl_user_store_mod);

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
}
