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

    const server_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/server.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    server_test_mod.addImport("xml", xml_mod);
    server_test_mod.addImport("xmpp", xmpp_mod);
    server_test_mod.addImport("sasl", sasl_mod);
    server_test_mod.addImport("ssl", ssl_test_mod);
    server_test_mod.linkSystemLibrary("ssl", .{});
    server_test_mod.linkSystemLibrary("crypto", .{});

    const server_tests = b.addTest(.{
        .name = "server-tests",
        .root_module = server_test_mod,
    });

    const run_server_tests = b.addRunArtifact(server_tests);

    // --- IPC tests ---

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
    core_mod.linkSystemLibrary("ssl", .{});
    core_mod.linkSystemLibrary("crypto", .{});

    const core_exe = b.addExecutable(.{
        .name = "xmppd-core",
        .root_module = core_mod,
    });
    b.installArtifact(core_exe);

    // xmppd: the master supervisor
    const master_mod = b.createModule(.{
        .root_source_file = b.path("src/master/main.zig"),
        .target = target,
        .optimize = optimize,
    });

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

    const auth_exe = b.addExecutable(.{
        .name = "xmppd-auth",
        .root_module = auth_mod,
    });
    b.installArtifact(auth_exe);

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
}
