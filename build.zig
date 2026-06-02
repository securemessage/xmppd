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

    const dns_tests = b.addTest(.{
        .name = "dns-tests",
        .root_module = dns_test_mod,
    });

    const run_xml_tests = b.addRunArtifact(xml_tests);
    const run_xmpp_tests = b.addRunArtifact(xmpp_tests);
    const run_sasl_tests = b.addRunArtifact(sasl_tests);
    const run_tls_tests = b.addRunArtifact(tls_tests);
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
    });

    const connection_tests = b.addTest(.{
        .name = "connection-tests",
        .root_module = connection_test_mod,
    });

    const run_connection_tests = b.addRunArtifact(connection_tests);

    const listener_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/listener.zig"),
        .target = target,
        .optimize = optimize,
    });

    const listener_tests = b.addTest(.{
        .name = "listener-tests",
        .root_module = listener_test_mod,
    });

    const run_listener_tests = b.addRunArtifact(listener_tests);

    const server_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_test_mod.addImport("xml", xml_mod);
    server_test_mod.addImport("xmpp", xmpp_mod);
    server_test_mod.addImport("sasl", sasl_mod);

    const server_tests = b.addTest(.{
        .name = "server-tests",
        .root_module = server_test_mod,
    });

    const run_server_tests = b.addRunArtifact(server_tests);

    const test_step = b.step("test", "Run all library tests");
    test_step.dependOn(&run_xml_tests.step);
    test_step.dependOn(&run_xmpp_tests.step);
    test_step.dependOn(&run_sasl_tests.step);
    test_step.dependOn(&run_tls_tests.step);
    test_step.dependOn(&run_dns_tests.step);
    test_step.dependOn(&run_event_loop_tests.step);
    test_step.dependOn(&run_connection_tests.step);
    test_step.dependOn(&run_listener_tests.step);
    test_step.dependOn(&run_server_tests.step);
}
