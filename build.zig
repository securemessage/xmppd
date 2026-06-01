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

    const xml_tests = b.addTest(.{
        .name = "xml-tests",
        .root_module = xml_test_mod,
    });

    const xmpp_tests = b.addTest(.{
        .name = "xmpp-tests",
        .root_module = xmpp_test_mod,
    });

    const run_xml_tests = b.addRunArtifact(xml_tests);
    const run_xmpp_tests = b.addRunArtifact(xmpp_tests);

    const test_step = b.step("test", "Run all library tests");
    test_step.dependOn(&run_xml_tests.step);
    test_step.dependOn(&run_xmpp_tests.step);
}
