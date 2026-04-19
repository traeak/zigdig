const std = @import("std");
const builtin = @import("builtin");
const dns = @import("lib.zig");

const logger = std.log.scoped(.zigdig_main);

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var args_it = init.minimal.args.iterate();
    _ = args_it.skip();

    const name_string = (args_it.next() orelse {
        logger.warn("no name provided", .{});
        return error.InvalidArgs;
    });

    const qtype_str = (args_it.next() orelse {
        logger.warn("no qtype provided", .{});
        return error.InvalidArgs;
    });

    const qtype = dns.ResourceType.fromString(qtype_str) catch |err| switch (err) {
        error.InvalidResourceType => {
            logger.warn("invalid query type provided", .{});
            return error.InvalidArgs;
        },
    };

    var name_buffer: [128][]const u8 = undefined;
    const name = try dns.Name.fromString(name_string, &name_buffer);

    var questions = [_]dns.Question{
        .{
            .name = name,
            .typ = qtype,
            .class = .IN,
        },
    };

    var empty = [0]dns.Resource{};

    // create question packet
    var packet = dns.Packet{
        .header = .{
            .id = dns.helpers.randomHeaderId(io),
            .is_response = false,
            .wanted_recursion = true,
            .question_length = 1,
        },
        .questions = &questions,
        .answers = &empty,
        .nameservers = &empty,
        .additionals = &empty,
    };

    logger.debug("packet: {any}", .{packet});

    const conn = if (builtin.os.tag == .windows)
        try dns.helpers.connectToResolver("8.8.8.8", null)
    else
        try dns.helpers.connectToSystemResolver();
    defer conn.close();

    logger.info("selected nameserver: {f}\n", .{conn.socket.address});

    var stdout_buffer: [1024]u8 = undefined;
    var stdout = std.Io.Writer.fixed(&stdout_buffer);

    // print out our same question as a zone file for debugging purposes
    try dns.helpers.printAsZoneFile(&packet, undefined, &stdout);

    try conn.sendPacket(io, conn.socket.address, packet);

    // as we need Names inside the NamePool to live beyond the call to
    // receiveFullPacket (since we need to deserialize names in RDATA)
    // we must take ownership of them and deinit ourselves
    var name_pool = dns.NamePool.init(gpa);
    defer name_pool.deinitWithNames();

    const reply = try conn.receiveFullPacket(
        io,
        gpa,
        4096,
        .{ .name_pool = &name_pool },
    );
    defer reply.deinit(.{ .names = false });

    const reply_packet = reply.packet;
    logger.debug("reply: {any}", .{reply_packet});

    try std.testing.expectEqual(packet.header.id, reply_packet.header.id);
    try std.testing.expect(reply_packet.header.is_response);

    try dns.helpers.printAsZoneFile(reply_packet, &name_pool, &stdout);
    try stdout.flush();
}
