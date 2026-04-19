const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.zigdig_main);

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    _ = init.io;

    var args_it = init.minimal.args.iterate();
    _ = args_it.skip();

    const name_string = (args_it.next() orelse {
        logger.warn("no name provided", .{});
        return error.InvalidArgs;
    });

    var addrs = try dns.helpers.getAddressList(name_string, 80, gpa);
    defer addrs.deinit();

    var stdout_buffer: [1024]u8 = undefined;
    var stdout = std.Io.Writer.fixed(&stdout_buffer);

    for (addrs.addrs) |addr| {
        try stdout.print("{s} has address {f}\n", .{ name_string, addr });
    }
    try stdout.flush();
}
