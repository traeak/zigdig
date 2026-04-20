const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.zigdig_main);
pub const std_options = std.Options{
    .log_level = .debug,
    .logFn = logfn,
};

pub var current_log_level: std.log.Level = .info;

fn logfn(
    comptime message_level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) <= @intFromEnum(@import("root").current_log_level)) {
        std.log.defaultLog(message_level, scope, format, args);
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    if (std.mem.eql(u8, init.environ_map.get("DEBUG") orelse "", "1")) current_log_level = .debug;

    var args_it = init.minimal.args.iterate();
    _ = args_it.next(); // skip program name

    const name_string = (args_it.next() orelse {
        logger.warn("no name provided", .{});
        return error.InvalidArgs;
    });

    var addrs = try dns.helpers.getAddressList(io, name_string, 80, allocator);
    defer addrs.deinit();

    var stdout_buffer: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &stdout_buffer);

    for (addrs.addrs) |addr| {
        try stdout.interface.print("{s} has address {f}\n", .{ name_string, addr });
    }
    try stdout.interface.flush();
}
