const std = @import("std");
const builtin = @import("builtin");
const dns = @import("lib.zig");

const CidrRange = @import("cidr.zig").CidrRange;

fn printList(
    name_pool: *dns.NamePool,
    writer: anytype,
    resource_list: []dns.Resource,
) !void {
    try writer.print(";;name\t\t\trrtype\tclass\tttl\trdata\n", .{});

    for (resource_list) |resource| {
        const resource_data = try dns.ResourceData.fromOpaque(
            resource.typ,
            resource.opaque_rdata.?,
            .{
                .name_provider = .{ .full = name_pool },
                .allocator = name_pool.allocator,
            },
        );
        defer switch (resource_data) {
            .TXT => resource_data.deinit(name_pool.allocator),
            else => {},
        };

        try writer.print("{?f}\t\t{s}\t{s}\t{d}\t{f}\n", .{
            resource.name,
            @tagName(resource.typ),
            @tagName(resource.class),
            resource.ttl,
            resource_data,
        });
    }

    try writer.print("\n", .{});
}

pub fn printAsZoneFile(
    packet: *dns.Packet,
    name_pool: *dns.NamePool,
    writer: anytype,
) !void {
    try writer.print(";; opcode: {}, status: {}, id: {}\n", .{
        packet.header.opcode,
        packet.header.response_code,
        packet.header.id,
    });

    try writer.print(";; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n\n", .{
        packet.header.question_length,
        packet.header.answer_length,
        packet.header.nameserver_length,
        packet.header.additional_length,
    });

    if (packet.header.question_length > 0) {
        try writer.print(";; QUESTION SECTION:\n", .{});
        try writer.print(";;name\ttype\tclass\n", .{});

        for (packet.questions) |question| {
            try writer.print(";{?f}\t{s}\t{s}\n", .{
                question.name,
                @tagName(question.typ),
                @tagName(question.class),
            });
        }

        try writer.print("\n", .{});
    }

    if (packet.header.answer_length > 0) {
        try writer.print(";; ANSWER SECTION:\n", .{});
        try printList(name_pool, writer, packet.answers);
    } else {
        try writer.print(";; no answer\n", .{});
    }

    if (packet.header.nameserver_length > 0) {
        try writer.print(";; AUTHORITY SECTION:\n", .{});
        try printList(name_pool, writer, packet.nameservers);
    } else {
        try writer.print(";; no authority\n\n", .{});
    }

    if (packet.header.additional_length > 0) {
        try writer.print(";; ADDITIONAL SECTION:\n", .{});
        try printList(name_pool, writer, packet.additionals);
    } else {
        try writer.print(";; no additional\n\n", .{});
    }
}

/// Generate a random header ID to use in a query.
pub fn randomHeaderId(io: std.Io) u16 {
    const now = std.Io.Clock.now(.real, io);
    const seed: u64 = @as(u64, @intCast(now.nanoseconds));
    var r = std.Random.DefaultPrng.init(seed);
    return r.random().int(u16);
}

/// High level wrapper around a single UDP connection to send and receive
/// DNS packets.
pub const DNSConnection = struct {
    socket: std.Io.net.Socket,

    const Self = @This();

    pub fn close(self: *const Self) void {
        _ = self;
    }

    pub fn sendPacket(self: *const Self, io: std.Io, dest: std.Io.net.IpAddress, packet: dns.Packet) !void {
        var buffer: [1024]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try packet.writeTo(&writer);
        try self.socket.send(io, &dest, buffer[0..writer.end]);
    }

    pub fn receiveFullPacket(
        self: *const Self,
        io: std.Io,
        packet_allocator: std.mem.Allocator,
        comptime max_incoming_message_size: usize,
        options: ParseFullPacketOptions,
    ) !dns.IncomingPacket {
        var packet_buffer: [max_incoming_message_size]u8 = undefined;
        const msg = try self.socket.receive(io, &packet_buffer);
        const packet_bytes = msg.data;
        logger.debug("read {d} bytes", .{msg.data.len});

        var stream = std.Io.Reader.fixed(packet_bytes);
        return parseFullPacket(&stream, packet_allocator, options);
    }
};

pub const ParseFullPacketOptions = struct {
    name_pool: ?*dns.NamePool = null,
};

pub fn parseFullPacket(
    reader: *std.Io.Reader,
    allocator: std.mem.Allocator,
    parse_full_packet_options: ParseFullPacketOptions,
) !dns.IncomingPacket {
    const parser_options = dns.ParserOptions{ .allocator = allocator };

    var packet = try allocator.create(dns.Packet);
    errdefer allocator.destroy(packet);
    const incoming_packet = dns.IncomingPacket{
        .allocator = allocator,
        .packet = packet,
    };

    var parser = dns.Parser.init(reader, parser_options);

    var builtin_name_pool = dns.NamePool.init(allocator);
    defer builtin_name_pool.deinit();

    var name_pool = if (parse_full_packet_options.name_pool) |np|
        np
    else
        &builtin_name_pool;

    var questions = std.array_list.Managed(dns.Question).init(allocator);
    defer questions.deinit();

    var answers = std.array_list.Managed(dns.Resource).init(allocator);
    defer answers.deinit();

    var nameservers = std.array_list.Managed(dns.Resource).init(allocator);
    defer nameservers.deinit();

    var additionals = std.array_list.Managed(dns.Resource).init(allocator);
    defer additionals.deinit();

    while (try parser.next()) |part| {
        switch (part) {
            .header => |header| packet.header = header,
            .question => |question_with_raw_names| {
                const question = try name_pool.transmuteResource(question_with_raw_names);
                try questions.append(question);
            },
            .end_question => packet.questions = try questions.toOwnedSlice(),
            .answer, .nameserver, .additional => |raw_resource| {
                const resource = try name_pool.transmuteResource(raw_resource);
                try (switch (part) {
                    .answer => answers,
                    .nameserver => nameservers,
                    .additional => additionals,
                    else => unreachable,
                }).append(resource);
            },
            .end_answer => packet.answers = try answers.toOwnedSlice(),
            .end_nameserver => packet.nameservers = try nameservers.toOwnedSlice(),
            .end_additional => packet.additionals = try additionals.toOwnedSlice(),
            .answer_rdata, .nameserver_rdata, .additional_rdata => unreachable,
        }
    }

    return incoming_packet;
}

const logger = std.log.scoped(.dns_helpers);

pub fn connectToResolver(address: []const u8, port: ?u16) !DNSConnection {
    const addr = blk: {
        if (builtin.os.tag == .windows) {
            break :blk try std.Io.net.IpAddress.parse(address, port orelse 53);
        } else {
            break :blk try std.Io.net.IpAddress.parse(address, port orelse 53);
        }
    };

    const fd: std.posix.fd_t = switch (addr) {
        .ip4 => blk: {
            const result = std.os.linux.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
            if (result < 0) return std.posix.errno(@as(i32, @intCast(result)));
            break :blk @as(std.posix.fd_t, @intCast(result));
        },
        .ip6 => blk: {
            const result = std.os.linux.socket(std.posix.AF.INET6, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
            if (result < 0) return std.posix.errno(@as(i32, @intCast(result)));
            break :blk @as(std.posix.fd_t, @intCast(result));
        },
    };

    return DNSConnection{
        .socket = .{ .handle = fd, .address = addr },
    };
}

pub fn connectToSystemResolver() !DNSConnection {
    var out_buffer: [256]u8 = undefined;

    if (builtin.os.tag != .linux) @compileError("connectToSystemResolver not supported on this target");

    const nameserver_address_string = (try randomNameserver(&out_buffer)).?;

    return connectToResolver(nameserver_address_string, null);
}

pub fn randomNameserver(output_buffer: []u8) !?[]const u8 {
    const io = std.Io.Threaded.io(std.Io.Threaded.global_single_threaded);
    var file = try std.Io.Dir.openFileAbsolute(io, "/etc/resolv.conf",
        .{ .mode = .read_only },
    );
    defer file.close(io);

    var line_buffer: [1024]u8 = undefined;
    var reader = file.reader(io, &line_buffer);
    try reader.seekTo(0);

    var nameserver_amount: usize = 0;
    while (try reader.interface.takeDelimiter('\n')) |line| {
        if (std.mem.startsWith(u8, line, "#")) continue;

        var ns_it = std.mem.splitSequence(u8, line, " ");
        const decl_name = ns_it.next();
        if (decl_name == null) continue;

        if (std.mem.eql(u8, decl_name.?, "nameserver")) {
            nameserver_amount += 1;
        }
    }

    const now = std.Io.Clock.now(.real, io);
    const seed: u64 = @as(u64, @intCast(now.nanoseconds));
    var r = std.Random.DefaultPrng.init(seed);
    const selected = r.random().uintLessThan(usize, nameserver_amount);

    try reader.seekTo(0);

    var current_nameserver: usize = 0;

    while (try reader.interface.takeDelimiter('\n')) |line| {
        if (std.mem.startsWith(u8, line, "#")) continue;

        var ns_it = std.mem.splitSequence(u8, line, " ");
        const decl_name = ns_it.next();
        if (decl_name == null) continue;

        if (std.mem.eql(u8, decl_name.?, "nameserver")) {
            if (current_nameserver == selected) {
                const nameserver_addr = ns_it.next().?;
                @memcpy(output_buffer[0..nameserver_addr.len], nameserver_addr);
                return output_buffer[0..nameserver_addr.len];
            }
            current_nameserver += 1;
        }
    }

    return null;
}

const AddressList = struct {
    allocator: std.mem.Allocator,
    addrs: []std.Io.net.IpAddress,
    pub fn deinit(self: @This()) void {
        self.allocator.free(self.addrs);
    }

    fn fromList(allocator: std.mem.Allocator, addrs: *std.array_list.Managed(std.Io.net.IpAddress)) !AddressList {
        return AddressList{ .allocator = allocator, .addrs = try addrs.toOwnedSlice() };
    }
};

const ReceiveTrustedAddressesOptions = struct {
    max_incoming_message_size: usize = 4096,
    requested_packet_header: ?dns.Header = null,
};

pub fn receiveTrustedAddresses(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: *const DNSConnection,
    comptime options: ReceiveTrustedAddressesOptions,
) ![]std.Io.net.IpAddress {
    var packet_buffer: [options.max_incoming_message_size]u8 = undefined;
    const msg = try connection.socket.receive(io, &packet_buffer);
    const packet_bytes = msg.data;
    logger.debug("read {d} bytes", .{msg.data.len});

    var reader = std.Io.Reader.fixed(packet_bytes);

    var parser = dns.Parser.init(&reader, .{});

    var addrs = std.array_list.Managed(std.Io.net.IpAddress).init(allocator);
    errdefer addrs.deinit();

    var current_resource: ?dns.Resource = null;

    while (try parser.next()) |part| {
        switch (part) {
            .header => |header| {
                if (options.requested_packet_header) |given_header| {
                    if (given_header.id != header.id)
                        return error.InvalidReply;
                }

                if (!header.is_response) return error.InvalidResponse;

                switch (header.response_code) {
                    .NoError => {},
                    .FormatError => return error.ServerFormatError,
                    .ServerFailure => return error.ServerFailure,
                    .NameError => return error.ServerNameError,
                    .NotImplemented => return error.ServerNotImplemented,
                    .Refused => return error.ServerRefused,
                }
            },
            .answer => |raw_resource| {
                current_resource = raw_resource;
            },

            .answer_rdata => |rdata| {
                defer current_resource = null;
                const maybe_addr = switch (current_resource.?.typ) {
                    .A => blk: {
                        var ip4addr: [4]u8 = undefined;
                        _ = try reader.readSliceAll(&ip4addr);
                        break :blk std.Io.net.IpAddress{ .ip4 = .{ .bytes = ip4addr, .port = 0 } };
                    },
                    .AAAA => blk: {
                        var ip6_addr: [16]u8 = undefined;
                        _ = try reader.readSliceAll(&ip6_addr);
                        break :blk std.Io.net.IpAddress{ .ip6 = .{ .bytes = ip6_addr, .port = 0, .flow = 0, .interface = .none } };
                    },
                    else => blk: {
                        reader.toss(rdata.size);
                        break :blk null;
                    },
                };

                if (maybe_addr) |addr| try addrs.append(addr);
            },
            else => {},
        }
    }

    return try addrs.toOwnedSlice();
}

fn fetchTrustedAddresses(
    allocator: std.mem.Allocator,
    io: std.Io,
    name: dns.Name,
    qtype: dns.ResourceType,
) ![]std.Io.net.IpAddress {
    var questions = [_]dns.Question{
        .{
            .name = name,
            .typ = qtype,
            .class = .IN,
        },
    };

    const packet = dns.Packet{
        .header = .{
            .id = dns.helpers.randomHeaderId(io),
            .is_response = false,
            .wanted_recursion = true,
            .question_length = 1,
        },
        .questions = &questions,
        .answers = &[_]dns.Resource{},
        .nameservers = &[_]dns.Resource{},
        .additionals = &[_]dns.Resource{},
    };

    const conn = try dns.helpers.connectToSystemResolver();
    defer conn.socket.close(io);

    logger.debug("selected nameserver", .{});
    try conn.sendPacket(io, conn.socket.address, packet);
    return try receiveTrustedAddresses(allocator, io, &conn, .{});
}

fn lookupHosts(addrs: *std.array_list.Managed(std.Io.net.IpAddress), io: std.Io, family: std.posix.sa_family_t, port: u16, name: []const u8) !void {
    const file = std.Io.Dir.openFileAbsolute(io, "/etc/hosts", .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound,
        error.NotDir,
        error.AccessDenied,
        => return,
        else => |e| return e,
    };
    defer file.close(io);

    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    while (reader.interface.takeDelimiter('\n') catch |err| switch (err) {
        error.StreamTooLong => return error.StreamTooLong,
        else => |e| return e,
    }) |line| {
        var split_it = std.mem.splitScalar(u8, line, '#');
        const no_comment_line = split_it.first();

        var line_it = std.mem.tokenizeAny(u8, no_comment_line, " \t");
        const ip_text = line_it.next() orelse continue;
        var first_name_text: ?[]const u8 = null;
        while (line_it.next()) |name_text| {
            if (first_name_text == null) first_name_text = name_text;
            if (std.mem.eql(u8, name_text, name)) {
                break;
            }
        } else continue;

        const addr = parseIpWithFamily(ip_text, family, port) catch continue;
        try addrs.append(addr);
    }
}

fn parseIpWithFamily(ip_text: []const u8, family: std.posix.sa_family_t, port: u16) !std.Io.net.IpAddress {
    const addr = std.Io.net.IpAddress.parse(ip_text, port) catch return error.InvalidIPAddressFormat;
    const expected_family: std.posix.sa_family_t = switch (addr) {
        .ip4 => std.posix.AF.INET,
        .ip6 => std.posix.AF.INET6,
    };
    if (expected_family != family) return error.InvalidIPAddressFormat;
    return addr;
}

pub fn getAddressList(incoming_name: []const u8, port: u16, allocator: std.mem.Allocator) !AddressList {
    var name_buffer: [128][]const u8 = undefined;
    const name = try dns.Name.fromString(incoming_name, &name_buffer);

    var final_list = std.array_list.Managed(std.Io.net.IpAddress).init(allocator);
    defer final_list.deinit();

    const last_label = name.full.labels[name.full.labels.len - 1];

    if (parseIpWithFamily(incoming_name, std.posix.AF.INET, port) catch null) |addr| {
        try final_list.append(addr);
    } else if (parseIpWithFamily(incoming_name, std.posix.AF.INET6, port) catch null) |addr| {
        try final_list.append(addr);
    } else if (std.mem.eql(u8, last_label, "localhost")) {
        try final_list.append(std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.loopback(port) });
        try final_list.append(std.Io.net.IpAddress{ .ip6 = std.Io.net.Ip6Address.loopback(port) });
    } else {
        if (builtin.os.tag == .windows) {
            const name_c = try allocator.dupeZ(u8, incoming_name);
            defer allocator.free(name_c);

            const port_c = try std.fmt.allocPrintZ(allocator, "{}", .{port});
            defer allocator.free(port_c);

            var addr_info: ?*std.os.windows.ws2_32.addrinfoa = null;

            const hints: std.os.windows.ws2_32.addrinfo = .{
                .flags = .{ .NUMERICSERV = true },
                .family = std.os.windows.ws2_32.AF.UNSPEC,
                .socktype = std.os.windows.ws2_32.SOCK.STREAM,
                .protocol = std.os.windows.ws2_32.IPPROTO.TCP,
                .addr = null,
                .canonname = null,
                .addrlen = 0,
                .next = null,
            };

            for (0..2) |_| {
                const res = std.os.windows.ws2_32.getaddrinfoa(name_c.ptr, port_c.ptr, &hints, &addr_info);

                if (res != 0) {
                    switch (@as(std.os.windows.ws2_32.WinsockError, @enumFromInt(res))) {
                        .WSATRY_AGAIN => return error.TryAgain,
                        .WSAEINVAL => return error.InvalidArgument,
                        .WSANO_RECOVERY => return error.Fatal,
                        .WSAEAFNOSUPPORT => return error.FamilyNotSupported,
                        .WSA_NOT_ENOUGH_MEMORY => return error.NotEnoughMemory,
                        .WSAHOST_NOT_FOUND => return error.HostNotFound,
                        .WSATYPE_NOT_FOUND => return error.TypeNotFound,
                        .WSAESOCKTNOSUPPORT => return error.SocketTypeNotSupported,
                        .WSANOTINITIALISED => {
                            try std.os.windows.callWSAStartup();
                            continue;
                        },
                        else => return error.InternalUnexpected,
                    }
                } else break;
            } else return error.InternalUnexpected;

            defer std.os.windows.ws2_32.freeaddrinfoa(addr_info);

            while (addr_info) |ai| : (addr_info = ai.next) {
                switch (@as(std.os.windows.ws2_32.sa_family_t, @enumFromInt(ai.family))) {
                    .AF_INET => {
                        const sa: *std.os.windows.ws2_32.sockaddr_in = @as(
                            *std.os.windows.ws2_32.sockaddr_in,
                            @ptrCast(@alignCast(ai.addr orelse continue)),
                        );
                        const addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address{
                            .bytes = @bitCast(sa.sin_addr.s_addr),
                            .port = std.net.byteOrder.fromBigEndian(u16, sa.sin_port),
                        }};
                        try final_list.append(addr);
                    },
                    .AF_INET6 => {
                        const sa: *std.os.windows.ws2_32.sockaddr_in6 = @as(
                            *std.os.windows.ws2_32.sockaddr_in6,
                            @ptrCast(@alignCast(ai.addr orelse continue)),
                        );
                        const addr = std.Io.net.IpAddress{ .ip6 = std.Io.net.Ip6Address{
                            .bytes = sa.sin6_addr.u.Byte,
                            .port = std.net.byteOrder.fromBigEndian(u16, sa.sin6_port),
                            .flow = sa.sin6_flowinfo,
                            .interface = .{ .index = sa.sin6_scope_id },
                        }};
                        try final_list.append(addr);
                    },
                    else => continue,
                }
            }
        } else if (builtin.os.tag == .linux) {
            const io = std.Io.Threaded.io(std.Io.Threaded.global_single_threaded);
            try lookupHosts(&final_list, io, std.posix.AF.INET, port, incoming_name);
            try lookupHosts(&final_list, io, std.posix.AF.INET, port, incoming_name);

            if (final_list.items.len == 0) {
                const addrs_v4 = try fetchTrustedAddresses(allocator, io, name, .A);
                defer allocator.free(addrs_v4);
                for (addrs_v4) |addr| try final_list.append(addr);

                const addrs_v6 = try fetchTrustedAddresses(allocator, io, name, .AAAA);
                defer allocator.free(addrs_v6);
                for (addrs_v6) |addr| try final_list.append(addr);
            }
        } else @compileError("getAddressList not supported on this target");
    }

    if (final_list.items.len == 1) return AddressList.fromList(allocator, &final_list);
    const all_ip4 = for (final_list.items) |addr| {
        if (addr != .ip4) break false;
    } else true;
    if (all_ip4) return AddressList.fromList(allocator, &final_list);

    std.mem.sort(std.Io.net.IpAddress, final_list.items, {}, addrCmpLessThan);

    return AddressList.fromList(allocator, &final_list);
}

const Policy = struct {
    cidr: CidrRange,
    precedence: usize,
    label: usize,

    pub fn new(cidr: CidrRange, precedence: usize, label: usize) @This() {
        return .{ .cidr = cidr, .precedence = precedence, .label = label };
    }
};

const policy_table = [_]Policy{
    Policy.new(CidrRange.parse("::1/128") catch unreachable, 50, 0),
    Policy.new(CidrRange.parse("::/0") catch unreachable, 40, 1),
    Policy.new(.{ .version = .v6, .first_address = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 }, .prefix_len = 96 }, 35, 4),
    Policy.new(CidrRange.parse("2002::/16") catch unreachable, 30, 2),
    Policy.new(CidrRange.parse("2001::/32") catch unreachable, 5, 5),
    Policy.new(CidrRange.parse("fc00::/7") catch unreachable, 3, 13),
    Policy.new(CidrRange.parse("::/96") catch unreachable, 1, 3),
};
fn cmpGetPrecedence(addr: std.Io.net.IpAddress) usize {
    for (policy_table) |policy| {
        if (policy.cidr.contains(addr) catch unreachable) {
            return policy.precedence;
        }
    }
    return 40;
}

fn isMulticast(a: std.Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => false,
        .ip6 => |ip6| ip6.bytes[0] == 0xff,
    };
}

fn isLinklocal(a: std.Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => false,
        .ip6 => |ip6| ip6.bytes[0] == 0xfe and (ip6.bytes[1] & 0xc0) == 0x80,
    };
}

fn isLoopback(a: std.Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => false,
        .ip6 => |ip6| {
            const b = &ip6.bytes;
            return b[0] == 0 and b[1] == 0 and b[2] == 0 and
                b[12] == 0 and b[13] == 0 and b[14] == 0 and b[15] == 1;
        },
    };
}

fn isSitelocal(a: std.Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => false,
        .ip6 => |ip6| ip6.bytes[0] == 0xfe and (ip6.bytes[1] & 0xc0) == 0xc0,
    };
}

fn cmpGetScope(addr: std.Io.net.IpAddress) usize {
    if (isMulticast(addr)) {
        return switch (addr) {
            .ip4 => unreachable,
            .ip6 => |ip6| ip6.bytes[1] & 15,
        };
    } else if (isLinklocal(addr)) {
        return 2;
    } else if (isLoopback(addr)) {
        return 2;
    } else if (isSitelocal(addr)) {
        return 5;
    }
    return 14;
}

fn cmpAddresses(a: std.Io.net.IpAddress, b: std.Io.net.IpAddress) bool {
    const prec_a = cmpGetPrecedence(a);
    const prec_b = cmpGetPrecedence(b);

    if (prec_a != prec_b) {
        return if (prec_a > prec_b) false else true;
    }

    const scope_a = cmpGetScope(a);
    const scope_b = cmpGetScope(b);

    if (scope_a != scope_b) {
        return if (scope_a < scope_b) false else true;
    }

    return false;
}

fn addrCmpLessThan(context: void, b: std.Io.net.IpAddress, a: std.Io.net.IpAddress) bool {
    _ = context;
    return cmpAddresses(a, b);
}
