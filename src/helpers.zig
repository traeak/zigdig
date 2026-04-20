const std = @import("std");
const builtin = @import("builtin");
const dns = @import("lib.zig");

const CidrRange = @import("cidr.zig").CidrRange;

fn printList(
    name_pool: *dns.NamePool,
    writer: anytype,
    resource_list: []dns.Resource,
) !void {
    // TODO the formatting here is not good...
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
            else => {}, // names are owned by given NamePool
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

/// Print a packet in the format of a "zone file".
///
/// This will deserialize resourcedata in the resource sections, so
/// a NamePool instance is required.
///
/// This helper method will NOT free the memory created by name allocation,
/// you should do this manually in a defer block calling NamePool.deinitWithNames.
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
    var seed_buf: [8]u8 = undefined;
    io.random(&seed_buf);
    const seed = std.mem.readInt(u64, &seed_buf, .little);
    var r = std.Random.DefaultPrng.init(seed);
    return r.random().int(u16);
}

/// High level wrapper around a single UDP connection to send and receive
/// DNS packets.
pub const DNSConnection = struct {
    address: std.Io.net.IpAddress,
    socket: std.Io.net.Socket,
    io: std.Io,

    const Self = @This();

    pub fn close(self: Self) void {
        self.socket.close(self.io);
    }

    pub fn sendPacket(self: Self, packet: dns.Packet) !void {
        var buffer: [1024]u8 = undefined;

        var writer = std.Io.Writer.fixed(&buffer);
        try packet.writeTo(&writer);

        const result = buffer[0..writer.end];
        try self.socket.send(self.io, &self.address, result);
    }

    /// Deserializes and allocates an *entire* DNS packet.
    pub fn receiveFullPacket(
        self: Self,
        packet_allocator: std.mem.Allocator,
        /// Maximum size for the incoming UDP datagram
        comptime max_incoming_message_size: usize,
        options: ParseFullPacketOptions,
    ) !dns.IncomingPacket {
        var packet_buffer: [max_incoming_message_size]u8 = undefined;
        const msg = try self.socket.receive(self.io, &packet_buffer);
        const read_bytes = msg.data.len;
        const packet_bytes = msg.data;
        logger.debug("read {d} bytes", .{read_bytes});

        var stream = std.Io.Reader.fixed(packet_bytes);
        return parseFullPacket(&stream, packet_allocator, options);
    }
};

pub const ParseFullPacketOptions = struct {
    /// Use this NamePool to let deserialization of names outlive the call
    /// to parseFullPacket.
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

    var questions = std.ArrayList(dns.Question).empty;
    defer questions.deinit(allocator);

    var answers = std.ArrayList(dns.Resource).empty;
    defer answers.deinit(allocator);

    var nameservers = std.ArrayList(dns.Resource).empty;
    defer nameservers.deinit(allocator);

    var additionals = std.ArrayList(dns.Resource).empty;
    defer additionals.deinit(allocator);

    while (try parser.next()) |part| {
        switch (part) {
            .header => |header| packet.header = header,
            .question => |question_with_raw_names| {
                const question =
                    try name_pool.transmuteResource(question_with_raw_names);
                try questions.append(allocator, question);
            },
            .end_question => packet.questions = try questions.toOwnedSlice(allocator),
            .answer, .nameserver, .additional => |raw_resource| {
                const resource = try name_pool.transmuteResource(raw_resource);
                try (switch (part) {
                    .answer => &answers,
                    .nameserver => &nameservers,
                    .additional => &additionals,
                    else => unreachable,
                }).append(allocator, resource);
            },
            .end_answer => packet.answers = try answers.toOwnedSlice(allocator),
            .end_nameserver => packet.nameservers = try nameservers.toOwnedSlice(allocator),
            .end_additional => packet.additionals = try additionals.toOwnedSlice(allocator),
            .answer_rdata, .nameserver_rdata, .additional_rdata => unreachable,
        }
    }

    return incoming_packet;
}

const logger = std.log.scoped(.dns_helpers);

/// Open a socket to the DNS resolver specified in input parameter
pub fn connectToResolver(io: std.Io, address: []const u8, port: ?u16) !DNSConnection {
    const addr = try std.Io.net.IpAddress.parse(address, port orelse 53);

    // Bind to any local address to create a UDP socket
    const local_addr: std.Io.net.IpAddress = switch (addr) {
        .ip4 => .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .ip6 => .{ .ip6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0 } },
    };

    const socket = try std.Io.net.IpAddress.bind(&local_addr, io, .{ .mode = .dgram });

    return DNSConnection{
        .address = addr,
        .socket = socket,
        .io = io,
    };
}

/// Open a socket to a random DNS resolver declared in the systems'
/// "/etc/resolv.conf" file.
pub fn connectToSystemResolver(io: std.Io) !DNSConnection {
    var out_buffer: [256]u8 = undefined;

    if (builtin.os.tag != .linux and builtin.os.tag != .macos)
        @compileError("connectToSystemResolver not supported on this target");

    const nameserver_address_string = (try randomNameserver(io, &out_buffer)).?;

    return connectToResolver(io, nameserver_address_string, null);
}

pub fn randomNameserver(io: std.Io, output_buffer: []u8) !?[]const u8 {
    var file = try std.Io.Dir.cwd().openFile(io, "/etc/resolv.conf", .{ .mode = .read_only });
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

    var seed_buf: [8]u8 = undefined;
    io.random(&seed_buf);
    const seed = std.mem.readInt(u64, &seed_buf, .little);
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

    fn fromList(allocator: std.mem.Allocator, addrs: *std.ArrayList(std.Io.net.IpAddress)) !AddressList {
        return AddressList{ .allocator = allocator, .addrs = try addrs.toOwnedSlice(allocator) };
    }
};

const ReceiveTrustedAddressesOptions = struct {
    max_incoming_message_size: usize = 4096,
    requested_packet_header: ?dns.Header = null,
};

/// This is an optimized deserializer that is only interested in A and AAAA
/// answers, returning a list of std.Io.net.IpAddress.
pub fn receiveTrustedAddresses(
    allocator: std.mem.Allocator,
    connection: *const DNSConnection,
    /// Options to receive message and deserialize it
    comptime options: ReceiveTrustedAddressesOptions,
) ![]std.Io.net.IpAddress {
    var packet_buffer: [options.max_incoming_message_size]u8 = undefined;
    const msg = try connection.socket.receive(connection.io, &packet_buffer);
    const read_bytes = msg.data.len;
    const packet_bytes = msg.data;
    logger.debug("read {d} bytes", .{read_bytes});

    var reader = std.Io.Reader.fixed(packet_bytes);

    var parser = dns.Parser.init(&reader, .{});

    var addrs = std.ArrayList(std.Io.net.IpAddress).empty;
    errdefer addrs.deinit(allocator);

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
                const maybe_addr: ?std.Io.net.IpAddress = switch (current_resource.?.typ) {
                    .A => blk: {
                        var ip4addr: [4]u8 = undefined;
                        _ = try reader.readSliceAll(&ip4addr);
                        break :blk .{ .ip4 = .{ .bytes = ip4addr, .port = 0 } };
                    },
                    .AAAA => blk: {
                        var ip6_addr: [16]u8 = undefined;
                        _ = try reader.readSliceAll(&ip6_addr);
                        break :blk .{ .ip6 = .{ .bytes = ip6_addr, .port = 0 } };
                    },
                    else => blk: {
                        reader.toss(rdata.size);
                        break :blk null;
                    },
                };

                if (maybe_addr) |addr| try addrs.append(allocator, addr);
            },
            else => {},
        }
    }

    return try addrs.toOwnedSlice(allocator);
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

    const conn = try dns.helpers.connectToSystemResolver(io);
    defer conn.close();

    logger.debug("selected nameserver: {f}", .{conn.address});
    try conn.sendPacket(packet);
    return try receiveTrustedAddresses(allocator, &conn, .{});
}

// implementation taken from std.net address resolution
fn lookupHosts(allocator: std.mem.Allocator, io: std.Io, addrs: *std.ArrayList(std.Io.net.IpAddress), port: u16, name: []const u8) !void {
    const file = std.Io.Dir.openFileAbsolute(io, "/etc/hosts", .{}) catch |err| switch (err) {
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
        error.StreamTooLong => {
            return error.StreamTooLong;
        },
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

        const addr = std.Io.net.IpAddress.parse(ip_text, port) catch continue;
        try addrs.append(allocator, addr);
    }
}

/// A getAddressList-like function that:
///  - gets a nameserver from resolv.conf
///  - starts a DNSConnection
///  - extracts A/AAAA records and turns them into std.Io.net.IpAddress
///
/// The only memory allocated here is for the list that holds IpAddress.
pub fn getAddressList(io: std.Io, incoming_name: []const u8, port: u16, allocator: std.mem.Allocator) !AddressList {
    var name_buffer: [128][]const u8 = undefined;
    const name = try dns.Name.fromString(incoming_name, &name_buffer);

    var final_list = std.ArrayList(std.Io.net.IpAddress).empty;
    defer final_list.deinit(allocator);

    const last_label = name.full.labels[name.full.labels.len - 1];

    // see if we can short-circuit on parsing the name as addr
    if (std.Io.net.IpAddress.parse(incoming_name, port) catch null) |addr| {
        try final_list.append(allocator, addr);
    } else if (std.mem.eql(u8, last_label, "localhost")) {
        // RFC 6761 Section 6.3.3
        try final_list.append(allocator, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } });
        try final_list.append(allocator, .{ .ip6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = port } });
    } else {
        if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
            try lookupHosts(allocator, io, &final_list, port, incoming_name);

            if (final_list.items.len == 0) {
                // if that didn't work, go to dns server
                const addrs_v4 = try fetchTrustedAddresses(allocator, io, name, .A);
                defer allocator.free(addrs_v4);
                for (addrs_v4) |addr| try final_list.append(allocator, addr);

                const addrs_v6 = try fetchTrustedAddresses(allocator, io, name, .AAAA);
                defer allocator.free(addrs_v6);
                for (addrs_v6) |addr| try final_list.append(allocator, addr);
            }
        } else @compileError("getAddressList not supported on this target");
    }

    // RFC 6761 is not run if everything is v4 or only 1 address returned
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

// Default policy table from RFC 6724 Section 2.1
const policy_table = [_]Policy{
    Policy.new(CidrRange.parse("::1/128") catch unreachable, 50, 0), // Loopback
    Policy.new(CidrRange.parse("::/0") catch unreachable, 40, 1), // Default
    Policy.new(CidrRange.parse("0:0:0:0:0:ffff:0:0/96") catch unreachable, 35, 4), // IPv4-mapped
    Policy.new(CidrRange.parse("2002::/16") catch unreachable, 30, 2), // 6to4
    Policy.new(CidrRange.parse("2001::/32") catch unreachable, 5, 5), // Teredo
    Policy.new(CidrRange.parse("fc00::/7") catch unreachable, 3, 13), // ULA
    Policy.new(CidrRange.parse("::/96") catch unreachable, 1, 3), // IPv4-compatible
};

fn cmpGetPrecedence(addr: std.Io.net.IpAddress) usize {
    for (policy_table) |policy| {
        if (policy.cidr.contains(addr) catch unreachable) {
            return policy.precedence;
        }
    }
    return 40; // Default precedence if no match
}

fn getIp6Bytes(addr: std.Io.net.IpAddress) [16]u8 {
    return switch (addr) {
        .ip4 => |ip4| blk: {
            var result: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };
            result[12] = ip4.bytes[0];
            result[13] = ip4.bytes[1];
            result[14] = ip4.bytes[2];
            result[15] = ip4.bytes[3];
            break :blk result;
        },
        .ip6 => |ip6| ip6.bytes,
    };
}

fn isMulticast(a: std.Io.net.IpAddress) bool {
    const bytes = getIp6Bytes(a);
    return bytes[0] == 0xff;
}

fn isLinklocal(a: std.Io.net.IpAddress) bool {
    const bytes = getIp6Bytes(a);
    return bytes[0] == 0xfe and (bytes[1] & 0xc0) == 0x80;
}

fn isLoopback(a: std.Io.net.IpAddress) bool {
    const bytes = getIp6Bytes(a);
    return bytes[0] == 0 and bytes[1] == 0 and
        bytes[2] == 0 and
        bytes[12] == 0 and bytes[13] == 0 and
        bytes[14] == 0 and bytes[15] == 1;
}

fn isSitelocal(a: std.Io.net.IpAddress) bool {
    const bytes = getIp6Bytes(a);
    return bytes[0] == 0xfe and (bytes[1] & 0xc0) == 0xc0;
}

fn cmpGetScope(addr: std.Io.net.IpAddress) usize {
    const bytes = getIp6Bytes(addr);
    if (isMulticast(addr)) {
        return bytes[1] & 15;
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
    // RFC 6761. Rules 3, 4, and 7 are omitted.

    // Rule 6: Prefer higher precedence
    const prec_a = cmpGetPrecedence(a);
    const prec_b = cmpGetPrecedence(b);

    if (prec_a != prec_b) {
        return if (prec_a > prec_b) false else true;
    }

    const scope_a = cmpGetScope(a);
    const scope_b = cmpGetScope(b);

    // Rule 8: Prefer smaller scope
    if (scope_a != scope_b) {
        return if (scope_a < scope_b) false else true;
    }

    // Rule 10: Otherwise, leave order unchanged
    return false;
}

fn addrCmpLessThan(context: void, b: std.Io.net.IpAddress, a: std.Io.net.IpAddress) bool {
    _ = context;
    return cmpAddresses(a, b);
}
