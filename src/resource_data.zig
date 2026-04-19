const std = @import("std");
const fmt = std.fmt;

const dns = @import("lib.zig");
const pkt = @import("packet.zig");
const Type = dns.ResourceType;

const logger = std.log.scoped(.dns_rdata);

pub const SOAData = struct {
    mname: ?dns.Name,
    rname: ?dns.Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};

pub const MXData = struct {
    preference: u16,
    exchange: ?dns.Name,
};

pub const SRVData = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: ?dns.Name,
};

fn maybeReadResourceName(
    wrapper: *dns.parserlib.WrapperReader,
    options: ResourceData.ParseOptions,
) !?dns.Name {
    return switch (options.name_provider) {
        .none => null,
        .raw => |allocator| try dns.Name.readFrom(wrapper, .{ .allocator = allocator }),
        .full => |name_pool| blk: {
            const name = try dns.Name.readFrom(
                wrapper,
                .{ .allocator = name_pool.allocator },
            );
            break :blk try name_pool.transmuteName(name.?);
        },
    };
}

/// Common representations of DNS' Resource Data.
pub const ResourceData = union(Type) {
    A: std.Io.net.Ip4Address,

    NS: ?dns.Name,
    MD: ?dns.Name,
    MF: ?dns.Name,
    CNAME: ?dns.Name,
    SOA: SOAData,

    MB: ?dns.Name,
    MG: ?dns.Name,
    MR: ?dns.Name,

    // ????
    NULL: void,

    // TODO WKS bit map
    WKS: struct {
        addr: u32,
        proto: u8,
        // how to define bit map? align(8)?
    },
    PTR: ?dns.Name,

    // TODO replace []const u8 by Name?
    HINFO: struct {
        cpu: []const u8,
        os: []const u8,
    },
    MINFO: struct {
        rmailbx: ?dns.Name,
        emailbx: ?dns.Name,
    },
    MX: MXData,
    TXT: ?[]const u8,
    AAAA: std.Io.net.Ip6Address,
    SRV: SRVData,
    OPT: void, // EDNS0 is not implemented

    const Self = @This();

    pub fn networkSize(self: Self) usize {
        return switch (self) {
            .A => 4,
            .AAAA => 16,
            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |name| name.size(),
            .TXT => |text| blk: {
                var len: usize = 0;
                len += @sizeOf(u16) * text.len;
                for (text) |string| {
                    len += string.len;
                }
                break :blk len;
            },

            else => @panic("TODO"),
        };
    }

    /// Format the RData into a human-readable form of it.
    ///
    /// For example, a resource data of type A would be
    /// formatted to its representing IPv4 address.
    pub fn format(self: Self, writer: anytype) std.Io.Writer.Error!void {
        switch (self) {
            .A => |addr| return writer.print("{d}.{d}.{d}.{d}:{d}", .{ addr.bytes[0], addr.bytes[1], addr.bytes[2], addr.bytes[3], addr.port }),
            .AAAA => |addr| return writer.print("{f}", .{addr}),

            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |name| return writer.print("{?f}", .{name}),

            .SOA => |soa| return writer.print("{?f} {?f} {} {} {} {} {}", .{
                soa.mname,
                soa.rname,
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum,
            }),

            .MX => |mx| return writer.print("{} {?f}", .{ mx.preference, mx.exchange }),
            .SRV => |srv| return writer.print("{} {} {} {?f}", .{
                srv.priority,
                srv.weight,
                srv.port,
                srv.target,
            }),

            .TXT => |text| return writer.print("{?s}", .{text}),
            else => return writer.print("TODO support {s}", .{@tagName(self)}),
        }
    }

    pub fn writeTo(self: Self, writer: *std.Io.Writer) !void {
        return switch (self) {
            .A => |addr| {
                try writer.writeInt(u32, @as(u32, @bitCast(addr.bytes)), .big);
            },
            .AAAA => |addr| {
                _ = try writer.write(&addr.bytes);
            },

            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |name| try name.?.writeTo(writer),

            .SOA => |soa_data| {
                try soa_data.mname.?.writeTo(writer);
                try soa_data.rname.?.writeTo(writer);

                try writer.writeInt(u32, soa_data.serial, .big);
                try writer.writeInt(u32, soa_data.refresh, .big);
                try writer.writeInt(u32, soa_data.retry, .big);
                try writer.writeInt(u32, soa_data.expire, .big);
                try writer.writeInt(u32, soa_data.minimum, .big);

                // break :blk mname_size + rname_size + (5 * @sizeOf(u32));
            },

            .MX => |mxdata| {
                try writer.writeInt(u16, mxdata.preference, .big);
                try mxdata.exchange.?.writeTo(writer);
            },

            .SRV => |srv| {
                try writer.writeInt(u16, srv.priority, .big);
                try writer.writeInt(u16, srv.weight, .big);
                try writer.writeInt(u16, srv.port, .big);

                try srv.target.?.writeTo(writer);
            },

            // TODO TXT

            else => @panic("not implemented"),
        };
    }

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        switch (self) {
            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |maybe_name| if (maybe_name) |name| name.deinit(allocator),
            .SOA => |soa_data| {
                if (soa_data.mname) |name| name.deinit(allocator);
                if (soa_data.rname) |name| name.deinit(allocator);
            },
            .MX => |mxdata| if (mxdata.exchange) |name| name.deinit(allocator),
            .SRV => |srv| if (srv.target) |name| name.deinit(allocator),
            .TXT => |maybe_data| if (maybe_data) |data| allocator.free(data),
            else => {},
        }
    }

    pub const Opaque = struct {
        data: []const u8,
        current_byte_count: usize,
    };

    pub const NameProvider = union(enum) {
        none: void,
        raw: std.mem.Allocator,
        full: *dns.NamePool,
    };

    pub const ParseOptions = struct {
        name_provider: NameProvider = NameProvider.none,
        allocator: ?std.mem.Allocator = null,
    };

    /// Deserialize a given opaque resource data.
    ///
    /// Call deinit() with the same allocator.
    pub fn fromOpaque(
        resource_type: dns.ResourceType,
        opaque_resource_data: Opaque,
        options: ParseOptions,
    ) !ResourceData {
        var underlying_reader = std.Io.Reader.fixed(opaque_resource_data.data);

        // important to keep track of that rdata's position in the packet
        // as rdata could point to other rdata.
        var wrapper_reader = dns.parserlib.WrapperReader.init(
            &underlying_reader,
            opaque_resource_data.current_byte_count,
        );
        var reader = wrapper_reader.reader;

        return switch (resource_type) {
            .A => blk: {
                var ip4addr: [4]u8 = undefined;
                try reader.readSliceAll(&ip4addr);
                break :blk ResourceData{
                    .A = .{ .bytes = ip4addr, .port = 0 },
                };
            },
            .AAAA => blk: {
                var ip6_addr: [16]u8 = undefined;
                try reader.readSliceAll(&ip6_addr);
                break :blk ResourceData{
                    .AAAA = .{ .bytes = ip6_addr, .port = 0, .flow = 0, .interface = .none },
                };
            },

            .NS => ResourceData{ .NS = try maybeReadResourceName(&wrapper_reader, options) },
            .CNAME => ResourceData{ .CNAME = try maybeReadResourceName(&wrapper_reader, options) },
            .PTR => ResourceData{ .PTR = try maybeReadResourceName(&wrapper_reader, options) },
            .MD => ResourceData{ .MD = try maybeReadResourceName(&wrapper_reader, options) },
            .MF => ResourceData{ .MF = try maybeReadResourceName(&wrapper_reader, options) },

            .MX => blk: {
                break :blk ResourceData{
                    .MX = MXData{
                        .preference = try reader.takeInt(u16, .big),
                        .exchange = try maybeReadResourceName(&wrapper_reader, options),
                    },
                };
            },

            .SOA => blk: {
                const mname = try maybeReadResourceName(&wrapper_reader, options);
                const rname = try maybeReadResourceName(&wrapper_reader, options);
                const serial = try reader.takeInt(u32, .big);
                const refresh = try reader.takeInt(u32, .big);
                const retry = try reader.takeInt(u32, .big);
                const expire = try reader.takeInt(u32, .big);
                const minimum = try reader.takeInt(u32, .big);

                break :blk ResourceData{
                    .SOA = SOAData{
                        .mname = mname,
                        .rname = rname,
                        .serial = serial,
                        .refresh = refresh,
                        .retry = retry,
                        .expire = expire,
                        .minimum = minimum,
                    },
                };
            },
            .SRV => blk: {
                const priority = try reader.takeInt(u16, .big);
                const weight = try reader.takeInt(u16, .big);
                const port = try reader.takeInt(u16, .big);
                const target = try maybeReadResourceName(&wrapper_reader, options);
                break :blk ResourceData{
                    .SRV = .{
                        .priority = priority,
                        .weight = weight,
                        .port = port,
                        .target = target,
                    },
                };
            },
            .TXT => blk: {
                const length = try reader.takeInt(u8, .big);
                if (length > 256) return error.Overflow;

                if (options.allocator) |allocator| {
                    const text = try allocator.alloc(u8, length);
                    try reader.readSliceAll(text);
                    break :blk ResourceData{ .TXT = text };
                } else {
                    reader.toss(length);
                    break :blk ResourceData{ .TXT = null };
                }
            },

            else => {
                logger.warn("unexpected rdata: {}\n", .{resource_type});
                return error.UnknownResourceType;
            },
        };
    }
};
