const std = @import("std");
const net = std.Io.net;
const mem = std.mem;
const fmt = std.fmt;
const posix = std.posix;

pub const IpVersion = enum {
    v4,
    v6,
};

pub const CidrParseError = error{
    InvalidFormat,
    InvalidAddress,
    InvalidPrefixLength,
    AddressesExhausted,
};

pub const CidrRange = struct {
    version: IpVersion,
    first_address: [16]u8,
    prefix_len: u8,

    const Self = @This();

    pub fn parse(cidr: []const u8) !CidrRange {
        var it = std.mem.splitSequence(u8, cidr, "/");
        const addr_str = it.next() orelse return error.InvalidFormat;
        const prefix_str = it.next() orelse return error.InvalidFormat;
        const must_be_null = it.next();
        if (must_be_null != null) return error.InvalidFormat;

        const prefix_len = std.fmt.parseInt(u8, prefix_str, 10) catch return error.InvalidPrefixLength;

        const maybe_ipv4 = net.IpAddress.parseIp4(addr_str, 0) catch |err| switch (err) {
            else => null,
        };
        if (maybe_ipv4) |ipv4| {
            if (prefix_len > 32) return CidrParseError.InvalidPrefixLength;

            var result = CidrRange{
                .version = .v4,
                .first_address = [_]u8{0} ** 16,
                .prefix_len = prefix_len,
            };

            if (ipv4 == .ip4) {
                const bytes = ipv4.ip4.bytes;
                result.first_address[10] = 0xff;
                result.first_address[11] = 0xff;
                result.first_address[12] = bytes[0];
                result.first_address[13] = bytes[1];
                result.first_address[14] = bytes[2];
                result.first_address[15] = bytes[3];
            }

            const host_bits = 32 - prefix_len;
            if (prefix_len == 0) {
                std.mem.writeInt(u32, result.first_address[12..16], 0, .big);
            } else if (host_bits > 0) {
                const mask = ~(@as(u32, (@as(u32, 1) << @as(u5, @intCast(host_bits))) - 1));
                const addr = std.mem.readInt(u32, result.first_address[12..16], .big);
                const masked = addr & mask;
                std.mem.writeInt(u32, result.first_address[12..16], masked, .big);
            }

            return result;
        }

        const maybe_ipv6: ?net.IpAddress = net.IpAddress.parseIp6(addr_str, 0) catch |err| switch (err) {
            else => null,
        };
        if (maybe_ipv6) |ipv6| {
            if (prefix_len > 128) return CidrParseError.InvalidPrefixLength;

            var result = CidrRange{
                .version = .v6,
                .first_address = ipv6.ip6.bytes,
                .prefix_len = prefix_len,
            };

            const full_bytes = prefix_len / 8;
            const remaining_bits = prefix_len % 8;

            if (remaining_bits > 0) {
                const mask = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
                result.first_address[full_bytes] &= mask;
            }

            for (result.first_address[full_bytes + @intFromBool(remaining_bits > 0) ..]) |*byte| {
                byte.* = 0;
            }

            return result;
        }

        return CidrParseError.InvalidAddress;
    }

    pub fn contains(self: Self, addr: net.IpAddress) !bool {
        var data: [16]u8 = switch (addr) {
            .ip4 => |ip4| blk: {
                var result: [16]u8 = [_]u8{0} ** 16;
                result[10] = 0xff;
                result[11] = 0xff;
                @memcpy(result[12..16], &ip4.bytes);
                break :blk result;
            },
            .ip6 => |ip6| blk: {
                break :blk ip6.bytes;
            },
        };

        const full_bytes = self.prefix_len / 8;
        const remaining_bits = self.prefix_len % 8;

        const start_byte: usize = if (self.version == .v4) 12 else 0;

        for (self.first_address[start_byte .. start_byte + full_bytes], data[start_byte .. start_byte + full_bytes], 0..) |a, b, i| {
            _ = i;
            if (a != b) {
                return false;
            }
        }

        if (remaining_bits > 0) {
            const mask = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
            const byte_pos = start_byte + full_bytes;
            if ((self.first_address[byte_pos] & mask) != (data[byte_pos] & mask)) {
                return false;
            }
        }

        return true;
    }

    pub fn format(self: Self, writer: anytype) std.Io.Writer.Error!void {
        switch (self.version) {
            .v4 => {
                try writer.print("{d}.{d}.{d}.{d}/{d}", .{
                    self.first_address[12],
                    self.first_address[13],
                    self.first_address[14],
                    self.first_address[15],
                    self.prefix_len,
                });
            },
            .v6 => {
                const addr = net.Ip6Address{
                    .bytes = self.first_address,
                    .port = 0,
                    .flow = 0,
                    .interface = .none,
                };
                try writer.print("{f}/{d}", .{ addr, self.prefix_len });
            },
        }
    }
};

const testing = std.testing;

test "IPv4 basic parsing" {
    const cases = .{
        .{
            "192.168.1.0/24",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 0 },
            24,
            IpVersion.v4,
        },
        .{
            "10.0.0.0/8",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 0 },
            8,
            IpVersion.v4,
        },
        .{
            "172.16.0.0/12",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 172, 16, 0, 0 },
            12,
            IpVersion.v4,
        },
    };

    inline for (cases) |case| {
        const cidr = try CidrRange.parse(case[0]);
        try testing.expectEqual(case[1], cidr.first_address);
        try testing.expectEqual(case[2], cidr.prefix_len);
        try testing.expectEqual(case[3], cidr.version);
    }
}

test "IPv6 basic parsing" {
    const cases = .{
        .{
            "2001:db8::/32",
            [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            32,
            IpVersion.v6,
        },
        .{
            "fe80::/10",
            [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            10,
            IpVersion.v6,
        },
        .{
            "::1/128",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            128,
            IpVersion.v6,
        },
    };

    inline for (cases) |case| {
        const cidr = try CidrRange.parse(case[0]);
        try testing.expectEqual(case[1], cidr.first_address);
        try testing.expectEqual(case[2], cidr.prefix_len);
        try testing.expectEqual(case[3], cidr.version);
    }
}

test "IPv6 compressed notation" {
    const cases = .{
        .{
            "2001:db8:0:0:0:0:0:0/32",
            "2001:db8::/32",
        },
        .{
            "2001:0db8:0000:0000:0000:0000:0000:0000/32",
            "2001:db8::/32",
        },
        .{
            "fe80:0:0:0:0:0:0:0/10",
            "fe80::/10",
        },
    };

    inline for (cases) |case| {
        const cidr1 = try CidrRange.parse(case[0]);
        const cidr2 = try CidrRange.parse(case[1]);
        try testing.expectEqual(cidr1.first_address, cidr2.first_address);
        try testing.expectEqual(cidr1.prefix_len, cidr2.prefix_len);
        try testing.expectEqual(cidr1.version, cidr2.version);
    }
}

test "Invalid CIDR formats" {
    const cases = .{
        "192.168.1.0",
        "192.168.1.0/",
        "192.168.1.0/33",
        "2001:db8::/129",
        "192.168.1.256/24",
        "2001:db8::xyz/32",
        "not.an.ip/24",
        "/24",
        "192.168.1.0/-1",
        "192.168.1.0/a",
    };

    inline for (cases) |case| {
        if (CidrRange.parse(case)) |_| {
            try testing.expect(false);
        } else |err| {
            switch (err) {
                error.InvalidFormat,
                error.InvalidAddress,
                error.InvalidPrefixLength,
                => {},
                else => try testing.expect(false),
            }
        }
    }
}

test "Edge cases" {
    const cases = .{
        .{
            "0.0.0.0/0",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 },
            0,
            IpVersion.v4,
        },
        .{
            "::/0",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            0,
            IpVersion.v6,
        },
        .{
            "255.255.255.255/32",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 255, 255, 255, 255 },
            32,
            IpVersion.v4,
        },
        .{
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
            [16]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            128,
            IpVersion.v6,
        },
    };

    inline for (cases) |case| {
        const cidr = try CidrRange.parse(case[0]);
        try testing.expectEqual(case[1], cidr.first_address);
        try testing.expectEqual(case[2], cidr.prefix_len);
        try testing.expectEqual(case[3], cidr.version);
    }
}

test "Non-zero host bits" {
    const cases = .{
        .{
            "192.168.1.1/24",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 0 },
        },
        .{
            "2001:db8::1/32",
            [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        },
    };

    inline for (cases) |case| {
        const cidr = try CidrRange.parse(case[0]);
        try testing.expectEqual(case[1], cidr.first_address);
    }
}

test "Boundary prefix lengths" {
    const ipv4_cases = .{
        "192.168.1.0/0",
        "192.168.1.0/1",
        "192.168.1.0/31",
        "192.168.1.0/32",
    };

    const ipv6_cases = .{
        "2001:db8::/0",
        "2001:db8::/1",
        "2001:db8::/127",
        "2001:db8::/128",
    };

    inline for (ipv4_cases) |case| {
        const cidr = try CidrRange.parse(case);
        try testing.expect(cidr.version == .v4);
    }

    inline for (ipv6_cases) |case| {
        const cidr = try CidrRange.parse(case);
        try testing.expect(cidr.version == .v6);
    }
}

fn ip4ToBytes(strAddr: []const u8, port: u16) [16]u8 {
    const ipv4 = net.IpAddress.parseIp4(strAddr, port) catch unreachable;
    const bytes = ipv4.ip4.bytes;

    var result: [16]u8 = [_]u8{0} ** 16;
    result[10] = 0xff;
    result[11] = 0xff;
    @memcpy(result[12..16], &bytes);
    return result;
}

test "IPv4 contains basic tests" {
    const cidr = try CidrRange.parse("192.168.1.0/24");

    try testing.expect(try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 0 }, .port = 0 }}));
    try testing.expect(try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 0 }}));
    try testing.expect(try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 255 }, .port = 0 }}));

    try testing.expect(!try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 0, 255 }, .port = 0 }}));
    try testing.expect(!try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 2, 0 }, .port = 0 }}));
    try testing.expect(!try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 169, 1, 1 }, .port = 0 }}));
}

test "IPv6 contains basic tests" {
    const cidr = try CidrRange.parse("2001:db8::/64");

    try testing.expect(try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
    try testing.expect(try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0, .flow = 0, .interface = .none }}));
    try testing.expect(try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }, .port = 0, .flow = 0, .interface = .none }}));

    try testing.expect(!try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
    try testing.expect(!try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
    try testing.expect(!try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x02, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
}

test "contains edge prefix lengths" {
    {
        const cidr_v4 = try CidrRange.parse("0.0.0.0/0");
        try testing.expect(try cidr_v4.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 }}));
        try testing.expect(try cidr_v4.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 255, 255, 255, 255 }, .port = 0 }}));
        try testing.expect(try cidr_v4.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 0 }}));
    }

    {
        const cidr_v6 = try CidrRange.parse("::/0");
        try testing.expect(try cidr_v6.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0 } ** 16, .port = 0, .flow = 0, .interface = .none }}));
        try testing.expect(try cidr_v6.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0xff } ** 16, .port = 0, .flow = 0, .interface = .none }}));
        try testing.expect(try cidr_v6.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0, .flow = 0, .interface = .none }}));
    }

    {
        const cidr_v4 = try CidrRange.parse("192.168.1.1/32");
        try testing.expect(try cidr_v4.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 0 }}));
        try testing.expect(!try cidr_v4.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 2 }, .port = 0 }}));
    }

    {
        const cidr_v6 = try CidrRange.parse("2001:db8::1/128");
        try testing.expect(try cidr_v6.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0, .flow = 0, .interface = .none }}));
        try testing.expect(!try cidr_v6.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, .port = 0, .flow = 0, .interface = .none }}));
    }
}

test "contains non-aligned prefix lengths" {
    {
        const cidr = try CidrRange.parse("192.168.0.0/23");
        try testing.expect(try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 0, 1 }, .port = 0 }}));
        try testing.expect(try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 0 }}));
        try testing.expect(!try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 2, 1 }, .port = 0 }}));
    }

    {
        const cidr = try CidrRange.parse("2001:db8::/63");
        try testing.expect(try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
        try testing.expect(try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
        try testing.expect(!try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
    }
}

test "contains byte boundary edge cases" {
    {
        const cidr = try CidrRange.parse("192.168.0.0/16");
        try testing.expect(try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 0, 0 }, .port = 0 }}));
        try testing.expect(try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 255, 255 }, .port = 0 }}));
        try testing.expect(!try cidr.contains(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 169, 0, 0 }, .port = 0 }}));
    }

    {
        const cidr = try CidrRange.parse("2001:db8:1100::/48");
        try testing.expect(try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0x11, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
        try testing.expect(try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0x11, 0x00, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
        try testing.expect(!try cidr.contains(net.IpAddress{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0x11, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0, .flow = 0, .interface = .none }}));
    }
}
