const std = @import("std");
const dns = @import("lib.zig");

const Name = dns.Name;
const ResourceType = dns.ResourceType;
const ResourceClass = dns.ResourceClass;

const logger = std.log.scoped(.dns_packet);

/// Represents the response code of the packet.
///
/// RCODE, in https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const ResponseCode = enum(u4) {
    NoError = 0,

    /// Format error - The name server was unable to interpret the query.
    FormatError = 1,

    /// Server failure - The name server was unable to process this query
    /// due to a problem with the name server.
    ServerFailure = 2,

    /// Name Error - Meaningful only for responses from an authoritative name
    /// server, this code signifies that the domain name referenced in
    /// the query does not exist.
    NameError = 3,

    /// Not Implemented - The name server does not support the requested
    /// kind of query.
    NotImplemented = 4,

    /// Refused - The name server refuses to perform the specified
    /// operation for policy reasons.  For example, a name server may not
    /// wish to provide the information to the particular requester,
    /// or a name server may not wish to perform a particular operation
    /// (e.g., zone transfer) for particular data.
    Refused = 5,
};

/// OPCODE from https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
///
/// This value is set by the originator of a query and copied into the response.
pub const OpCode = enum(u4) {
    /// a standard query (QUERY)
    Query = 0,
    /// an inverse query (IQUERY)
    InverseQuery = 1,
    /// a server status request (STATUS)
    ServerStatusRequest = 2,

    // rest is unused as per RFC1035
};

const bitWriter = struct {
    buffer: u8 = 0,
    bit_count: u3 = 0,
    writer: *std.Io.Writer,

    const Self = @This();

    fn writeBits(self: *Self, value: anytype, comptime bit_count: u8) !void {
        // value must fit in bit_count bits
        var bits_remaining: u8 = bit_count;
        const v: u64 = @intCast(value);

        while (bits_remaining > 0) {
            const space = 8 - @as(u8, self.bit_count);
            const n = @min(space, bits_remaining);

            // grab the top `n` bits from what's remaining
            const shift: u6 = @intCast(bits_remaining - n);
            const chunk: u8 = @intCast((v >> shift) & ((@as(u64, 1) << @intCast(n)) - 1));

            self.buffer |= chunk << @intCast(space - n);
            self.bit_count += @intCast(n);
            bits_remaining -= n;

            if (self.bit_count == 8) {
                try self.writer.writeByte(self.buffer);
                self.buffer = 0;
                self.bit_count = 0;
            }
        }
    }

    fn flushBits(self: *Self) !void {
        if (self.bit_count > 0) {
            try self.writer.writeByte(self.buffer);
            self.buffer = 0;
            self.bit_count = 0;
        }
    }
};

/// Describes the header of a DNS packet.
///
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const Header = packed struct {
    /// The ID of the packet. Replies to a packet MUST have the same ID.
    id: u16 = 0,

    /// Query/Response flag
    /// Defines if this is a response packet or not.
    is_response: bool = false,

    /// specifies kind of query in this message.
    opcode: OpCode = .Query,

    /// Authoritative Answer flag
    /// Only valid in response packets. Specifies if the server
    /// replying is an authority for the domain name.
    aa_flag: bool = false,

    /// TC flag - TrunCation.
    /// If the packet was truncated.
    truncated: bool = false,

    /// RD flag - Recursion Desired.
    /// Must be copied to a response packet. If set, the server
    /// handling the request can pursue the query recursively.
    wanted_recursion: bool = false,

    /// RA flag - Recursion Available
    /// Whether recursive query support is available on the server.
    recursion_available: bool = false,

    /// DO NOT USE. RFC1035 has not assigned anything to the Z bits
    z: u3 = 0,

    /// Response code.
    response_code: ResponseCode = .NoError,

    /// Amount of questions in the packet.
    question_length: u16 = 0,

    /// Amount of answers in the packet.
    answer_length: u16 = 0,

    /// Amount of nameservers in the packet.
    nameserver_length: u16 = 0,

    /// Amount of additional records in the packet.
    additional_length: u16 = 0,

    const Self = @This();

    /// Read a header from its network representation in a stream.
    pub fn readFrom(reader: *std.Io.Reader) !Self {
        var self = try reader.takeStruct(Self, .big);
        self.sanityCheck();
        return self;
    }

    /// Write the network representation of a header to the given writer.
    pub fn writeTo(self: Self, writer: *std.Io.Writer) !void {
        self.sanityCheck();
        return try writer.writeStruct(self, .big);
    }

    fn sanityCheck(_: Self) void {
        // just validate i'm using the correct types
        const fields = @typeInfo(Self).@"struct".fields;
        inline for (fields) |field| {
            switch (field.type) {
                bool => {},
                u3 => {},
                u4 => {},
                OpCode, ResponseCode => {},
                u16 => {},
                else => @compileError(
                    "unsupported type on header " ++ @typeName(field.type),
                ),
            }
        }

        // and that struct is 12 bytes
        if (@bitSizeOf(Self) / 8 != 12) @compileError("dns.Header is not 12 bytes");
    }
};

/// Represents a DNS question.
///
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
pub const Question = struct {
    name: ?dns.Name,
    typ: ResourceType,
    class: ResourceClass = .IN,

    const Self = @This();

    pub fn readFrom(reader: *std.Io.Reader, options: dns.ParserOptions) !Self {
        logger.debug(
            "reading question at {d} bytes",
            .{reader.seek},
        );

        const name = try Name.readFrom(reader, options);
        const qtype = try reader.takeEnum(ResourceType, .big);
        const qclass = try ResourceClass.readFrom(reader);

        return Self{
            .name = name,
            .typ = qtype,
            .class = qclass,
        };
    }
};

/// DNS resource
///
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
pub const Resource = struct {
    name: ?dns.Name,
    typ: ResourceType,
    class: ResourceClass,

    ttl: i32,

    /// Opaque Resource Data. This holds the bytes representing the RDATA
    /// section of the resource, with some metadata for pointer resolution.
    ///
    /// To parse this section, use dns.ResourceData.fromOpaque
    opaque_rdata: ?dns.ResourceData.Opaque,

    const Self = @This();

    /// Extract an RDATA. This only spits out a slice of u8.
    /// Parsing of RDATA sections are in the dns.rdata module.
    ///
    /// Caller owns returned memory.
    fn readResourceDataFrom(
        reader: *std.Io.Reader,
        options: dns.ParserOptions,
    ) !?dns.ResourceData.Opaque {
        if (options.allocator) |allocator| {
            const rdata_length = try reader.takeInt(u16, .big);
            const rdata_index = reader.seek;

            const opaque_rdata = try allocator.alloc(u8, rdata_length);
            try reader.readSliceAll(opaque_rdata);
            return .{
                .data = opaque_rdata,
                .current_byte_count = rdata_index,
            };
        } else {
            return null;
        }
    }

    pub fn readFrom(reader: *std.Io.Reader, options: dns.ParserOptions) !Self {
        logger.debug(
            "reading resource at {d} bytes",
            .{reader.seek},
        );
        const name = try Name.readFrom(reader, options);
        const typ = try ResourceType.readFrom(reader);
        const class = try ResourceClass.readFrom(reader);
        const ttl = try reader.takeInt(i32, .big);
        const opaque_rdata = try Self.readResourceDataFrom(reader, options);

        return Self{
            .name = name,
            .typ = typ,
            .class = class,
            .ttl = ttl,
            .opaque_rdata = opaque_rdata,
        };
    }

    pub fn writeTo(self: @This(), writer: anytype) !void {
        try self.name.?.writeTo(writer);
        try self.typ.writeTo(writer);
        try self.class.writeTo(writer);
        try writer.writeInt(i32, self.ttl, .big);
        try writer.writeInt(u16, @as(u16, @intCast(self.opaque_rdata.?.data.len)), .big);
        _ = try writer.write(self.opaque_rdata.?.data);
    }
};

/// A DNS packet, as specified in RFC1035.
///
/// Beware, the amount of questions or resources given in this Packet
/// MUST be synchronized with the lengths set in the Header field.
///
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
pub const Packet = struct {
    header: Header,
    questions: []Question,
    answers: []Resource,
    nameservers: []Resource,
    additionals: []Resource,

    const Self = @This();

    fn writeResourceListTo(resource_list: []Resource, writer: anytype) !void {
        for (resource_list) |resource| {
            try resource.writeTo(writer);
        }
    }

    /// Write the network representation of this packet into a Writer.
    pub fn writeTo(self: Self, writer: *std.Io.Writer) !void {
        var writer_start = writer.end;
        std.debug.assert(self.header.question_length == self.questions.len);
        std.debug.assert(self.header.answer_length == self.answers.len);
        std.debug.assert(self.header.nameserver_length == self.nameservers.len);
        std.debug.assert(self.header.additional_length == self.additionals.len);

        try self.header.writeTo(writer);
        const header_size = writer.end - writer_start;
        writer_start = writer.end;

        for (self.questions) |question| {
            try question.name.?.writeTo(writer);
            try question.typ.writeTo(writer);
            try question.class.writeTo(writer);
        }
        const question_size = writer.end - writer_start;
        writer_start = writer.end;

        try Self.writeResourceListTo(self.answers, writer);
        const answers_size = writer.end - writer_start;
        writer_start = writer.end;

        try Self.writeResourceListTo(self.nameservers, writer);
        const nameservers_size = writer.end - writer_start;
        writer_start = writer.end;

        try Self.writeResourceListTo(self.additionals, writer);
        const additionals_size = writer.end - writer_start;
        writer_start = writer.end;

        logger.debug(
            "header = {d}, question_size = {d}, answers_size = {d}," ++
                " nameservers_size = {d}, additionals_size = {d}",
            .{ header_size, question_size, answers_size, nameservers_size, additionals_size },
        );

        // return header_size + question_size +
        //     answers_size + nameservers_size + additionals_size;
    }
};

/// Represents a Packet where all of its data was allocated dynamically.
pub const IncomingPacket = struct {
    allocator: std.mem.Allocator,
    packet: *Packet,

    fn freeResource(
        self: @This(),
        resource: Resource,
        options: DeinitOptions,
    ) void {
        if (options.names)
            if (resource.name) |name| name.deinit(self.allocator);
        if (resource.opaque_rdata) |opaque_rdata|
            self.allocator.free(opaque_rdata.data);
    }

    fn freeResourceList(
        self: @This(),
        resource_list: []Resource,
        options: DeinitOptions,
    ) void {
        for (resource_list) |resource| self.freeResource(resource, options);
        self.allocator.free(resource_list);
    }

    pub const DeinitOptions = struct {
        /// If the names inside the packet should be deinitialized or not.
        ///
        /// This should be set to false if you are passing ownership of the Name
        /// to dns.NamePool, as it has dns.NamePool.deinitWithNames().
        names: bool = true,
    };

    pub fn deinit(self: @This(), options: DeinitOptions) void {
        if (options.names) for (self.packet.questions) |question| {
            if (question.name) |name| name.deinit(self.allocator);
        };

        self.allocator.free(self.packet.questions);
        self.freeResourceList(self.packet.answers, options);
        self.freeResourceList(self.packet.nameservers, options);
        self.freeResourceList(self.packet.additionals, options);

        self.allocator.destroy(self.packet);
    }
};
