const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const dns = @import("lib.zig");
const helpers = @import("helpers.zig");
const Packet = dns.Packet;

test "convert domain string to dns name" {
    const domain = "www.google.com";
    var name_buffer: [3][]const u8 = undefined;
    const name = (try dns.Name.fromString(domain[0..], &name_buffer)).full;
    try std.testing.expectEqual(3, name.labels.len);
    try std.testing.expectEqualStrings("www", name.labels[0]);
    try std.testing.expectEqualStrings("google", name.labels[1]);
    try std.testing.expectEqualStrings("com", name.labels[2]);
}

test "convert domain string to dns name (buffer overflow case)" {
    const domain = "www.google.com";
    var name_buffer: [1][]const u8 = undefined;
    _ = dns.Name.fromString(domain[0..], &name_buffer) catch |err| switch (err) {
        error.Overflow => {},
        else => return err,
    };
}

// extracted with 'dig google.com a +noedns'
const TEST_PKT_QUERY = "FEUBIAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ==";
const TEST_PKT_RESPONSE = "RM2BgAABAAEAAAAABmdvb2dsZQNjb20AAAEAAcAMAAEAAQAAASwABNg6yo4=";
const GOOGLE_COM_LABELS = [_][]const u8{ "google"[0..], "com"[0..] };

test "Packet serialize/deserialize" {
    var seed_buf: [8]u8 = undefined;
    @memset(&seed_buf, 0x42); // deterministic for test
    const seed = std.mem.readInt(u64, &seed_buf, .little);
    var r = std.Random.DefaultPrng.init(seed);
    const random_id = r.random().int(u16);
    const packet = dns.Packet{
        .header = .{ .id = random_id },
        .questions = &[_]dns.Question{},
        .answers = &[_]dns.Resource{},
        .nameservers = &[_]dns.Resource{},
        .additionals = &[_]dns.Resource{},
    };

    // then we'll serialize it under a buffer on the stack,
    // deserialize it, and the header.id should be equal to random_id
    var write_buffer: [1024]u8 = undefined;
    const buf = try serialTest(packet, &write_buffer);

    // deserialize it and compare if everythings' equal
    var incoming = try deserialTest(buf);
    defer incoming.deinit(.{});
    const deserialized = incoming.packet;

    try std.testing.expectEqual(deserialized.header.id, packet.header.id);

    const fields = [_][]const u8{ "id", "opcode", "question_length", "answer_length" };

    const new_header = deserialized.header;
    const header = packet.header;

    inline for (fields) |field| {
        try std.testing.expectEqual(
            @field(new_header, field),
            @field(header, field),
        );
    }
}

fn decodeBase64(encoded: []const u8, write_buffer: []u8) ![]const u8 {
    const size = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    try std.base64.standard.Decoder.decode(write_buffer[0..size], encoded);
    return write_buffer[0..size];
}

fn expectGoogleLabels(actual: [][]const u8) !void {
    for (actual, 0..) |label, idx| {
        try std.testing.expectEqualSlices(u8, label, GOOGLE_COM_LABELS[idx]);
    }
}

test "deserialization of original question google.com/A" {
    var write_buffer: [0x10000]u8 = undefined;

    const decoded = try decodeBase64(TEST_PKT_QUERY, &write_buffer);

    var incoming = try deserialTest(decoded);
    defer incoming.deinit(.{});
    const pkt = incoming.packet;

    try std.testing.expectEqual(@as(u16, 5189), pkt.header.id);
    try std.testing.expectEqual(@as(u16, 1), pkt.header.question_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.answer_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.nameserver_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.additional_length);
    try std.testing.expectEqual(@as(usize, 1), pkt.questions.len);

    const question = pkt.questions[0];

    try expectGoogleLabels(question.name.?.full.labels);
    try std.testing.expectEqual(@as(usize, 12), question.name.?.full.packet_index.?);
    try std.testing.expectEqual(question.typ, dns.ResourceType.A);
    try std.testing.expectEqual(question.class, dns.ResourceClass.IN);
}

test "deserialization of reply google.com/A" {
    var encode_buffer: [0x10000]u8 = undefined;
    const decoded = try decodeBase64(TEST_PKT_RESPONSE, &encode_buffer);

    var incoming = try deserialTest(decoded);
    defer incoming.deinit(.{});
    const pkt = incoming.packet;

    try std.testing.expectEqual(@as(u16, 17613), pkt.header.id);
    try std.testing.expectEqual(@as(u16, 1), pkt.header.question_length);
    try std.testing.expectEqual(@as(u16, 1), pkt.header.answer_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.nameserver_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.additional_length);

    const question = pkt.questions[0];

    try expectGoogleLabels(question.name.?.full.labels);
    try testing.expectEqual(dns.ResourceType.A, question.typ);
    try testing.expectEqual(dns.ResourceClass.IN, question.class);

    const answer = pkt.answers[0];

    try expectGoogleLabels(answer.name.?.full.labels);
    try testing.expectEqual(dns.ResourceType.A, answer.typ);
    try testing.expectEqual(dns.ResourceClass.IN, answer.class);
    try testing.expectEqual(@as(i32, 300), answer.ttl);

    const resource_data = try dns.ResourceData.fromOpaque(
        .A,
        answer.opaque_rdata.?,
        .{},
    );

    try testing.expectEqual(
        dns.ResourceType.A,
        @as(dns.ResourceType, resource_data),
    );

    const addr = resource_data.A.ip4.bytes;
    try testing.expectEqual(@as(u8, 216), addr[0]);
    try testing.expectEqual(@as(u8, 58), addr[1]);
    try testing.expectEqual(@as(u8, 202), addr[2]);
    try testing.expectEqual(@as(u8, 142), addr[3]);
}

fn encodeBase64(buffer: []u8, source: []const u8) []const u8 {
    const encoded = buffer[0..std.base64.standard.Encoder.calcSize(source.len)];
    return std.base64.standard.Encoder.encode(encoded, source);
}

fn encodePacket(pkt: Packet, encode_buffer: []u8, write_buffer: []u8) ![]const u8 {
    const out = try serialTest(pkt, write_buffer);
    return encodeBase64(encode_buffer, out);
}

test "serialization of google.com/A (question)" {
    const domain = "google.com";
    var name_buffer: [2][]const u8 = undefined;
    const name = try dns.Name.fromString(domain[0..], &name_buffer);

    var questions = [_]dns.Question{.{
        .name = name,
        .typ = .A,
        .class = .IN,
    }};

    var empty = [0]dns.Resource{};

    const packet = dns.Packet{
        .header = .{
            .id = 5189,
            .wanted_recursion = true,
            .z = 2,
            .question_length = 1,
        },
        .questions = &questions,
        .answers = &empty,
        .nameservers = &empty,
        .additionals = &empty,
    };

    var encode_buffer: [256]u8 = undefined;
    var write_buffer: [256]u8 = undefined;
    const encoded = try encodePacket(packet, &encode_buffer, &write_buffer);
    try std.testing.expectEqualSlices(u8, TEST_PKT_QUERY, encoded);
}

fn serialTest(packet: Packet, write_buffer: []u8) ![]u8 {
    var stream = std.Io.Writer.fixed(write_buffer);
    try packet.writeTo(&stream);
    const written_data = write_buffer[0..stream.end];
    return written_data;
}

fn deserialTest(packet_data: []const u8) !dns.IncomingPacket {
    var stream = std.Io.Reader.fixed(packet_data);
    return try dns.helpers.parseFullPacket(
        &stream,
        std.testing.allocator,
        .{},
    );
}

test "convert string to dns type" {
    const parsed = try dns.ResourceType.fromString("AAAA");
    try std.testing.expectEqual(dns.ResourceType.AAAA, parsed);
}

test "names have good sizes" {
    var name_buffer: [10][]const u8 = undefined;
    var name = try dns.Name.fromString("example.com", &name_buffer);

    var buf: [256]u8 = undefined;
    var stream = std.Io.Writer.fixed(&buf);
    try name.writeTo(&stream);

    // length + data + length + data + null
    try testing.expectEqual(@as(usize, 1 + 7 + 1 + 3 + 1), stream.end);
}

test "resources have good sizes" {
    var name_buffer: [10][]const u8 = undefined;
    var name = try dns.Name.fromString("example.com", &name_buffer);

    var resource = dns.Resource{
        .name = name,
        .typ = .A,
        .class = .IN,
        .ttl = 300,
        .opaque_rdata = .{ .data = "", .current_byte_count = 0 },
    };

    var buf: [256]u8 = undefined;
    var stream = std.Io.Writer.fixed(&buf);
    try resource.writeTo(&stream);

    // name + rr (2) + class (2) + ttl (4) + rdlength (2)
    try testing.expectEqual(
        @as(usize, name.networkSize() + 10 + resource.opaque_rdata.?.data.len),
        stream.end,
    );
}

// This is a known packet generated by zigdig. It would be welcome to have it
// tested in other libraries.
const PACKET_WITH_RDATA = "FEUBIAAAAAEAAAAABmdvb2dsZQNjb20AAAEAAQAAASwABAEAAH8=";

test "rdata serialization" {
    var name_buffer: [2][]const u8 = undefined;
    const name = try dns.Name.fromString("google.com", &name_buffer);
    var resource_data = dns.ResourceData{
        .A = .{ .ip4 = .{ .bytes = .{ 1, 0, 0, 127 }, .port = 0 } },
    };

    var opaque_rdata_buffer: [1024]u8 = undefined;
    var stream = std.Io.Writer.fixed(&opaque_rdata_buffer);
    try resource_data.writeTo(&stream);
    const opaque_rdata = opaque_rdata_buffer[0..stream.end];

    var answers = [_]dns.Resource{.{
        .name = name,
        .typ = .A,
        .class = .IN,
        .ttl = 300,
        .opaque_rdata = .{ .data = opaque_rdata, .current_byte_count = 0 },
    }};

    var empty_res = [_]dns.Resource{};
    var empty_question = [_]dns.Question{};
    const packet = dns.Packet{
        .header = .{
            .id = 5189,
            .wanted_recursion = true,
            .z = 2,
            .answer_length = 1,
        },
        .questions = &empty_question,
        .answers = &answers,
        .nameservers = &empty_res,
        .additionals = &empty_res,
    };

    var write_buffer: [1024]u8 = undefined;
    const serialized_result = try serialTest(packet, &write_buffer);

    var encode_buffer: [1024]u8 = undefined;
    const encoded_result = encodeBase64(&encode_buffer, serialized_result);
    try std.testing.expectEqualStrings(PACKET_WITH_RDATA, encoded_result);
}

test "localhost always resolves to 127.0.0.1" {
    const addrs = try helpers.getAddressList(std.testing.io, "localhost", 80, std.testing.allocator);
    defer addrs.deinit();
    // First should be IPv6 loopback ::1
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &addrs.addrs[0].ip6.bytes);
    // Second should be IPv4 loopback 127.0.0.1
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &addrs.addrs[1].ip4.bytes);
}

test "NS records with cross-rdata pointer compression" {
    // Simulates a response for "l4.pm NS" with two NS records:
    //   - coco.bunny.net. (full name in rdata)
    //   - kiki.bunny.net. (uses pointer to "bunny.net." in first rdata)
    //
    // Packet layout:
    //   offset  0: header (12 bytes)
    //   offset 12: question name \x02l4\x02pm\x00 (7 bytes)
    //   offset 19: question type/class (4 bytes)
    //   offset 23: answer 1 header (name ptr + type + class + ttl + rdlength = 12 bytes)
    //   offset 35: answer 1 rdata: \x04coco\x05bunny\x03net\x00 (16 bytes)
    //   offset 51: answer 2 header (12 bytes)
    //   offset 63: answer 2 rdata: \x04kiki\xC0\x28 (7 bytes)
    //                                        ^ pointer to offset 40 = "bunny.net." in answer 1 rdata
    const packet_bytes = [_]u8{
        // Header
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: response, recursion desired+available
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x02, // ANCOUNT: 2
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0

        // Question: l4.pm IN NS
        0x02, 'l',
        '4',  0x02,
        'p',  'm',
        0x00,
        0x00, 0x02, // Type NS
        0x00, 0x01, // Class IN

        // Answer 1: l4.pm NS coco.bunny.net.
        0xC0, 0x0C, // Name: pointer to offset 12 (l4.pm)
        0x00, 0x02, // Type NS
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x0E, 0x10, // TTL 3600
        0x00, 0x10, // RDLENGTH 16
        0x04, 'c',
        'o',  'c',
        'o',  0x05,
        'b',  'u',
        'n',  'n',
        'y',  0x03,
        'n',  'e',
        't',
        0x00,

        // Answer 2: l4.pm NS kiki.bunny.net.
        0xC0, 0x0C, // Name: pointer to offset 12 (l4.pm)
        0x00, 0x02, // Type NS
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x0E, 0x10, // TTL 3600
        0x00, 0x07, // RDLENGTH 7
        0x04, 'k',
        'i',  'k',
        'i',
        0xC0, 0x28, // pointer to offset 40 (bunny.net.)
    };

    var stream = std.Io.Reader.fixed(&packet_bytes);
    var name_pool = dns.NamePool.init(std.testing.allocator);
    defer name_pool.deinitWithNames();

    var incoming = try dns.helpers.parseFullPacket(
        &stream,
        std.testing.allocator,
        .{ .name_pool = &name_pool },
    );
    defer incoming.deinit(.{ .names = false });

    const pkt = incoming.packet;

    // Verify basic structure
    try std.testing.expectEqual(@as(u16, 2), pkt.header.answer_length);
    try std.testing.expectEqual(@as(usize, 2), pkt.answers.len);

    // Parse both NS rdata records through the name pool
    const ns1 = try dns.ResourceData.fromOpaque(
        .NS,
        pkt.answers[0].opaque_rdata.?,
        .{
            .name_provider = .{ .full = &name_pool },
            .allocator = std.testing.allocator,
        },
    );

    const ns2 = try dns.ResourceData.fromOpaque(
        .NS,
        pkt.answers[1].opaque_rdata.?,
        .{
            .name_provider = .{ .full = &name_pool },
            .allocator = std.testing.allocator,
        },
    );

    // Verify first NS record: coco.bunny.net.
    const ns1_name = ns1.NS.?.full;
    try std.testing.expectEqual(@as(usize, 3), ns1_name.labels.len);
    try std.testing.expectEqualStrings("coco", ns1_name.labels[0]);
    try std.testing.expectEqualStrings("bunny", ns1_name.labels[1]);
    try std.testing.expectEqualStrings("net", ns1_name.labels[2]);

    // Verify second NS record: kiki.bunny.net.
    // This is the critical test - "bunny.net." comes from pointer compression
    const ns2_name = ns2.NS.?.full;
    try std.testing.expectEqual(@as(usize, 3), ns2_name.labels.len);
    try std.testing.expectEqualStrings("kiki", ns2_name.labels[0]);
    try std.testing.expectEqualStrings("bunny", ns2_name.labels[1]);
    try std.testing.expectEqualStrings("net", ns2_name.labels[2]);
}

test "pointer offset >= 256 (14-bit offset high byte)" {
    // Exercises the pointer offset parsing for offsets >= 256, where
    // the first byte's lower 6 bits are nonzero. A long question name
    // pushes answer rdata past byte 256, then answer 2 uses a pointer
    // into answer 1's rdata at offset >= 256.
    //
    // Packet layout:
    //   offset   0: header (12 bytes)
    //   offset  12: question name: 4 labels of 58 chars each + null (237 bytes)
    //   offset 249: question type/class (4 bytes)
    //   offset 253: answer 1 header (name ptr + type + class + ttl + rdlength = 12 bytes)
    //   offset 265: answer 1 rdata: \x04test\x03net\x00 (10 bytes)
    //               "net" label starts at offset 270 (0x10E)
    //   offset 275: answer 2 header (12 bytes)
    //   offset 287: answer 2 rdata: \x04kiki + pointer to offset 270 (0xC1 0x0E)
    //
    // Old buggy code computed pointer 0xC1 0x0E as offset 142 instead of 270.
    var packet_bytes: [294]u8 = undefined;
    var i: usize = 0;

    // Header (12 bytes)
    const header = [_]u8{
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x02, // ANCOUNT: 2
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    };
    @memcpy(packet_bytes[i..][0..header.len], &header);
    i += header.len;

    // Question name: 4 labels of 58 chars each
    for (0..4) |label_idx| {
        packet_bytes[i] = 58; // length prefix
        i += 1;
        const fill_char: u8 = 'a' + @as(u8, @intCast(label_idx));
        @memset(packet_bytes[i..][0..58], fill_char);
        i += 58;
    }
    packet_bytes[i] = 0x00; // null terminator
    i += 1;
    std.debug.assert(i == 249);

    // Question type NS + class IN
    @memcpy(packet_bytes[i..][0..4], &[_]u8{ 0x00, 0x02, 0x00, 0x01 });
    i += 4;
    std.debug.assert(i == 253);

    // Answer 1: pointer to question name, NS, rdata = "test.net."
    const ans1_header = [_]u8{
        0xC0, 0x0C, // Name: pointer to offset 12
        0x00, 0x02, // Type NS
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x0E, 0x10, // TTL 3600
        0x00, 0x0A, // RDLENGTH 10
    };
    @memcpy(packet_bytes[i..][0..ans1_header.len], &ans1_header);
    i += ans1_header.len;
    std.debug.assert(i == 265);

    // Answer 1 rdata: \x04test\x03net\x00
    const rdata1 = [_]u8{ 0x04, 't', 'e', 's', 't', 0x03, 'n', 'e', 't', 0x00 };
    @memcpy(packet_bytes[i..][0..rdata1.len], &rdata1);
    i += rdata1.len;
    std.debug.assert(i == 275);

    // Answer 2: pointer to question name, NS, rdata = "kiki" + pointer to offset 270
    const ans2_header = [_]u8{
        0xC0, 0x0C, // Name: pointer to offset 12
        0x00, 0x02, // Type NS
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x0E, 0x10, // TTL 3600
        0x00, 0x07, // RDLENGTH 7
    };
    @memcpy(packet_bytes[i..][0..ans2_header.len], &ans2_header);
    i += ans2_header.len;
    std.debug.assert(i == 287);

    // Answer 2 rdata: \x04kiki + pointer to offset 270 (0x10E)
    // Pointer bytes: 0xC0 | (0x10E >> 8) = 0xC1, low byte = 0x0E
    const rdata2 = [_]u8{ 0x04, 'k', 'i', 'k', 'i', 0xC1, 0x0E };
    @memcpy(packet_bytes[i..][0..rdata2.len], &rdata2);
    i += rdata2.len;
    std.debug.assert(i == 294);

    var stream = std.Io.Reader.fixed(&packet_bytes);
    var name_pool = dns.NamePool.init(std.testing.allocator);
    defer name_pool.deinitWithNames();

    var incoming = try dns.helpers.parseFullPacket(
        &stream,
        std.testing.allocator,
        .{ .name_pool = &name_pool },
    );
    defer incoming.deinit(.{ .names = false });

    const pkt = incoming.packet;
    try std.testing.expectEqual(@as(usize, 2), pkt.answers.len);

    // Parse NS rdata through name pool
    const ns1 = try dns.ResourceData.fromOpaque(
        .NS,
        pkt.answers[0].opaque_rdata.?,
        .{ .name_provider = .{ .full = &name_pool }, .allocator = std.testing.allocator },
    );
    const ns1_name = ns1.NS.?.full;
    try std.testing.expectEqual(@as(usize, 2), ns1_name.labels.len);
    try std.testing.expectEqualStrings("test", ns1_name.labels[0]);
    try std.testing.expectEqualStrings("net", ns1_name.labels[1]);

    const ns2 = try dns.ResourceData.fromOpaque(
        .NS,
        pkt.answers[1].opaque_rdata.?,
        .{ .name_provider = .{ .full = &name_pool }, .allocator = std.testing.allocator },
    );
    const ns2_name = ns2.NS.?.full;
    try std.testing.expectEqual(@as(usize, 2), ns2_name.labels.len);
    try std.testing.expectEqualStrings("kiki", ns2_name.labels[0]);
    try std.testing.expectEqualStrings("net", ns2_name.labels[1]);
}

test "pointer into multi-label name respects wire length prefixes" {
    // Exercises the NamePool wire length calculation fix. A name with
    // many short labels (1 char each) makes the off-by-N error from
    // missing length prefix bytes significant enough that a pointer to
    // a later label falls outside the incorrectly computed range.
    //
    // Packet layout:
    //   offset  0: header (12 bytes)
    //   offset 12: question name \x01q\x00 (3 bytes)
    //   offset 15: question type/class (4 bytes)
    //   offset 19: answer 1 header (12 bytes)
    //   offset 31: answer 1 rdata: name "a.b.c.d.e.f.g" (15 bytes)
    //              label "g" length byte at offset 31+12 = 43
    //              Without +1 fix: name_length = 7, end = 38. 43 > 38 = miss!
    //              With    +1 fix: name_length = 14, end = 45. 43 <= 45 = hit!
    //   offset 46: answer 2 header (12 bytes)
    //   offset 58: answer 2 rdata: \x01z + pointer to offset 43 (0xC0 0x2B)
    const packet_bytes = [_]u8{
        // Header
        0xAB, 0xCD, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x02, // ANCOUNT: 2
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0

        // Question: q. IN NS
        0x01, 'q',
        0x00,
        0x00, 0x02, // Type NS
        0x00, 0x01, // Class IN

        // Answer 1: q. NS a.b.c.d.e.f.g.
        0xC0, 0x0C, // Name: pointer to offset 12 (q.)
        0x00, 0x02, // Type NS
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x0E, 0x10, // TTL 3600
        0x00, 0x0F, // RDLENGTH 15

        // rdata: a.b.c.d.e.f.g. (offset 31)
        0x01, 'a',
        0x01, 'b',
        0x01, 'c',
        0x01, 'd',
        0x01, 'e',
        0x01, 'f',
        0x01, 'g', // "g" length byte at offset 31+12 = 43
        0x00,

        // Answer 2: q. NS z.g.
        0xC0, 0x0C, // Name: pointer to offset 12 (q.)
        0x00, 0x02, // Type NS
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x0E, 0x10, // TTL 3600
        0x00, 0x04, // RDLENGTH 4

        // rdata: \x01z + pointer to offset 43 ("g." from answer 1 rdata)
        0x01, 'z',
        0xC0, 0x2B, // pointer to offset 43
    };

    var stream = std.Io.Reader.fixed(&packet_bytes);
    var name_pool = dns.NamePool.init(std.testing.allocator);
    defer name_pool.deinitWithNames();

    var incoming = try dns.helpers.parseFullPacket(
        &stream,
        std.testing.allocator,
        .{ .name_pool = &name_pool },
    );
    defer incoming.deinit(.{ .names = false });

    const pkt = incoming.packet;
    try std.testing.expectEqual(@as(usize, 2), pkt.answers.len);

    // Parse answer 1 NS rdata first (registers "a.b.c.d.e.f.g" in pool)
    const ns1 = try dns.ResourceData.fromOpaque(
        .NS,
        pkt.answers[0].opaque_rdata.?,
        .{ .name_provider = .{ .full = &name_pool }, .allocator = std.testing.allocator },
    );
    const ns1_name = ns1.NS.?.full;
    try std.testing.expectEqual(@as(usize, 7), ns1_name.labels.len);
    try std.testing.expectEqualStrings("a", ns1_name.labels[0]);
    try std.testing.expectEqualStrings("g", ns1_name.labels[6]);

    // Parse answer 2 NS rdata: "z" + pointer to "g" from answer 1
    // Without the +1 fix, the name pool would fail to find the name
    // covering offset 43, returning UnknownPointerOffset.
    const ns2 = try dns.ResourceData.fromOpaque(
        .NS,
        pkt.answers[1].opaque_rdata.?,
        .{ .name_provider = .{ .full = &name_pool }, .allocator = std.testing.allocator },
    );
    const ns2_name = ns2.NS.?.full;
    try std.testing.expectEqual(@as(usize, 2), ns2_name.labels.len);
    try std.testing.expectEqualStrings("z", ns2_name.labels[0]);
    try std.testing.expectEqualStrings("g", ns2_name.labels[1]);
}

test "everything" {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("name.zig"));
    std.testing.refAllDecls(@import("cidr.zig"));
}
