const builtin = @import("builtin");

const mqtt = @import("mqtt.zig");

const native_endian = builtin.cpu.arch.endian();

pub inline fn readInt(
    comptime T: type,
    buf: *const [@divExact(@typeInfo(T).int.bits, 8)]u8,
) T {
    const value: T = @bitCast(buf.*);
    return if (native_endian == .big) value else @byteSwap(value);
}

pub inline fn writeInt(
    comptime T: type,
    buf: *[@divExact(@typeInfo(T).int.bits, 8)]u8,
    value: T,
) void {
    buf.* = @bitCast(if (native_endian == .big) value else @byteSwap(value));
}

pub fn readString(buf: []const u8) error{InvalidString}!struct { []const u8, usize } {
    if (buf.len < 2) {
        return error.InvalidString;
    }
    const len = readInt(u16, buf[0..2]);
    const end = len + 2;
    if (buf.len < end) {
        return error.InvalidString;
    }
    return .{ buf[2..end], end };
}

pub fn writeString(buf: []u8, value: []const u8) error{WriteBufferFull}!usize {
    const total = value.len + 2;
    if (buf.len < total) {
        return error.WriteBufferFull;
    }

    writeInt(u16, buf[0..2], @intCast(value.len));
    @memcpy(buf[2..total], value);
    return total;
}

pub fn writeVarint(buf: []u8, len: usize) error{ WriteBufferFull, ValueTooLarge }!usize {
    if (len > 268_435_455) return error.ValueTooLarge;

    var i: usize = 0;
    var remaining = len;
    while (true) : (i += 1) {
        if (i >= buf.len) return error.WriteBufferFull;

        const b: u8 = @intCast(remaining & 0x7F);
        remaining >>= 7;

        if (remaining == 0) {
            buf[i] = b;
            return i + 1;
        }

        buf[i] = b | 0x80;
    }
}

// This returns the varint value (if we have one) AND the length of the varint
pub fn readVarint(buf: []const u8) error{InvalidVarint}!?struct { usize, usize } {
    if (buf.len == 0) {
        return null;
    }

    if (buf[0] < 128) {
        return .{ @as(usize, @intCast(buf[0])), 1 };
    }

    if (buf.len == 1) {
        return null;
    }

    var total: usize = buf[0] & 0x7f;
    if (buf[1] < 128) {
        return .{ total + @as(usize, buf[1]) * 128, 2 };
    }

    if (buf.len == 2) {
        return null;
    }
    total += (@as(usize, buf[1]) & 0x7f) * 128;
    if (buf[2] < 128) {
        return .{ total + @as(usize, buf[2]) * 16_384, 3 };
    }

    if (buf.len == 3) {
        return null;
    }
    total += (@as(usize, buf[2]) & 0x7f) * 16_384;
    if (buf[3] < 128) {
        return .{ total + @as(usize, buf[3]) * 2_097_152, 4 };
    }

    return error.InvalidVarint;
}

pub fn calcLengthOfVarint(len: usize) usize {
    return switch (len) {
        0...127 => 1,
        128...16_383 => 2,
        16_384...2_097_151 => 3,
        2_097_152...268_435_455 => 4,
        else => unreachable,
    };
}

pub const PublishFlags = packed struct(u4) {
    dup: bool,
    qos: mqtt.QoS,
    retain: bool,
};

pub fn encodePacketHeader(buf: []u8, packet_type: u8, packet_flags: u8) ![]u8 {
    const remaining_len = buf.len - 5;
    const length_of_len = calcLengthOfVarint(remaining_len);

    // This is where, in buf, our packet is actually going to start. You'd think
    // it would start at buf[0], but the package length is variable, so it'll
    // only start at buf[0] in the [unlikely] case where the length took 4 bytes.
    const start = 5 - length_of_len - 1;

    buf[start] = (packet_type << 4) | packet_flags;
    _ = try writeVarint(buf[start + 1 ..], remaining_len);
    return buf[start..];
}

pub fn encodeConnect(buf: []u8, opts: mqtt.ConnectOpts) ![]u8 {
    var connect_flags = packed struct(u8) {
        _reserved: bool = false,
        clean_start: bool = true,
        will: bool = false,
        will_qos: mqtt.QoS = .at_most_once,
        will_retain: bool = false,
        username: bool,
        password: bool,
    }{
        .username = opts.username != null,
        .password = opts.password != null,
    };

    if (opts.will) |w| {
        connect_flags.will = true;
        connect_flags.will_qos = w.qos;
        connect_flags.will_retain = w.retain;
    }

    buf[5] = 0;
    buf[6] = 4;
    buf[7] = 'M';
    buf[8] = 'Q';
    buf[9] = 'T';
    buf[10] = 'T';
    buf[11] = 4;

    buf[12] = @bitCast(connect_flags);

    writeInt(u16, buf[13..15], opts.keepalive_sec);

    const PAYLOAD_OFFSET = 15;

    var pos: usize = PAYLOAD_OFFSET;
    pos += try writeString(buf[pos..], opts.client_id orelse "");

    if (opts.will) |will| {
        pos += try writeString(buf[pos..], will.topic);
        pos += try writeString(buf[pos..], will.message);
    }

    if (opts.username) |u| {
        pos += try writeString(buf[pos..], u);
    }

    if (opts.password) |p| {
        pos += try writeString(buf[pos..], p);
    }

    return encodePacketHeader(buf[0..pos], 1, 0);
}

pub fn encodeSubscribe(
    buf: []u8,
    packet_identifier: u16,
    opts: mqtt.SubscribeOpts,
) ![]u8 {
    // reserve 1 byte for the packet type
    // reserve 4 bytes for the packet length (which might be less than 4 bytes)
    writeInt(u16, buf[5..7], packet_identifier);

    const PAYLOAD_OFFSET = 7;
    var pos: usize = PAYLOAD_OFFSET;
    for (opts.topics) |topic| {
        pos += try writeString(buf[pos..], topic.filter);
        buf[pos] = @intFromEnum(topic.qos);
        pos += 1;
    }

    return encodePacketHeader(buf[0..pos], 8, 2);
}

pub fn encodeUnsubscribe(
    buf: []u8,
    packet_identifier: u16,
    opts: mqtt.UnsubscribeOpts,
) ![]u8 {
    // reserve 1 byte for the packet type
    // reserve 4 bytes for the packet length (which might be less than 4 bytes)
    writeInt(u16, buf[5..7], packet_identifier);

    const PAYLOAD_OFFSET = 7;
    var pos = PAYLOAD_OFFSET;
    for (opts.topics) |topic| {
        pos += try writeString(buf[pos..], topic);
    }

    return encodePacketHeader(buf[0..pos], 10, 2);
}

pub fn encodePublish(
    buf: []u8,
    packet_identifier: ?u16,
    opts: mqtt.PublishOpts,
) ![]u8 {
    const publish_flags = PublishFlags{
        .dup = opts.dup,
        .qos = opts.qos,
        .retain = opts.retain,
    };

    // reserve 1 byte for the packet type
    // reserve 4 bytes for the packet length (which might be less than 4 bytes)
    const VARIABLE_HEADER_OFFSET = 5;
    const topic_len = try writeString(buf[VARIABLE_HEADER_OFFSET..], opts.topic);

    var payload_offset = VARIABLE_HEADER_OFFSET + topic_len;
    if (packet_identifier) |pi| {
        const packet_identifier_offset = payload_offset;
        payload_offset += 2;
        writeInt(u16, buf[packet_identifier_offset..payload_offset][0..2], pi);
    }

    const message = opts.message;
    const end = payload_offset + message.len;
    if (end > buf.len) {
        return error.WriteBufferFull;
    }

    @memcpy(buf[payload_offset..end], message);
    return encodePacketHeader(buf[0..end], 3, @as(u4, @bitCast(publish_flags)));
}

pub fn encodePubAck(buf: []u8, opts: mqtt.PubAckOpts) ![]u8 {
    // reserve 1 byte for the packet type
    // reserve 4 bytes for the packet length (which might be less than 4 bytes)
    writeInt(u16, buf[5..7], opts.packet_identifier);

    // MQTT 3.1.1: only packet identifier (2 bytes)
    buf[3] = 64; // packet type (0100) + flags (0000)
    buf[4] = 2; // remaining length
    return buf[3..7];
}

pub fn encodePubRec(buf: []u8, opts: mqtt.PubRecOpts) ![]u8 {
    // reserve 1 byte for the packet type
    // reserve 4 bytes for the packet length (which might be less than 4 bytes)
    writeInt(u16, buf[5..7], opts.packet_identifier);

    // MQTT 3.1.1: only packet identifier (2 bytes)
    buf[3] = 80; // packet type (0101) + flags (0000)
    buf[4] = 2; // remaining length
    return buf[3..7];
}

pub fn encodePubRel(buf: []u8, opts: mqtt.PubRelOpts) ![]u8 {
    // reserve 1 byte for the packet type
    // reserve 4 bytes for the packet length (which might be less than 4 bytes)
    writeInt(u16, buf[5..7], opts.packet_identifier);

    // MQTT 3.1.1: only packet identifier (2 bytes)
    buf[3] = 98; // packet type (0110) + flags (0010)
    buf[4] = 2; // remaining length
    return buf[3..7];
}

pub fn encodePubComp(buf: []u8, opts: mqtt.PubCompOpts) ![]u8 {
    // reserve 1 byte for the packet type
    // reserve 4 bytes for the packet length (which might be less than 4 bytes)
    writeInt(u16, buf[5..7], opts.packet_identifier);

    // MQTT 3.1.1: only packet identifier (2 bytes)
    buf[3] = 112; // packet type (0111) + flags (0000)
    buf[4] = 2; // remaining length
    return buf[3..7];
}

pub fn encodeDisconnect(buf: []u8) ![]u8 {
    // In MQTT 3.1.1, DISCONNECT has no variable header (only fixed header)
    return encodePacketHeader(buf[0..5], 14, 0);
}
