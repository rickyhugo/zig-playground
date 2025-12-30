const std = @import("std");
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

// Maximum length of MQTT fixed header: 1 byte packet type + 4 bytes max varint length
const MAX_FIXED_HEADER_LEN = 5;

pub const PublishFlags = packed struct(u4) {
    dup: bool,
    qos: mqtt.QoS,
    retain: bool,
};

pub fn encodePacketHeader(buf: []u8, packet_type: u8, packet_flags: u8) ![]u8 {
    const remaining_len = buf.len - MAX_FIXED_HEADER_LEN;
    const length_of_len = calcLengthOfVarint(remaining_len);

    // This is where, in buf, our packet is actually going to start. You'd think
    // it would start at buf[0], but the package length is variable, so it'll
    // only start at buf[0] in the [unlikely] case where the length took 4 bytes.
    const start = MAX_FIXED_HEADER_LEN - length_of_len - 1;

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

    buf[MAX_FIXED_HEADER_LEN] = 0;
    buf[MAX_FIXED_HEADER_LEN + 1] = 4;
    buf[MAX_FIXED_HEADER_LEN + 2] = 'M';
    buf[MAX_FIXED_HEADER_LEN + 3] = 'Q';
    buf[MAX_FIXED_HEADER_LEN + 4] = 'T';
    buf[MAX_FIXED_HEADER_LEN + 5] = 'T';
    buf[MAX_FIXED_HEADER_LEN + 6] = 4;

    buf[MAX_FIXED_HEADER_LEN + 7] = @bitCast(connect_flags);

    writeInt(u16, buf[MAX_FIXED_HEADER_LEN + 8 ..][0..2], opts.keepalive_sec);

    const PAYLOAD_OFFSET = MAX_FIXED_HEADER_LEN + 10;

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
    // reserve MAX_FIXED_HEADER_LEN bytes for the fixed header
    writeInt(u16, buf[MAX_FIXED_HEADER_LEN..][0..2], packet_identifier);

    const PAYLOAD_OFFSET = MAX_FIXED_HEADER_LEN + 2;
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
    // reserve MAX_FIXED_HEADER_LEN bytes for the fixed header
    writeInt(u16, buf[MAX_FIXED_HEADER_LEN..][0..2], packet_identifier);

    const PAYLOAD_OFFSET = MAX_FIXED_HEADER_LEN + 2;
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
    // Validate topic per MQTT 3.1.1 spec
    if (opts.topic.len == 0) return error.EmptyTopic;
    if (opts.topic.len > 65535) return error.TopicTooLong;
    // PUBLISH topics must not contain wildcards
    if (std.mem.indexOfAny(u8, opts.topic, "#+")) |_| return error.InvalidTopicCharacter;

    const publish_flags = PublishFlags{
        .dup = opts.dup,
        .qos = opts.qos,
        .retain = opts.retain,
    };

    // reserve MAX_FIXED_HEADER_LEN bytes for the fixed header
    const topic_len = try writeString(buf[MAX_FIXED_HEADER_LEN..], opts.topic);

    var payload_offset = MAX_FIXED_HEADER_LEN + topic_len;
    if (packet_identifier) |pi| {
        writeInt(u16, buf[payload_offset..][0..2], pi);
        payload_offset += 2;
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
    // reserve MAX_FIXED_HEADER_LEN bytes for the fixed header
    // MQTT 3.1.1: only packet identifier (2 bytes)
    writeInt(u16, buf[MAX_FIXED_HEADER_LEN..][0..2], opts.packet_identifier);
    return encodePacketHeader(buf[0 .. MAX_FIXED_HEADER_LEN + 2], 4, 0);
}

pub fn encodePubRec(buf: []u8, opts: mqtt.PubRecOpts) ![]u8 {
    // reserve MAX_FIXED_HEADER_LEN bytes for the fixed header
    // MQTT 3.1.1: only packet identifier (2 bytes)
    writeInt(u16, buf[MAX_FIXED_HEADER_LEN..][0..2], opts.packet_identifier);
    return encodePacketHeader(buf[0 .. MAX_FIXED_HEADER_LEN + 2], 5, 0);
}

pub fn encodePubRel(buf: []u8, opts: mqtt.PubRelOpts) ![]u8 {
    // reserve MAX_FIXED_HEADER_LEN bytes for the fixed header
    // MQTT 3.1.1: only packet identifier (2 bytes), flags must be 0010
    writeInt(u16, buf[MAX_FIXED_HEADER_LEN..][0..2], opts.packet_identifier);
    return encodePacketHeader(buf[0 .. MAX_FIXED_HEADER_LEN + 2], 6, 2);
}

pub fn encodePubComp(buf: []u8, opts: mqtt.PubCompOpts) ![]u8 {
    // reserve MAX_FIXED_HEADER_LEN bytes for the fixed header
    // MQTT 3.1.1: only packet identifier (2 bytes)
    writeInt(u16, buf[MAX_FIXED_HEADER_LEN..][0..2], opts.packet_identifier);
    return encodePacketHeader(buf[0 .. MAX_FIXED_HEADER_LEN + 2], 7, 0);
}

pub fn encodeDisconnect(buf: []u8) ![]u8 {
    // In MQTT 3.1.1, DISCONNECT has no variable header (only fixed header)
    return encodePacketHeader(buf[0..MAX_FIXED_HEADER_LEN], 14, 0);
}
