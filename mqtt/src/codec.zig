const builtin = @import("builtin");

const mqtt = @import("mqtt.zig");

const native_endian = builtin.cpu.arch.endian();

pub inline fn writeInt(
    comptime T: type,
    buf: *[@divExact(@typeInfo(T).int.bits, 8)]u8,
    value: T,
) void {
    buf.* = @bitCast(if (native_endian == .big) value else @byteSwap(value));
}

pub fn writeString(buf: []u8, value: []const u8) error{WriteBufferIsFull}!usize {
    const total = value.len + 2;
    if (buf.len < total) {
        return error.WriteBufferIsFull;
    }

    writeInt(u16, buf[0..2], @intCast(value.len));
    @memcpy(buf[2..total], value);
    return total;
}

pub const WriteVarintError = error{
    WriteBufferFull,
    ValueTooLarge,
};

pub fn writeVarint(buf: []u8, len: usize) WriteVarintError!usize {
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

pub fn calcLengthOfVarint(len: usize) usize {
    return switch (len) {
        0...127 => 1,
        128...16_383 => 2,
        16_384...2_097_151 => 3,
        2_097_152...268_435_455 => 4,
        else => unreachable,
    };
}

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

pub fn encodeConnect(
    comptime protocol_version: mqtt.ProtocolVersion,
    buf: []u8,
    opts: mqtt.ConnectOpts,
) ![]u8 {
    if (comptime protocol_version == .mqtt_3_1_1) {
        try validateConnectOptsFor311(opts);
    }

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
    buf[11] = protocol_version.byte();

    buf[12] = @bitCast(connect_flags);

    writeInt(u16, buf[13..15], opts.keepalive_sec);

    const PROPERTIES_OFFSET = 15;

    const properties_len = if (comptime protocol_version == .mqtt_5_0)
        // TODO: enable v5 later
        unreachable
    else
        0; // MQTT 3.1.1 has no properties

    var pos: usize = PROPERTIES_OFFSET + properties_len;
    pos += try writeString(buf[pos..], opts.client_id orelse "");

    if (opts.will) |will| {
        pos += if (comptime protocol_version == .mqtt_5_0)
            // TODO: enable v5 later
            unreachable
        else
            0; // MQTT 3.1.1 has no will properties
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

pub const Mqtt311Error = error{
    UnsupportedPropertyForMqtt311,
};

fn validateConnectOptsFor311(opts: mqtt.ConnectOpts) Mqtt311Error!void {
    if (opts.session_expiry_interval != null) return error.UnsupportedPropertyForMqtt311;
    if (opts.receive_maximum != null) return error.UnsupportedPropertyForMqtt311;
    if (opts.maximum_packet_size != null) return error.UnsupportedPropertyForMqtt311;
    if (opts.user_properties != null) return error.UnsupportedPropertyForMqtt311;

    if (opts.will) |will| {
        if (will.delay_interval != null) return error.UnsupportedPropertyForMqtt311;
        if (will.payload_format != null) return error.UnsupportedPropertyForMqtt311;
        if (will.message_expiry_interval != null) return error.UnsupportedPropertyForMqtt311;
        if (will.content_type != null) return error.UnsupportedPropertyForMqtt311;
        if (will.response_topic != null) return error.UnsupportedPropertyForMqtt311;
        if (will.correlation_data != null) return error.UnsupportedPropertyForMqtt311;
    }
}
