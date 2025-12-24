const codec = @import("codec.zig");
const mqtt = @import("mqtt.zig");

pub const Packet = union(enum) {
    connack: ConnAck,
    suback: SubAck,
    unsuback: UnsubAck,
    publish: Publish,
    puback: PubAck,
    pubrec: PubRec,
    pubrel: PubRel,
    pubcomp: PubComp,
    disconnect: Disconnect,
    pong: void,

    pub const ConnAck = struct {
        session_present: bool,
        return_code: ReturnCode,

        // MQTT 3.1.1 Return Codes
        pub const ReturnCode = enum(u8) {
            accepted = 0,
            unacceptable_protocol_version = 1,
            identifier_rejected = 2,
            server_unavailable = 3,
            bad_username_or_password = 4,
            not_authorized = 5,
        };
    };

    // MQTT 3.1.1: SUBACK contains QoS granted (0,1,2) or protocol failure
    pub const SubAck = struct {
        packet_identifier: u16,
        results: []const u8,

        const Error = error{
            Failure,
            Protocol,
        };

        pub fn result(self: *const SubAck, topic_index: usize) SubAck.Error!mqtt.QoS {
            const results = self.results;

            switch (results[topic_index]) {
                0 => return .at_most_once,
                1 => return .at_least_once,
                2 => return .exactly_once,
                else => return error.Protocol,
            }
        }
    };

    // MQTT 3.1.1: UNSUBACK is just packet identifier, no payload/results
    pub const UnsubAck = struct {
        packet_identifier: u16,
    };

    pub const Publish = struct {
        dup: bool,
        qos: mqtt.QoS,
        retain: bool,

        topic: []const u8,
        message: []const u8,
        // null when qos is .at_least_once
        packet_identifier: ?u16,
    };

    // MQTT 3.1.1: PUBACK is just packet identifier
    pub const PubAck = struct {
        packet_identifier: u16,
    };

    // MQTT 3.1.1: PUBREC is just packet identifier
    pub const PubRec = struct {
        packet_identifier: u16,
    };

    // MQTT 3.1.1: PUBREL is just packet identifier
    pub const PubRel = struct {
        packet_identifier: u16,
    };

    // MQTT 3.1.1: PUBCOMP is just packet identifier
    pub const PubComp = struct {
        packet_identifier: u16,
    };

    // MQTT 3.1.1: Server-sent DISCONNECT has no variable header
    // (In 3.1.1, servers typically just close the connection rather than sending DISCONNECT)
    pub const Disconnect = struct {};

    pub fn decode(b1: u8, data: []u8) !Packet {
        // data.len has to be > 0
        // TODO: how to assert without std?
        const flags: u4 = @intCast(b1 & 15);
        switch (b1 >> 4) {
            2 => return .{ .connack = try decodeConnAck(data, flags) },
            3 => return .{ .publish = try decodePublish(data, flags) },
            4 => return .{ .puback = try decodePubAck(data, flags) },
            5 => return .{ .pubrec = try decodePubRec(data, flags) },
            6 => return .{ .pubrel = try decodePubRel(data, flags) },
            7 => return .{ .pubcomp = try decodePubComp(data, flags) },
            9 => return .{ .suback = try decodeSubAck(data, flags) },
            11 => return .{ .unsuback = try decodeUnsubAck(data, flags) },
            13 => return if (flags == 0) .{ .pong = {} } else error.InvalidFlags,
            14 => return .{ .disconnect = try decodeDisconnect(data, flags) },
            else => return error.UnknownPacketType, // TODO
        }
    }
};

fn decodeConnAck(data: []u8, flags: u4) !Packet.ConnAck {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    // MQTT 3.1.1: must have exactly 2 bytes (Connect Acknowledge Flags, Return Code)
    if (data.len < 2) {
        return error.IncompletePacket;
    }

    const session_present = switch (data[0] & 0x01) {
        0 => false,
        1 => true,
        else => unreachable,
    };

    // MQTT 3.1.1: only bits 0 is used for session present, bits 1-7 must be 0
    if (data[0] & 0xFE != 0) {
        return error.MalformedPacket;
    }

    const return_code: Packet.ConnAck.ReturnCode = switch (data[1]) {
        0 => .accepted,
        1 => .unacceptable_protocol_version,
        2 => .identifier_rejected,
        3 => .server_unavailable,
        4 => .bad_username_or_password,
        5 => .not_authorized,
        else => return error.InvalidReasonCode,
    };

    return Packet.ConnAck{
        .session_present = session_present,
        .return_code = return_code,
    };
}

fn decodeSubAck(data: []u8, flags: u4) !Packet.SubAck {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    // MQTT 3.1.1: 2 for packet identifier, at least 1 for QoS byte
    const min_len: usize = 3;
    if (data.len < min_len) {
        return error.IncompletePacket;
    }

    var suback = Packet.SubAck{
        .packet_identifier = codec.readInt(u16, data[0..2]),
        .results = undefined,
    };

    const payload_offset: usize = 2;

    // the rest of the packet is the payload, and the payload is 1 or more
    // 1 byte reason codes. 1 reason code per subscribed topic (in the same order)
    // So if you subscribed to 2 topics and want to know the result of the 2nd one
    // you would check suback.results[1], or better for an enum value: suback.result(1).
    suback.results = data[payload_offset..];
    return suback;
}
fn decodeUnsubAck(data: []u8, flags: u4) !Packet.UnsubAck {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    // MQTT 3.1.1: just 2 bytes for packet identifier (no payload)
    if (data.len < 2) {
        return error.IncompletePacket;
    }

    return Packet.UnsubAck{
        .packet_identifier = codec.readInt(u16, data[0..2]),
    };
}
fn decodePublish(data: []u8, flags: u4) !Packet.Publish {
    // MQTT 3.1.1: 2 for topic length (empty topic + empty message)
    if (data.len < 2) {
        return error.IncompletePacket;
    }

    const publish_flags: *codec.PublishFlags = @ptrCast(@constCast(&flags));

    const topic, var message_offset = try codec.readString(data);
    var publish = Packet.Publish{
        .dup = publish_flags.dup,
        .qos = publish_flags.qos,
        .retain = publish_flags.retain,
        .topic = topic,
        .message = undefined,
        .packet_identifier = null,
    };

    if (publish.qos != .at_most_once) {
        const packet_identifier_offset = message_offset;
        message_offset += 2;
        publish.packet_identifier = codec.readInt(
            u16,
            data[packet_identifier_offset..message_offset][0..2],
        );
    }

    publish.message = data[message_offset..];
    return publish;
}
fn decodePubAck(data: []u8, flags: u4) !Packet.PubAck {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    if (data.len < 2) {
        return error.IncompletePacket;
    }

    // MQTT 3.1.1: only packet identifier (2 bytes)
    return .{
        .packet_identifier = codec.readInt(u16, data[0..2]),
    };
}

fn decodePubRec(data: []u8, flags: u4) !Packet.PubRec {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    if (data.len < 2) {
        return error.IncompletePacket;
    }

    // MQTT 3.1.1: only packet identifier (2 bytes)
    return .{
        .packet_identifier = codec.readInt(u16, data[0..2]),
    };
}
fn decodePubRel(data: []u8, flags: u4) !Packet.PubRel {
    if (flags != 2) {
        // MQTT 3.1.1 spec: PUBREL fixed header flags must be 0010
        return error.InvalidFlags;
    }

    if (data.len < 2) {
        return error.IncompletePacket;
    }

    // MQTT 3.1.1: only packet identifier (2 bytes)
    return .{
        .packet_identifier = codec.readInt(u16, data[0..2]),
    };
}

fn decodePubComp(data: []u8, flags: u4) !Packet.PubComp {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    if (data.len < 2) {
        return error.IncompletePacket;
    }

    // MQTT 3.1.1: only packet identifier (2 bytes)
    return .{
        .packet_identifier = codec.readInt(u16, data[0..2]),
    };
}

fn decodeDisconnect(_: []u8, flags: u4) !Packet.Disconnect {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    // MQTT 3.1.1: DISCONNECT has no variable header or payload
    return .{};
}
