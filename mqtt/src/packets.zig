const mqtt = @import("mqtt.zig");
const codec = @import("codec.zig");

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
        reason_code: ReasonCode,
        session_expiry_interval: ?u32 = null,
        receive_maximum: ?u16 = null,
        maximum_qos: ?mqtt.QoS = null,
        retain_available: ?bool = null,
        maximum_packet_size: ?u32 = null,
        assigned_client_identifier: ?[]const u8 = null,
        topic_alias_maximum: ?u16 = null,
        reason_string: ?[]const u8 = null,
        wildcard_subscription_available: ?bool = null,
        subscription_identifier_available: ?bool = null,
        shared_subscription_available: ?bool = null,
        server_keepalive: ?u16 = null,
        response_information: ?[]const u8 = null,
        server_reference: ?[]const u8 = null,
        authentication_method: ?[]const u8 = null,
        authentication_data: ?[]const u8 = null,
        _user_properties: ?[]const u8 = null,

        pub fn userProperties(_: *const ConnAck) void {
            unreachable;
        }

        pub const ReasonCode = enum(u8) {
            success = 0,
            unspecified_error = 128,
            malformed_packet = 129,
            protocol_error = 130,
            implementation_specific_error = 131,
            unsupported_protocol_version = 132,
            client_identifier_not_valid = 133,
            bad_user_name_or_password = 134,
            not_authorized = 135,
            server_unavailable = 136,
            server_busy = 137,
            banned = 138,
            bad_authentication_method = 140,
            topic_name_invalid = 144,
            packet_too_large = 149,
            quota_exceeded = 151,
            payload_format_invalid = 153,
            retain_not_supported = 154,
            qos_not_supported = 155,
            use_another_server = 156,
            server_moved = 157,
            connection_rate_exceeded = 159,
        };
    };

    pub const SubAck = struct {
        packet_identifier: u16,
        reason_string: ?[]const u8 = null,
        results: []const u8,
        _user_properties: ?[]const u8 = null,

        pub fn userProperties(_: *const SubAck) void {
            unreachable;
        }

        const Error = error{
            Protocol,
            Unspecified,
            ImplementationSpecific,
            NotAuthorized,
            TopicFilterInvalid,
            PacketIdentifierInUse,
            QuotaExceeded,
            SharedSubscriptionsNotSupported,
            SubscriptionIdentifierNotSupported,
            WildcardSubscriptionsNotSupported,
        };

        pub fn result(self: *const SubAck, topic_index: usize) SubAck.Error!mqtt.QoS {
            const results = self.results;

            switch (results[topic_index]) {
                0 => return .at_most_once,
                1 => return .at_least_once,
                2 => return .exactly_once,
                128 => return error.Unspecified,
                131 => return error.ImplementationSpecific,
                135 => return error.NotAuthorized,
                143 => return error.TopicFilterInvalid,
                145 => return error.PacketIdentifierInUse,
                151 => return error.QuotaExceeded,
                158 => return error.SharedSubscriptionsNotSupported,
                161 => return error.SubscriptionIdentifierNotSupported,
                162 => return error.WildcardSubscriptionsNotSupported,
                else => return error.Protocol,
            }
        }
    };

    pub const UnsubAck = struct {
        packet_identifier: u16,
        reason_string: ?[]const u8 = null,
        results: []const u8,
        _user_properties: ?[]const u8 = null,

        pub fn userProperties(_: *const UnsubAck) void {
            unreachable;
        }

        const Error = error{
            Protocol,
            NoSubscriptionExisted,
            Unspecified,
            ImplementationSpecific,
            NotAuthorized,
            TopicFilterInvalid,
            PacketIdentifierInUse,
        };

        pub fn result(self: *const UnsubAck, topic_index: usize) UnsubAck.Error!void {
            const results = self.results;

            switch (results[topic_index]) {
                0 => return,
                17 => return error.NoSubscriptionExisted,
                128 => return error.Unspecified,
                131 => return error.ImplementationSpecific,
                135 => return error.NotAuthorized,
                143 => return error.TopicFilterInvalid,
                145 => return error.PacketIdentifierInUse,
                else => return error.Protocol,
            }
        }
    };

    pub const Publish = struct {
        dup: bool,
        qos: mqtt.QoS,
        // not sure what this means in the context of a received message
        // maybe it's never set, or maybe it indicates that the server is publishing
        // a message which it retains?
        retain: bool,

        topic: []const u8,
        message: []const u8,
        // null when qos is .at_least_once
        packet_identifier: ?u16,

        payload_format: ?mqtt.PayloadFormat = null,
        message_expiry_interval: ?u32 = null, // does a server ever send this?
        topic_alias: ?u16 = null,
        response_topic: ?[]const u8 = null,
        correlation_data: ?[]const u8 = null,
        subscription_identifier: ?usize = null,
        content_type: ?[]const u8 = null,
        _user_properties: ?[]const u8 = null,

        pub fn userProperties(_: *const Publish) void {
            unreachable;
        }
    };

    pub const PubAck = struct {
        packet_identifier: u16,
        reason_code: mqtt.PubAckReason,
        reason_string: ?[]const u8 = null,
        _user_properties: ?[]const u8 = null,

        pub fn userProperties(_: *const PubAck) void {
            unreachable;
        }
    };

    pub const PubRec = struct {
        packet_identifier: u16,
        reason_code: mqtt.PubRecReason,
        reason_string: ?[]const u8 = null,
        _user_properties: ?[]const u8 = null,

        pub fn userProperties(_: *const PubRec) void {
            unreachable;
        }
    };

    pub const PubRel = struct {
        packet_identifier: u16,
        reason_code: mqtt.PubRelReason,
        reason_string: ?[]const u8 = null,
        _user_properties: ?[]const u8 = null,

        pub fn userProperties(_: *const PubRel) void {
            unreachable;
        }
    };

    pub const PubComp = struct {
        packet_identifier: u16,
        reason_code: mqtt.PubCompReason,
        reason_string: ?[]const u8 = null,
        _user_properties: ?[]const u8 = null,

        pub fn userProperties(_: *const PubComp) void {
            unreachable;
        }
    };

    pub const Disconnect = struct {
        reason_code: ReasonCode,
        reason_string: ?[]const u8 = null,
        // not sure this is ever set by the server
        session_expiry_interval: ?u32 = null,
        _user_properties: ?[]const u8 = null,

        pub fn userProperties(_: *const Disconnect) void {
            unreachable;
        }

        pub const ReasonCode = enum(u8) {
            normal = 0,
            unspecified_error = 128,
            malformed_packet = 129,
            protocol_error = 130,
            implementation_specific_error = 131,
            not_authorized = 135,
            server_busy = 137,
            server_shutting_down = 139,
            keepalive_timeout = 141,
            session_taken_over = 142,
            topic_filter_invalid = 143,
            topic_name_invlaid = 144,
            receive_maximum_exceeded = 147,
            topic_alias_invalid = 148,
            packet_too_large = 149,
            message_rate_too_high = 150,
            quota_exceeded = 151,
            administrative_action = 152,
            payload_format_invalid = 153,
            retain_not_supported = 154,
            qos_not_supported = 155,
            use_another_server = 156,
            server_moved = 157,
            shared_subscriptions_not_supported = 158,
            connection_rate_exceeded = 159,
            maximum_connect_time = 160,
            subscription_identifiers_not_supported = 161,
            wildcard_subscriptions_not_supported = 162,
        };
    };

    pub fn decode(b1: u8, data: []u8, comptime protocol_version: mqtt.ProtocolVersion) !Packet {
        // data.len has to be > 0
        // TODO: how to assert without std?
        const flags: u4 = @intCast(b1 & 15);
        switch (b1 >> 4) {
            2 => return .{ .connack = try decodeConnAck(data, flags, protocol_version) },
            3 => return .{ .publish = try decodePublish(data, flags, protocol_version) },
            4 => return .{ .puback = try decodePubAck(data, flags, protocol_version) },
            5 => return .{ .pubrec = try decodePubRec(data, flags, protocol_version) },
            6 => return .{ .pubrel = try decodePubRel(data, flags, protocol_version) },
            7 => return .{ .pubcomp = try decodePubComp(data, flags, protocol_version) },
            9 => return .{ .suback = try decodeSubAck(data, flags, protocol_version) },
            11 => return .{ .unsuback = try decodeUnsubAck(data, flags, protocol_version) },
            13 => return if (flags == 0) .{ .pong = {} } else error.InvalidFlags,
            14 => return .{ .disconnect = try decodeDisconnect(data, flags, protocol_version) },
            else => return error.UnknownPacketType, // TODO
        }
    }
};

pub const PartialPacket = union(enum) {
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

    pub const ConnAck = struct {};

    pub const SubAck = struct {
        packet_identifier: u16,
    };

    pub const UnsubAck = struct {
        packet_identifier: u16,
    };

    pub const Publish = struct {
        dup: bool,
        qos: mqtt.QoS,
        // not sure what this means in the context of a received message
        // maybe it's never set, or maybe it indicates that the server is publishing
        // a message which it retains?
        retain: bool,

        topic: []const u8,
        // null when qos is .at_least_once
        packet_identifier: ?u16,
    };

    pub const PubAck = struct {
        packet_identifier: u16,
    };

    pub const PubRec = struct {
        packet_identifier: u16,
    };

    pub const PubRel = struct {
        packet_identifier: u16,
    };

    pub const PubComp = struct {
        packet_identifier: u16,
    };

    pub const Disconnect = struct {};

    pub fn decode(b1: u8, data: []const u8) ?PartialPacket {
        // data.len has to be > 0
        // TODO: how to assert without std?
        const flags: u4 = @intCast(b1 & 15);
        switch (b1 >> 4) {
            2 => return .{ .connack = .{} },
            3 => return .{ .publish = decodePartialPublish(data, flags) orelse return null },
            4 => return .{ .puback = decodePartialPubAck(data, flags) orelse return null },
            5 => return .{ .pubrec = decodePartialPubRec(data, flags) orelse return null },
            6 => return .{ .pubrel = decodePartialPubRel(data, flags) orelse return null },
            7 => return .{ .pubcomp = decodePartialPubComp(data, flags) orelse return null },
            9 => return .{ .suback = decodePartialSubAck(data, flags) orelse return null },
            11 => return .{ .unsuback = decodePartialUnsubAck(data, flags) orelse return null },
            13 => if (flags == 0) return .{ .pong = {} } else return null,
            14 => return .{ .disconnect = .{} },
            else => return null, // TODO
        }
    }
};

fn decodeConnAck(data: []u8, flags: u4, comptime protocol_version: mqtt.ProtocolVersion) !Packet.ConnAck {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    const min_len: usize = if (comptime protocol_version == .mqtt_3_1_1) 2 else 3;
    if (data.len < min_len) {
        // MQTT 3.1.1: must have at least 2 bytes (ConnAck flag, Return Code)
        // MQTT 5.0: must have at least 3 bytes (ConnAck flag, Reason Code, Property Length)
        return error.IncompletePacket;
    }

    const session_present = switch (data[0]) {
        0 => false,
        1 => true,
        else => return error.MalformedPacket,
    };

    const reason_code: Packet.ConnAck.ReasonCode = switch (data[1]) {
        0 => .success,
        128 => .unspecified_error,
        129 => .malformed_packet,
        130 => .protocol_error,
        131 => .implementation_specific_error,
        132 => .unsupported_protocol_version,
        133 => .client_identifier_not_valid,
        134 => .bad_user_name_or_password,
        135 => .not_authorized,
        136 => .server_unavailable,
        137 => .server_busy,
        138 => .banned,
        140 => .bad_authentication_method,
        144 => .topic_name_invalid,
        149 => .packet_too_large,
        151 => .quota_exceeded,
        153 => .payload_format_invalid,
        154 => .retain_not_supported,
        155 => .qos_not_supported,
        156 => .use_another_server,
        157 => .server_moved,
        159 => .connection_rate_exceeded,
        else => return error.InvalidReasonCode,
    };

    const connack = Packet.ConnAck{
        .session_present = session_present,
        .reason_code = reason_code,
    };

    // MQTT 5.0: read properties
    if (comptime protocol_version == .mqtt_5_0) {
        unreachable;
    }

    return connack;
}

fn decodeSubAck(data: []u8, flags: u4, comptime protocol_version: mqtt.ProtocolVersion) !Packet.SubAck {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    const min_len: usize = if (comptime protocol_version == .mqtt_3_1_1) 3 else 4;
    if (data.len < min_len) {
        // MQTT 3.1.1: 2 for packet identifier, at least 1 for QoS byte
        // MQTT 5.0: 2 for packet identifier, at least 1 for property list, at least 1 for reason code
        return error.IncompletePacket;
    }

    var suback = Packet.SubAck{
        .packet_identifier = codec.readInt(u16, data[0..2]),
        .results = undefined,
    };

    const payload_offset: usize = 2;

    // MQTT 5.0: read properties
    if (comptime protocol_version == .mqtt_5_0) {
        unreachable;
    }

    // the rest of the packet is the payload, and the payload is 1 or more
    // 1 byte reason codes. 1 reason code per subscribed topic (in the same order)
    // So if you subscribed to 2 topics and want to know the result of the 2nd one
    // you would check suback.results[1], or better for an enum value: suback.result(1).
    suback.results = data[payload_offset..];
    return suback;
}
fn decodePartialSubAck(data: []const u8, flags: u4) ?mqtt.PartialPacket.SubAck {
    if (flags != 0) {
        return null;
    }

    if (data.len < 4) {
        // must have at least 4 bytes
        // 2 for the packet identifier
        // at least 1 for a 0-length property list
        // at least 1 for 1 reason code in the body
        return null;
    }
    return .{ .packet_identifier = codec.readInt(u16, data[0..2]) };
}

fn decodeUnsubAck(data: []u8, flags: u4, comptime protocol_version: mqtt.ProtocolVersion) !Packet.UnsubAck {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    const min_len: usize = if (comptime protocol_version == .mqtt_3_1_1) 2 else 4;
    if (data.len < min_len) {
        // MQTT 3.1.1: just 2 bytes for packet identifier (no payload)
        // MQTT 5.0: 2 for packet identifier, at least 1 for property list, at least 1 for reason code
        return error.IncompletePacket;
    }

    var unsuback = Packet.UnsubAck{
        .packet_identifier = codec.readInt(u16, data[0..2]),
        .results = undefined,
    };

    const payload_offset: usize = 2;

    // MQTT 5.0: read properties
    if (comptime protocol_version == .mqtt_5_0) {
        unreachable;
    }

    // MQTT 5.0: the rest of the packet is the payload with reason codes
    // MQTT 3.1.1: no payload (empty results)
    unsuback.results = data[payload_offset..];
    return unsuback;
}
fn decodePartialUnsubAck(data: []const u8, flags: u4) ?PartialPacket.UnsubAck {
    if (flags != 0) {
        return null;
    }

    if (data.len < 4) {
        // must have at least 4 bytes
        // 2 for the packet identifier
        // at least 1 for a 0-length property list
        // at least 1 for 1 reason code in the body
        return null;
    }
    return .{ .packet_identifier = codec.readInt(u16, data[0..2]) };
}

fn decodePublish(data: []u8, flags: u4, comptime protocol_version: mqtt.ProtocolVersion) !Packet.Publish {
    const min_len: usize = if (comptime protocol_version == .mqtt_3_1_1) 2 else 5;
    if (data.len < min_len) {
        // MQTT 3.1.1: 2 for topic length (empty topic + empty message)
        // MQTT 5.0: 2 for topic, 1 for property list, 2 for message
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
        publish.packet_identifier = codec.readInt(u16, data[packet_identifier_offset..message_offset][0..2]);
    }

    // MQTT 5.0: read properties
    if (comptime protocol_version == .mqtt_5_0) {
        unreachable;
    }

    publish.message = data[message_offset..];
    return publish;
}
fn decodePartialPublish(data: []const u8, flags: u4) ?PartialPacket.Publish {
    if (data.len < 5) {
        // must have at least 4 bytes
        // 2 for the packet identifier
        // at least 1 for a 0-length property list
        // at least 1 for 1 reason code in the body
        return null;
    }
    const publish_flags: *codec.PublishFlags = @ptrCast(@constCast(&flags));

    const topic, var properties_offset = codec.readString(data) catch {
        return null;
    };
    var publish = PartialPacket.Publish{
        .dup = publish_flags.dup,
        .qos = publish_flags.qos,
        .retain = publish_flags.retain,
        .topic = topic,
        .packet_identifier = null,
    };

    if (publish.qos != .at_most_once) {
        const packet_identifier_offset = properties_offset;
        properties_offset += 2;
        publish.packet_identifier = codec.readInt(u16, data[packet_identifier_offset..properties_offset][0..2]);
    }

    return publish;
}

fn decodePubAck(
    data: []u8,
    flags: u4,
    comptime protocol_version: mqtt.ProtocolVersion,
) !Packet.PubAck {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    if (data.len < 2) {
        return error.IncompletePacket;
    }

    const packet_identifier = codec.readInt(u16, data[0..2]);

    // MQTT 3.1.1: only packet identifier (2 bytes)
    // MQTT 5.0: can be just packet identifier if reason code is success and no properties
    if (data.len == 2 or protocol_version == .mqtt_3_1_1) {
        return .{
            .reason_code = .success,
            .packet_identifier = packet_identifier,
        };
    }

    // MQTT 5.0: has reason code and properties
    const reason_code: mqtt.PubAckReason = switch (data[2]) {
        0 => .success,
        16 => .no_matching_subscribers,
        128 => .unspecified_error,
        131 => .implementation_specific_error,
        135 => .not_authorized,
        144 => .topic_name_invalid,
        151 => .quota_exceeded,
        153 => .payload_format_invalid,
        else => return error.MalformedPacket,
    };

    const puback = Packet.PubAck{
        .packet_identifier = packet_identifier,
        .reason_code = reason_code,
    };

    return puback;
}
fn decodePartialPubAck(data: []const u8, flags: u4) ?PartialPacket.PubAck {
    if (flags != 0) {
        return null;
    }

    if (data.len < 2) {
        // must have at least 4 bytes
        // 2 for the packet identifier
        // at least 1 for a 0-length property list
        // at least 1 for 1 reason code in the body
        return null;
    }
    return .{ .packet_identifier = codec.readInt(u16, data[0..2]) };
}

fn decodePubRec(data: []u8, flags: u4, comptime protocol_version: mqtt.ProtocolVersion) !Packet.PubRec {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    if (data.len < 2) {
        return error.IncompletePacket;
    }

    const packet_identifier = codec.readInt(u16, data[0..2]);

    // MQTT 3.1.1: only packet identifier (2 bytes)
    // MQTT 5.0: can be just packet identifier if reason code is success and no properties
    if (data.len == 2 or protocol_version == .mqtt_3_1_1) {
        return .{
            .reason_code = .success,
            .packet_identifier = packet_identifier,
        };
    }

    // MQTT 5.0: has reason code and properties
    const reason_code: mqtt.PubRecReason = switch (data[2]) {
        0 => .success,
        16 => .no_matching_subscribers,
        128 => .unspecified_error,
        131 => .implementation_specific_error,
        135 => .not_authorized,
        144 => .topic_name_invalid,
        151 => .quota_exceeded,
        153 => .payload_format_invalid,
        else => return error.MalformedPacket,
    };

    const pubrec = Packet.PubRec{
        .packet_identifier = packet_identifier,
        .reason_code = reason_code,
    };

    return pubrec;
}
fn decodePartialPubRec(data: []const u8, flags: u4) ?PartialPacket.PubRec {
    if (flags != 0) {
        return null;
    }

    if (data.len < 2) {
        // must have at least 4 bytes
        // 2 for the packet identifier
        // at least 1 for a 0-length property list
        // at least 1 for 1 reason code in the body
        return null;
    }
    return .{ .packet_identifier = codec.readInt(u16, data[0..2]) };
}

fn decodePubRel(data: []u8, flags: u4, comptime protocol_version: mqtt.ProtocolVersion) !Packet.PubRel {
    if (flags != 2) {
        // what's up with this? Why does this flag have to be 2??
        return error.InvalidFlags;
    }

    if (data.len < 2) {
        return error.IncompletePacket;
    }

    const packet_identifier = codec.readInt(u16, data[0..2]);

    // MQTT 3.1.1: only packet identifier (2 bytes)
    // MQTT 5.0: can be just packet identifier if reason code is success and no properties
    if (data.len == 2 or protocol_version == .mqtt_3_1_1) {
        return .{
            .reason_code = .success,
            .packet_identifier = packet_identifier,
        };
    }

    // MQTT 5.0: has reason code and properties
    const reason_code: mqtt.PubRelReason = switch (data[2]) {
        0 => .success,
        146 => .packet_identifier_not_found,
        else => return error.MalformedPacket,
    };

    const pubrel = Packet.PubRel{
        .packet_identifier = packet_identifier,
        .reason_code = reason_code,
    };

    return pubrel;
}
fn decodePartialPubRel(data: []const u8, flags: u4) ?PartialPacket.PubRel {
    if (flags != 0) {
        return null;
    }

    if (data.len < 2) {
        // must have at least 4 bytes
        // 2 for the packet identifier
        // at least 1 for a 0-length property list
        // at least 1 for 1 reason code in the body
        return null;
    }
    return .{ .packet_identifier = codec.readInt(u16, data[0..2]) };
}

// If you've gotten this far and are thinking: does he plan on DRYing this stuff?
// The answer is [obviously]..apparently not.
fn decodePubComp(data: []u8, flags: u4, comptime protocol_version: mqtt.ProtocolVersion) !Packet.PubComp {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    if (data.len < 2) {
        return error.IncompletePacket;
    }

    const packet_identifier = codec.readInt(u16, data[0..2]);

    // MQTT 3.1.1: only packet identifier (2 bytes)
    // MQTT 5.0: can be just packet identifier if reason code is success and no properties
    if (data.len == 2 or protocol_version == .mqtt_3_1_1) {
        return .{
            .reason_code = .success,
            .packet_identifier = packet_identifier,
        };
    }

    // MQTT 5.0: has reason code and properties
    const reason_code: mqtt.PubCompReason = switch (data[2]) {
        0 => .success,
        146 => .packet_identifier_not_found,
        else => return error.MalformedPacket,
    };

    const pubcomp = Packet.PubComp{
        .packet_identifier = packet_identifier,
        .reason_code = reason_code,
    };

    return pubcomp;
}
fn decodePartialPubComp(data: []const u8, flags: u4) ?PartialPacket.PubComp {
    if (flags != 0) {
        return null;
    }

    if (data.len < 2) {
        // must have at least 4 bytes
        // 2 for the packet identifier
        // at least 1 for a 0-length property list
        // at least 1 for 1 reason code in the body
        return null;
    }
    return .{ .packet_identifier = codec.readInt(u16, data[0..2]) };
}

fn decodeDisconnect(
    data: []u8,
    flags: u4,
    comptime protocol_version: mqtt.ProtocolVersion,
) !Packet.Disconnect {
    if (flags != 0) {
        return error.InvalidFlags;
    }

    // MQTT 3.1.1: DISCONNECT has no variable header (data.len == 0)
    if (comptime protocol_version == .mqtt_3_1_1) {
        return .{ .reason_code = .normal };
    }

    // MQTT 5.0: has reason code and properties
    if (data.len < 2) {
        // 1 for reason code
        // 1 for 0 length properties
        return error.IncompletePacket;
    }

    const reason_code: Packet.Disconnect.ReasonCode = switch (data[0]) {
        0 => .normal,
        128 => .unspecified_error,
        129 => .malformed_packet,
        130 => .protocol_error,
        131 => .implementation_specific_error,
        135 => .not_authorized,
        137 => .server_busy,
        139 => .server_shutting_down,
        141 => .keepalive_timeout,
        142 => .session_taken_over,
        143 => .topic_filter_invalid,
        144 => .topic_name_invlaid,
        147 => .receive_maximum_exceeded,
        148 => .topic_alias_invalid,
        149 => .packet_too_large,
        150 => .message_rate_too_high,
        151 => .quota_exceeded,
        152 => .administrative_action,
        153 => .payload_format_invalid,
        154 => .retain_not_supported,
        155 => .qos_not_supported,
        156 => .use_another_server,
        157 => .server_moved,
        158 => .shared_subscriptions_not_supported,
        159 => .connection_rate_exceeded,
        160 => .maximum_connect_time,
        161 => .subscription_identifiers_not_supported,
        162 => .wildcard_subscriptions_not_supported,
        else => return error.InvalidReasonCode,
    };

    const disconnect = Packet.Disconnect{
        .reason_code = reason_code,
    };

    return disconnect;
}
