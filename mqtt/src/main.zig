const std = @import("std");
const net = std.net;

pub fn main() !void {
    // 1. TCP connect to localhost:1883
    const stream = try net.tcpConnectToHost(std.heap.page_allocator, "localhost", 1883);
    defer stream.close();

    std.debug.print("Connected to broker\n", .{});

    // 2. Send CONNECT packet
    // Fixed header:     10 10 (CONNECT, remaining length 16)
    // Protocol name:    00 04 "MQTT"
    // Protocol level:   04 (3.1.1)
    // Connect flags:    02 (clean session)
    // Keep alive:       00 3C (60 seconds)
    // Client ID:        00 04 "zig!"
    const connect_packet = [_]u8{
        0x10, 0x10, // Fixed header (remaining length = 16)
        0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol name (6 bytes)
        0x04, // Protocol level (3.1.1) (1 byte)
        0x02, // Connect flags (clean session) (1 byte)
        0x00, 0x3C, // Keep alive (60 seconds) (2 bytes)
        0x00, 0x04, 'z', 'i', 'g', '!', // Client ID (6 bytes)
    }; // Total after fixed header: 6+1+1+2+6 = 16

    try stream.writeAll(&connect_packet);

    // 3. Read CONNACK (4 bytes expected)
    var connack: [4]u8 = undefined;
    var total_read: usize = 0;
    while (total_read < 4) {
        const n = try stream.read(connack[total_read..]);
        if (n == 0) return error.ConnectionClosed;
        total_read += n;
    }

    // Validate CONNACK: 20 02 XX RC
    if (connack[0] != 0x20 or connack[1] != 0x02) {
        std.debug.print("Invalid CONNACK header: {x:0>2} {x:0>2}\n", .{ connack[0], connack[1] });
        return error.InvalidConnack;
    }

    if (connack[3] != 0x00) {
        std.debug.print("Connection refused, code: {d}\n", .{connack[3]});
        return error.ConnectionRefused;
    }

    std.debug.print("CONNACK received, connected!\n", .{});

    // 4. Send PUBLISH packet (QoS 0)
    // Fixed header:     30 17 (PUBLISH QoS 0, remaining length 23)
    // Topic:            00 0A "test/hello"
    // Payload:          "hello world" (11 bytes, no length prefix for payload)
    const publish_packet = [_]u8{
        0x30, 0x17, // Fixed header (PUBLISH, QoS 0, remaining length 23)
        0x00, 0x0A, 't', 'e', 's', 't', '/', 'h', 'e', 'l', 'l', 'o', // Topic
        'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', // Payload
    };
    try stream.writeAll(&publish_packet);

    std.debug.print("Published 'hello world' to 'test/hello'\n", .{});

    // 5. Send DISCONNECT
    const disconnect_packet = [_]u8{ 0xE0, 0x00 };
    try stream.writeAll(&disconnect_packet);

    std.debug.print("Disconnected cleanly\n", .{});
}
