const std = @import("std");
const net = std.net;

const codec = @import("codec.zig");
const mqtt = @import("mqtt.zig");

pub fn main() !void {
    // 1. TCP connect to localhost:1883

    const stream = try net.tcpConnectToHost(std.heap.page_allocator, "localhost", 1883);
    defer stream.close();

    std.debug.print("Connected to broker\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const write_buf_size: u16 = 8192;
    const write_buf = try allocator.alloc(u8, write_buf_size);
    defer allocator.free(write_buf);

    // const connect_packet = try codec.encodeConnect(
    //     .mqtt_3_1_1,
    //     write_buf,
    //     .{ .client_id = "hugoplanet" },
    // );
    //
    // try stream.writeAll(connect_packet);

    var client = try mqtt.Client311.init(.{
        .port = 1883,
        .host = "localhost",
        // It IS possible to use the posix client without an allocator, see readme
        .allocator = allocator,
    });

    _ = try client.connect(
        .{ .timeout = 2000 },
        .{ .client_id = "my client" },
    );

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
