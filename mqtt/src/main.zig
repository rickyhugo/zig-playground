const std = @import("std");
const net = std.net;

const codec = @import("codec.zig");
const mqtt = @import("mqtt.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = try mqtt.Client.init(.{
        .port = 1883,
        .host = "localhost",
        .allocator = allocator,
    });
    defer {
        client.disconnect(.{ .timeout = 1000 }) catch {};
        client.deinit();
    }

    _ = try client.connect(
        .{ .timeout = 2000 },
        .{ .client_id = "hugoplanet" },
    );

    if (try client.readPacket(.{})) |packet| switch (packet) {
        .disconnect => {
            std.debug.print("server disconnected us", .{});
            return;
        },
        .connack => {
            // TODO: the connack packet can include server capabilities. We might care
            // about these to tweak how our client behaves (like, what is the maximum
            // supported QoS)
            std.debug.print("connack: hugoplanet", .{});
        },
        else => {
            // The server should not send any other type of packet at this point
            // HOWEVER, we should probably handle this case better than an `unreachable`
        },
    };

    var buf: [50]u8 = undefined;
    for (5000..5003) |i| {
        _ = try client.publish(
            .{},
            .{ .topic = "test/hello", .message = try std.fmt.bufPrint(&buf, "over {d}!", .{i}) },
        );

        std.Thread.sleep(std.time.ns_per_s);
    }

    {
        const packet_identifier = try client.subscribe(
            .{},
            .{ .topics = &.{.{ .filter = "test/receiver", .qos = .at_least_once }} },
        );

        if (try client.readPacket(.{})) |packet| switch (packet) {
            .disconnect => {
                std.debug.print("server disconnected us", .{});
                return;
            },
            .suback => |s| {
                std.debug.assert(s.packet_identifier == packet_identifier);
            },
            else => {
                // The server should not send any other type of packet at this point
                // HOWEVER, we should probably handle this case better than an `unreachable`
                unreachable;
            },
        };

        var count: usize = 0;
        loop: while (true) {
            const packet = try client.readPacket(.{ .timeout = 1000 }) orelse {
                std.debug.print("Still waiting for messages...\n", .{});
                continue :loop;
            };

            switch (packet) {
                .publish => |*publish| {
                    try client.puback(.{}, .{ .packet_identifier = publish.packet_identifier.? });

                    std.debug.print("received\ntopic: {s}\n{s}\n\n", .{ publish.topic, publish.message });
                    count += 1;
                    if (count == 2) {
                        return;
                    }
                },
                else => {
                    // always have to be mindful of the bi-directional nature of MQTT
                    // but in this case, nothing here should be possible.
                    // client.readPacket handles `disconnect` and our above connect and
                    // subscribe should have handled their corresponing connack and suback
                    std.debug.print("unexpected packet: {any}\n", .{packet});
                },
            }
        }
    }
}
