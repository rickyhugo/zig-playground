const std = @import("std");
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;

const codec = @import("codec.zig");

pub const ProtocolVersion = union(enum) {
    mqtt_5_0: void,
    mqtt_3_1_1: void,

    pub fn byte(self: ProtocolVersion) u8 {
        return switch (self) {
            .mqtt_3_1_1 => 4,
            .mqtt_5_0 => 5,
        };
    }
};

pub const QoS = enum(u2) {
    at_most_once = 0,
    at_least_once = 1,
    exactly_once = 2,
};

pub const UserProperty = struct {
    key: []const u8,
    value: []const u8,
};

pub const PayloadFormat = enum(u1) {
    unspecified = 0,
    utf8 = 1,
};

pub const ConnectOpts = struct {
    client_id: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    will: ?Will = null,
    keepalive_sec: u16 = 0,
    session_expiry_interval: ?u32 = null,
    receive_maximum: ?u16 = null,
    maximum_packet_size: ?u32 = null,
    user_properties: ?[]const UserProperty = null,

    pub const Will = struct {
        topic: []const u8,
        message: []const u8,
        qos: QoS,
        retain: bool,
        delay_interval: ?u32 = null,
        payload_format: ?PayloadFormat = null,
        message_expiry_interval: ?u32 = null,
        content_type: ?[]const u8 = null,
        response_topic: ?[]const u8 = null,
        correlation_data: ?[]const u8 = null,
    };
};

const Address = struct {
    // null when we're given an ip:port.
    host: ?Host = null,

    // initially null when we're given a host:port
    address: ?net.Address = null,

    const Host = struct {
        port: u16,
        name: []const u8,
    };

    fn init(
        optional_host: ?[]const u8,
        optional_ip: ?[]const u8,
        port: u16,
    ) !Address {
        if (optional_ip) |ip| {
            return .{
                // setting a future resolved means, on connect/reconnect we won't try to
                .address = try std.net.Address.parseIp(ip, port),
            };
        }

        const host = optional_host orelse return error.HostOrIPRequired;
        return .{ .host = .{ .name = host, .port = port } };
    }

    fn connect(
        self: *Address,
        allocator: ?Allocator,
        timeout: i32,
    ) !posix.socket_t {
        if (self.address) |addr| {
            // we were given an ip:port, so the address is fixed
            return connectTo(addr, timeout);
        }

        // If we don't have an address, then we were given a host:ip.
        // The address can change (DNS can be updated), and there can be multiple
        // IPs, hence why we don't convert host:ip -> net.Address in init.
        const host = self.host.?;
        const list = try net.getAddressList(allocator.?, host.name, host.port);
        defer list.deinit();

        if (list.addrs.len == 0) {
            return error.UnknownHostName;
        }

        for (list.addrs) |addr| {
            return connectTo(addr, timeout) catch continue;
        }

        return posix.ConnectError.ConnectionRefused;
    }

    fn connectTo(addr: net.Address, timeout: i32) !posix.socket_t {
        const sock_flags =
            posix.SOCK.STREAM |
            posix.SOCK.NONBLOCK |
            posix.SOCK.CLOEXEC;

        const socket = try posix.socket(
            addr.any.family,
            sock_flags,
            posix.IPPROTO.TCP,
        );
        errdefer posix.close(socket);

        posix.connect(
            socket,
            &addr.any,
            addr.getOsSockLen(),
        ) catch |err| switch (err) {
            error.WouldBlock => {
                var fds = [1]posix.pollfd{.{
                    .fd = socket,
                    .events = posix.POLL.OUT,
                    .revents = 0,
                }};
                if (try posix.poll(&fds, timeout) == 0) {
                    return error.Timeout;
                }

                if (fds[0].revents & posix.POLL.OUT != posix.POLL.OUT) {
                    return error.ConnectionRefused;
                }

                // if this returns void, then we've successfully connected
                try posix.getsockoptError(socket);
            },
            else => return err,
        };

        return socket;
    }
};

pub const Client311 = Client(.mqtt_3_1_1);
pub const Client5 = Client(.mqtt_5_0);

pub fn Client(comptime protocol_version: ProtocolVersion) type {
    return struct {
        // Our own wrapper around std.net.Address. Handles connect timeout and can
        // pickup DNS changes on reconnect.
        address: Address,

        // if we own the read_buffer, it's our job to free it on deinit
        read_buf_own: bool,
        read_buf: []u8,

        // if we own the write_buffer, it's our job to free it on deinit
        write_buf_own: bool,
        write_buf: []u8,

        allocator: ?Allocator,

        connect_timeout: i32,

        // set when connect is called, can be unset on error
        // (indicating that we need to reconnect)
        socket: ?posix.socket_t,

        default_retries: u16,
        default_timeout: i32,

        pub const Opts = struct {
            port: u16,

            // either ip or host must be provided
            ip: ?[]const u8 = null,
            host: ?[]const u8 = null,

            connect_timeout: i32 = 10_000,
            default_retries: ?u16 = null,
            default_timeout: ?i32 = null,

            // required if host != null OR read_buffer == null OR write_buffer == null
            allocator: ?Allocator = null,

            // if null, we'll use allocator to create a buffer of read_buffer_size
            read_buf: ?[]u8 = null,
            read_buf_size: u16 = 8192,

            // if null, we'll use allocator to create a buffer of read_buffer_size
            write_buf: ?[]u8 = null,
            write_buf_size: u16 = 8192,
        };

        const ReadWriteOpts = struct {
            retries: ?u16 = null,
            timeout: ?i32 = null,
        };

        const Self = @This();

        pub fn init(opts: Opts) !Self {
            const allocator = opts.allocator;

            if (allocator == null and (opts.ip == null or opts.read_buf == null or opts.write_buf == null)) {
                return error.AllocatorRequired;
            }

            var read_buf_own = false;
            var read_buf = opts.read_buf;
            if (read_buf == null) {
                read_buf_own = true;
                read_buf = try allocator.?.alloc(u8, opts.read_buf_size);
            }
            errdefer if (read_buf_own) allocator.?.free(read_buf.?);

            var write_buf_own = false;
            var write_buf = opts.write_buf;
            if (write_buf == null) {
                write_buf_own = true;
                write_buf = try allocator.?.alloc(u8, opts.write_buf_size);
            }
            errdefer if (write_buf_own) allocator.?.free(write_buf.?);

            const address = try Address.init(opts.host, opts.ip, opts.port);

            return .{
                .socket = null,
                .address = address,
                .allocator = allocator,
                .read_buf_own = read_buf_own,
                .read_buf = read_buf.?,
                .write_buf_own = write_buf_own,
                .write_buf = write_buf.?,
                .connect_timeout = opts.connect_timeout,
                .default_retries = opts.default_retries orelse 1,
                .default_timeout = opts.default_timeout orelse 5_000,
            };
        }

        fn close(self: *Self) void {
            if (self.socket) |socket| {
                posix.close(socket);
                self.socket = null;
            }
        }

        pub fn deinit(self: *Self) void {
            self.close();

            const allocator = self.allocator;
            if (self.read_buf_own) {
                allocator.?.free(self.mqtt.read_buf);
            }

            if (self.write_buf_own) {
                allocator.?.free(self.mqtt.write_buf);
            }
        }

        const Context = struct {
            retries: u16 = 1,
            timeout: i32 = 10_000,
        };

        fn createContext(self: *Self, rw: ReadWriteOpts) Context {
            return .{
                .retries = rw.retries orelse self.default_retries,
                .timeout = rw.timeout orelse self.default_timeout,
            };
        }

        pub fn connect(self: *Self, rw: ReadWriteOpts, opts: ConnectOpts) !void {
            const connect_packet = try codec.encodeConnect(
                protocol_version,
                self.write_buf,
                opts,
            );

            try self.writePacket(&self.createContext(rw), connect_packet);
        }

        fn getOrConnectSocket(self: *Self) !posix.socket_t {
            return self.socket orelse {
                const socket = try self.address.connect(
                    self.allocator,
                    self.connect_timeout,
                );
                self.socket = socket;
                return socket;
            };
        }

        fn handleError(self: *Self, retries: *u16) !posix.socket_t {
            self.close();

            const r = retries.*;
            if (r == 0) {
                return error.Closed;
            }

            const socket = try self.getOrConnectSocket();
            retries.* = r - 1;
            return socket;
        }

        pub fn readPacket(self: *Self, ctx: *const Context, buf: []u8, _: usize) !?usize {
            const absolute_timeout = std.time.milliTimestamp() + ctx.timeout;

            // on disconnect, the number of times that we'll try to reconnect and
            // continue. This counts downwards to 0.
            var retries = ctx.retries;

            // If retries > 0 and we detect a disconnect, we'll attempt to reload the
            // socket (hence socket is var, not const).
            var socket = try self.getOrConnectSocket();
            loop: while (true) {
                const n = posix.read(socket, buf) catch |err| {
                    switch (err) {
                        error.BrokenPipe, error.ConnectionResetByPeer => {
                            socket = try self.handleError(&retries);
                            continue :loop;
                        },
                        error.WouldBlock => {
                            const timeout: i32 = @intCast(absolute_timeout - std.time.milliTimestamp());
                            if (timeout < 0) {
                                return null;
                            }

                            var fds = [1]posix.pollfd{.{ .fd = socket, .events = posix.POLL.IN, .revents = 0 }};
                            if (try posix.poll(&fds, timeout) == 0) {
                                return null;
                            }

                            if (fds[0].revents & posix.POLL.IN != posix.POLL.IN) {
                                // handle any other non-POLLOUT event as an error
                                socket = try self.handleError(&retries);
                            }

                            // Either poll has told us we can read without blocking OR
                            // poll told us there was a error, but retries > 0 and we managed
                            // to reconnect. Either way, we're gonna try to read again.
                            continue :loop;
                        },
                        else => {
                            self.close();
                            return err;
                        },
                    }
                };

                if (n != 0) {
                    return n;
                }

                socket = try self.handleError(&retries);
            }
        }

        pub fn writePacket(self: *Self, ctx: *const Context, data: []const u8) !void {
            const absolute_timeout = std.time.milliTimestamp() + ctx.timeout;

            // on disconnect, the number of times that we'll try to reconnect and
            // continue. This counts downwards to 0.
            var retries = ctx.retries;

            // If retries > 0 and we detect a disconnect, we'll attempt to reload the
            // socket (hence socket is var, not const).
            var socket = try self.getOrConnectSocket();

            // position in data that we've written to so far (or, put differently,
            // positition in data that our next write starts at)
            var pos: usize = 0;

            loop: while (pos < data.len) {
                pos += posix.write(socket, data[pos..]) catch |err| switch (err) {
                    error.WouldBlock => {
                        const timeout: i32 = @intCast(std.time.milliTimestamp() - absolute_timeout);
                        if (timeout < 0) {
                            return error.Timeout;
                        }

                        var fds = [1]posix.pollfd{.{
                            .fd = socket,
                            .events = posix.POLL.OUT,
                            .revents = 0,
                        }};
                        if (try posix.poll(&fds, timeout) == 0) {
                            return error.Timeout;
                        }

                        const revents = fds[0].revents;
                        if (revents & posix.POLL.OUT != posix.POLL.OUT) {
                            // handle any other non-POLLOUT event as an error
                            socket = try self.handleError(&retries);
                        }

                        // Either poll has told us we can write without blocking OR
                        // poll told us there was a error, but retries > 0 and we managed
                        // to reconnect. Either way, we're gonna try to write again.
                        continue :loop;
                    },
                    error.BrokenPipe, error.ConnectionResetByPeer => {
                        socket = try self.handleError(&retries);
                        continue :loop;
                    },
                    else => {
                        self.close();
                        return err;
                    },
                };
            }
        }
    };
}
