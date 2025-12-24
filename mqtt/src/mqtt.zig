const std = @import("std");
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;

const codec = @import("codec.zig");
const Packet = @import("packets.zig").Packet;

pub const QoS = enum(u2) {
    at_most_once = 0,
    at_least_once = 1,
    exactly_once = 2,
};

pub const ConnectOpts = struct {
    client_id: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    will: ?Will = null,
    keepalive_sec: u16 = 0,

    pub const Will = struct {
        topic: []const u8,
        message: []const u8,
        qos: QoS,
        retain: bool,
    };
};

pub const SubscribeOpts = struct {
    packet_identifier: ?u16 = null,
    topics: []const Topic,

    pub const Topic = struct {
        filter: []const u8,
        qos: QoS = .at_most_once,
    };
};

pub const UnsubscribeOpts = struct {
    packet_identifier: ?u16 = null,
    topics: []const []const u8,
};

pub const PublishOpts = struct {
    topic: []const u8,
    message: []const u8,
    dup: bool = false,
    qos: QoS = .at_most_once,
    retain: bool = false,
    packet_identifier: ?u16 = null,
};

pub const PubAckOpts = struct {
    packet_identifier: u16,
};

pub const PubRecOpts = struct {
    packet_identifier: u16,
};

pub const PubRelOpts = struct {
    packet_identifier: u16,
};

pub const PubCompOpts = struct {
    packet_identifier: u16,
};

pub const ErrorDetail = union(enum) {
    inner: anyerror,
    details: []const u8,
};

const Address = struct {
    host: ?Host = null,
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

pub const Client = struct {
    // Our own wrapper around std.net.Address. Handles connect timeout and can
    // pickup DNS changes on reconnect.
    address: Address,

    read_pos: usize,
    read_len: usize,

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

    // Many packets take an identifier, we increment this by one on each call
    packet_identifier: u16,

    last_error: ?ErrorDetail,

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
            .read_pos = 0,
            .read_len = 0,
            .read_buf_own = read_buf_own,
            .read_buf = read_buf.?,
            .write_buf_own = write_buf_own,
            .write_buf = write_buf.?,
            .connect_timeout = opts.connect_timeout,
            .default_retries = opts.default_retries orelse 1,
            .default_timeout = opts.default_timeout orelse 5_000,
            .packet_identifier = 0,
            .last_error = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.close();

        if (self.read_buf_own) {
            self.allocator.?.free(self.read_buf);
        }

        if (self.write_buf_own) {
            self.allocator.?.free(self.write_buf);
        }
    }

    pub fn connect(self: *Self, rw: ReadWriteOpts, opts: ConnectOpts) !void {
        const connect_packet = try codec.encodeConnect(self.write_buf, opts);
        try self.write(&self.createContext(rw), connect_packet);
    }

    pub fn subscribe(self: *Self, rw: ReadWriteOpts, opts: SubscribeOpts) !u16 {
        if (opts.topics.len == 0) {
            self.last_error = .{ .details = "must have at least 1 topic" };
            return error.Usage;
        }

        const packet_identifier = self.packetIdentifier(opts.packet_identifier);
        const subscribe_packet = try codec.encodeSubscribe(
            self.write_buf,
            packet_identifier,
            opts,
        );
        try self.write(&self.createContext(rw), subscribe_packet);
        return packet_identifier;
    }

    pub fn unsubscribe(self: *Self, rw: ReadWriteOpts, opts: UnsubscribeOpts) !u16 {
        if (opts.topics.len == 0) {
            self.last_error = .{ .details = "must have at least 1 topic" };
            return error.Usage;
        }

        const packet_identifier = self.packetIdentifier(opts.packet_identifier);
        const unsubscribe_packet = try codec.encodeUnsubscribe(
            self.write_buf,
            packet_identifier,
            opts,
        );
        try self.write(&self.createContext(rw), unsubscribe_packet);
        return packet_identifier;
    }

    pub fn publish(self: *Self, rw: ReadWriteOpts, opts: PublishOpts) !?u16 {
        var packet_identifier: ?u16 = null;
        if (opts.qos != .at_most_once) {
            // when QoS > 0, we include a packet identifier
            packet_identifier = self.packetIdentifier(opts.packet_identifier);
        }

        const publish_packet = try codec.encodePublish(
            self.write_buf,
            packet_identifier,
            opts,
        );

        try self.write(&self.createContext(rw), publish_packet);
        return packet_identifier;
    }

    pub fn puback(self: *Self, rw: ReadWriteOpts, opts: PubAckOpts) !void {
        const puback_packet = try codec.encodePubAck(self.write_buf, opts);
        try self.write(&self.createContext(rw), puback_packet);
    }

    pub fn pubrec(self: *Self, rw: ReadWriteOpts, opts: PubRecOpts) !void {
        const pubrec_packet = try codec.encodePubRec(self.write_buf, opts);
        try self.write(&self.createContext(rw), pubrec_packet);
    }

    pub fn pubrel(self: *Self, rw: ReadWriteOpts, opts: PubRelOpts) !void {
        const pubrel_packet = try codec.encodePubRel(self.write_buf, opts);
        try self.write(&self.createContext(rw), pubrel_packet);
    }

    pub fn pubcomp(self: *Self, rw: ReadWriteOpts, opts: PubCompOpts) !void {
        const pubcomp_packet = try codec.encodePubComp(self.write_buf, opts);
        try self.write(&self.createContext(rw), pubcomp_packet);
    }

    pub fn ping(self: *Self, rw: ReadWriteOpts) !void {
        try self.write(&self.createContext(rw), &.{ 192, 0 });
    }

    pub fn disconnect(self: *Self, rw: ReadWriteOpts) !void {
        if (self.socket == null) {
            return;
        }

        // copy so we can mutate
        var rw_copy = rw;
        if (rw.retries == null) {
            // unless a retry is explicit set, let's override the default, since we
            // don't want to reconnect just to disconnect.
            rw_copy.retries = 0;
        }

        defer self.close();

        const disconnect_packet = try codec.encodeDisconnect(self.write_buf);
        return self.write(&self.createContext(rw_copy), disconnect_packet);
    }

    pub fn lastError(self: *const Self) ?ErrorDetail {
        return self.last_error;
    }

    pub fn lastReadPacket(self: *const Self) []const u8 {
        return self.read_buf[0..self.read_pos];
    }

    fn close(self: *Self) void {
        if (self.socket) |socket| {
            posix.close(socket);
            self.socket = null;
        }
    }

    const Context = struct {
        retries: u16 = 1,
        timeout: i32 = 10_000,
    };

    fn packetIdentifier(self: *Self, explicit: ?u16) u16 {
        if (explicit) |pi| {
            return pi;
        }
        const pi = self.packet_identifier +% 1;
        self.packet_identifier = pi;
        return pi;
    }

    fn createContext(self: *Self, rw: ReadWriteOpts) Context {
        return .{
            .retries = rw.retries orelse self.default_retries,
            .timeout = rw.timeout orelse self.default_timeout,
        };
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

    pub fn readPacket(self: *Self, rw: ReadWriteOpts) !?Packet {
        var ctx = self.createContext(rw);

        const p = (try self.readOrBuffered(&ctx)) orelse return null;
        switch (p) {
            .connack => |*connack| try self.processConnack(&ctx, connack),
            else => {},
        }
        return p;
    }

    fn processConnack(
        self: *Self,
        ctx: *Context,
        connack: *const Packet.ConnAck,
    ) !void {
        // Check if connection was rejected
        if (connack.return_code != .accepted) {
            self.close();

            self.last_error = .{
                .details = switch (connack.return_code) {
                    .accepted => unreachable,
                    .unacceptable_protocol_version => "connection refused: unacceptable protocol version",
                    .identifier_rejected => "connection refused: client identifier rejected",
                    .server_unavailable => "connection refused: server unavailable",
                    .bad_username_or_password => "connection refused: bad username or password",
                    .not_authorized => "connection refused: not authorized",
                },
            };

            return error.ConnectionRefused;
        }

        // In MQTT 3.1.1, we always request clean_session=true, so session_present
        // should always be false. If it's true, that's a protocol error.
        if (connack.session_present) {
            self.disconnect(.{ .retries = ctx.retries, .timeout = ctx.timeout }) catch {};

            self.last_error = .{
                .details = "connack indicated the presence of a session despite requesting clean_session",
            };

            return error.Protocol;
        }
    }

    fn readOrBuffered(self: *Self, ctx: *Context) !?Packet {
        if (try self.bufferedPacket()) |buffered_packet| {
            return buffered_packet;
        }

        var buf = self.read_buf;
        var pos = self.read_len;

        if (pos > 0 and pos == self.read_pos) {
            // optimize, our last readPacket read exactly 1 packet
            // we can reset all our indexes to 0 so that we have the full buffer
            // available
            pos = 0;
            self.read_pos = 0;
            self.read_len = 0;
        }

        while (true) {
            if (pos == buf.len) {
                const read_pos = self.read_pos;
                // we have no more space in our buffer ...
                if (read_pos == 0) {
                    // ... and we started reading this packet from the start of our
                    // buffer, so we really have no more space
                    return error.ReadBufferIsFull;
                }

                // ... and we didn't start reading this message from the start of our
                // buffer, so if we move things around, we'll have new free space.

                // std.mem.copyForward. can't use @memcpy because these potentially overlap
                pos = self.read_len - read_pos;
                for (buf[0..pos], buf[read_pos..]) |*d, s| {
                    d.* = s;
                }
                self.read_pos = 0;
                self.read_len = pos;
            }

            const n = (try self.read(ctx, buf[pos..])) orelse return null;
            if (n == 0) {
                return error.Closed;
            }

            pos += n;
            self.read_len += n;

            // bufferedPacket() will set read_pos
            if (try self.bufferedPacket()) |p| {
                return p;
            }
        }
    }

    // see if we have a full packet in our read_buf already
    fn bufferedPacket(self: *Self) !?Packet {
        const buf = self.read_buf[self.read_pos..self.read_len];

        // always has to be at least 2 bytes
        // 1 for the packet type and at least 1 for the length.
        if (buf.len < 2) {
            return null;
        }

        const remaining_len, const length_of_len = codec.readVarint(
            buf[1..],
        ) catch |err| switch (err) {
            error.InvalidVarint => {
                self.last_error = .{ .inner = err };
                return error.MalformedPacket;
            },
        } orelse return null;

        // +1 for the packet type
        const fixed_header_len = 1 + length_of_len;

        const total_len = fixed_header_len + remaining_len;
        if (buf.len < total_len) {
            // don't have a full packet yet
            return null;
        }

        self.read_pos += total_len;
        return Packet.decode(buf[0], buf[fixed_header_len..total_len]) catch |err| {
            self.last_error = .{ .inner = err };
            switch (err) {
                error.UnknownPacketType => return error.Protocol,
                error.InvalidReasonCode => return error.Protocol,
                else => return error.MalformedPacket,
            }
        };
    }

    fn read(self: *Self, ctx: *const Context, buf: []u8) !?usize {
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

                        var fds = [1]posix.pollfd{.{
                            .fd = socket,
                            .events = posix.POLL.IN,
                            .revents = 0,
                        }};

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

    fn write(self: *Self, ctx: *const Context, data: []const u8) !void {
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
                    const timeout: i32 = @intCast(absolute_timeout - std.time.milliTimestamp());
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
