# MQTT 3.1.1 Client for Zig

A minimal, production-grade MQTT 3.1.1 client with non-blocking I/O.

## Implementation Roadmap

### Phase 1: Core Protocol (Codec)

- [ ] **Varint encoding/decoding** - Remaining length field (1-4 bytes)
- [ ] **String encoding/decoding** - 2-byte big-endian length prefix + UTF-8 data
- [ ] **U16 big-endian helpers** - For packet identifiers, keep-alive, etc.

### Phase 2: Packet Building

- [ ] **CONNECT packet**
  - [ ] Protocol name ("MQTT") and level (4)
  - [ ] Connect flags (clean session, will, username, password)
  - [ ] Keep-alive interval
  - [ ] Client ID (required in 3.1.1)
  - [ ] Optional: Will topic/message
  - [ ] Optional: Username/password

- [ ] **PUBLISH packet**
  - [ ] QoS 0 (fire and forget)
  - [ ] QoS 1 (at least once, needs PUBACK)
  - [ ] QoS 2 (exactly once, needs PUBREC/PUBREL/PUBCOMP)
  - [ ] Retain flag
  - [ ] DUP flag (for redelivery)
  - [ ] Packet identifier (QoS > 0 only)

- [ ] **SUBSCRIBE packet**
  - [ ] Multiple topic filters in single packet
  - [ ] QoS per topic
  - [ ] Packet identifier

- [ ] **UNSUBSCRIBE packet**
  - [ ] Multiple topic filters
  - [ ] Packet identifier

- [ ] **PUBACK/PUBREC/PUBREL/PUBCOMP packets** - QoS 1/2 acknowledgments
- [ ] **PINGREQ packet** - Keep-alive
- [ ] **DISCONNECT packet** - Clean shutdown

### Phase 3: Packet Parsing

- [ ] **Fixed header parsing** - Packet type, flags, remaining length
- [ ] **CONNACK parsing** - Session present flag, return code
- [ ] **PUBLISH parsing** - Topic, QoS, packet ID, payload
- [ ] **PUBACK/PUBREC/PUBREL/PUBCOMP parsing** - Packet identifier
- [ ] **SUBACK parsing** - Packet identifier, granted QoS per topic
- [ ] **UNSUBACK parsing** - Packet identifier
- [ ] **PINGRESP parsing** - (empty payload)

### Phase 4: Client Structure

- [ ] **Client state struct**
  - [ ] Socket handle
  - [ ] Read/write buffers (user-provided or allocated)
  - [ ] Current read position and length (for partial packets)
  - [ ] Packet identifier counter (auto-increment, wrapping)
  - [ ] Connection state (disconnected, connecting, connected)

- [ ] **Configuration options**
  - [ ] Host/IP and port
  - [ ] Client ID
  - [ ] Keep-alive interval
  - [ ] Username/password (optional)
  - [ ] Will message (optional)
  - [ ] Buffer sizes

### Phase 5: Non-Blocking I/O

- [ ] **Non-blocking socket setup** - `SOCK.NONBLOCK` flag
- [ ] **Poll-based waiting** - `std.posix.poll()` for read/write readiness
- [ ] **Connect with timeout** - Non-blocking connect + poll
- [ ] **Read with timeout** - Return `null` on timeout instead of blocking
- [ ] **Write with timeout** - Return error on timeout
- [ ] **Partial read handling** - Buffer management for incomplete packets
- [ ] **Partial write handling** - Track position, retry remaining bytes

### Phase 6: Connection Management

- [ ] **Connect flow** - TCP connect -> CONNECT -> wait CONNACK -> validate
- [ ] **Disconnect flow** - Send DISCONNECT -> close socket
- [ ] **Keep-alive** - Track last activity, send PINGREQ when needed
- [ ] **Reconnection logic** (optional)
  - [ ] Configurable retry count
  - [ ] Backoff strategy
  - [ ] Re-resolve DNS on reconnect

### Phase 7: QoS Handling

- [ ] **QoS 0** - Fire and forget (no tracking needed)
- [ ] **QoS 1 outbound** - Track pending PUBLISHes, match PUBACKs by packet ID
- [ ] **QoS 1 inbound** - Send PUBACK for received messages
- [ ] **QoS 2 outbound** - PUBLISH -> PUBREC -> PUBREL -> PUBCOMP state machine
- [ ] **QoS 2 inbound** - PUBLISH -> PUBREC -> PUBREL -> PUBCOMP handling
- [ ] **Retry on timeout** - Resend unacknowledged packets with DUP flag

### Phase 8: Error Handling

- [ ] **Error types**
  - [ ] `ConnectionClosed` - Peer closed connection
  - [ ] `Timeout` - Operation timed out
  - [ ] `ProtocolError` - Invalid packet from server
  - [ ] `BufferFull` - Read/write buffer exhausted
  - [ ] `ConnectionRefused` - CONNACK with non-zero return code

- [ ] **CONNACK return codes**
  - [ ] 0 = Accepted
  - [ ] 1 = Unacceptable protocol version
  - [ ] 2 = Identifier rejected
  - [ ] 3 = Server unavailable
  - [ ] 4 = Bad username/password
  - [ ] 5 = Not authorized

- [ ] **Detailed error context** - Store last error details for debugging

### Phase 9: API Design

- [ ] **init/deinit** - Create and destroy client
- [ ] **connect(opts)** - Establish MQTT connection
- [ ] **disconnect()** - Clean shutdown
- [ ] **publish(topic, message, opts)** - Send message
- [ ] **subscribe(topics)** - Subscribe to topic filters
- [ ] **unsubscribe(topics)** - Unsubscribe from topics
- [ ] **readPacket()** - Read next packet (non-blocking, returns null on timeout)
- [ ] **ping()** - Send PINGREQ manually

### Phase 10: Testing

- [ ] **Unit tests for codec** - Varint, string, packet encoding/decoding
- [ ] **Unit tests for packet parsing** - All packet types, edge cases
- [ ] **Integration tests** - Against local Mosquitto broker
- [ ] **Fuzz testing** - Random partial reads, malformed packets
- [ ] **Timeout tests** - Verify non-blocking behavior

### Phase 11: Polish

- [ ] **Documentation** - Usage examples, API reference
- [ ] **Allocation-free option** - User-provided buffers, no heap allocation
- [ ] **Configurable buffer sizes** - Sensible defaults, user override
- [ ] **Topic validation** - Wildcards (#, +) only for subscribe
- [ ] **Client ID generation** - Random ID if not provided

---

## Current Status

- [x] Basic TCP connection
- [x] Hardcoded CONNECT packet
- [x] CONNACK validation
- [x] Hardcoded PUBLISH (QoS 0)
- [x] DISCONNECT

## Usage

```bash
# Start subscriber (in another terminal)
mosquitto_sub -h localhost -t "test/hello" -v

# Run the client
zig build run
```

## References

- [MQTT 3.1.1 Specification (OASIS)](http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)
- [mqttz](https://github.com/karlseguin/mqttz) - Reference implementation
