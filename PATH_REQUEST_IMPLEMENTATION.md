# Path Request Implementation Documentation

## Overview

Path request handling has been fully implemented in Reticulum-rs. This document describes the implementation details and how it aligns with the Reticulum protocol.

## Implementation Details

### 1. Path Request Generation

**Location:** `src/transport.rs:659` - `Transport::request_path()`

**Functionality:**
- Generates path request packets with the standard format:
  - Destination hash (16 bytes) - The destination being searched for
  - Transport ID hash (16 bytes) - The requesting transport's identity
  - Request tag (32 bytes) - Unique identifier for this request
- Sends to the well-known plain destination: `"rnstransport.path.request"`
- Uses `PacketType::Data` with `DestinationType::Plain`
- Broadcasts the request to all connected interfaces

**Example Usage:**
```rust
transport.request_path(&destination_hash, None).await;
```

### 2. Path Request Handling

**Location:** `src/transport.rs:1099` - `handle_path_request()`

**Functionality:**
- Validates incoming path request packets (minimum 64 bytes)
- Extracts the requested destination hash
- Checks if the destination exists in local `single_in_destinations`
- If found, generates an announce packet with `PacketContext::PathResponse`
- Returns the path response packet for broadcasting

**Packet Flow:**
1. Incoming packet arrives at `handle_data()`
2. Checks if `destination_type == Plain` and destination matches `"rnstransport.path.request"`
3. Calls `handle_path_request()` to process
4. Broadcasts the returned path response announce

### 3. Path Response Processing

**Location:** `src/transport.rs:1279-1398` - `handle_announce()`

**Functionality:**
- Path responses are regular announces with `context = PacketContext::PathResponse`
- The `is_path_response` flag is set based on packet context
- Announce handlers can filter path responses using the `receive_path_responses()` method
- Path response announces update the path table and trigger announce handlers

### 4. Announce Handler Support

**Trait:** `AnnounceHandler` in `src/transport.rs:145`

**Methods:**
- `receive_path_responses()` - Returns `true` if handler wants to receive path response announces
- `should_handle()` - Custom filtering based on destination hash
- `handle_announce()` - Called for both regular announces and path responses

**AnnounceEvent Structure:**
- `destination: Arc<Mutex<SingleOutputDestination>>` - The announced destination
- `app_data: PacketDataBuffer` - Application-specific data
- `is_path_response: bool` - Flag indicating if this is a path response

## Protocol Compatibility

The implementation follows the Reticulum protocol specification:

1. **Plain Destination:** Uses `"rnstransport.path.request"` as the well-known destination
2. **Packet Format:** Follows the standard format (destination_hash + transport_id + tag)
3. **Path Response:** Sends regular announces with PathResponse context
4. **Broadcasting:** Path requests are broadcast, responses are also broadcast
5. **No Identity:** Path request destination has no identity (Plain type)

## Test Coverage

### Test 1: Basic Path Request/Response
**File:** `tests/path_request_test.rs:98`
- Creates two transports connected via TCP
- Sends a regular announce from transport A
- Requests a path from transport B
- Verifies that both the regular announce and path response are received

### Test 2: Multiple Destinations
**File:** `tests/path_request_test.rs:159`
- Creates multiple destinations on transport A
- Requests paths to multiple destinations without prior announces
- Verifies that all path responses are received

### Test Results
```
running 2 tests
test test_path_request_response ... ok
test test_path_request_response_with_multiple_destinations ... ok

test result: ok. 2 passed; 0 failed
```

## Key Implementation Points

1. **PathResponse Context:** The `PacketContext::PathResponse` (0x0B) distinguishes path response announces from regular announces

2. **Handler Filtering:** Handlers can choose to ignore path responses by returning `false` from `receive_path_responses()`

3. **Destination Lookup:** Only local destinations (those in `single_in_destinations`) respond to path requests

4. **No Ratchet Flag Confusion:** The context_flag in the packet header indicates ratchet presence, NOT path response status. Path response status is indicated by the context field.

5. **Broadcast Propagation:** Path responses are broadcast like regular announces, allowing them to propagate through the network

## Future Enhancements

Potential improvements (not currently required):
- Path request rate limiting per destination
- Path request caching to avoid duplicate responses
- Metrics tracking for path request/response counts
- Multi-hop path response aggregation

## Conclusion

The path request handling implementation is complete and fully functional. It correctly handles:
- ✅ Generating path request packets
- ✅ Processing incoming path requests
- ✅ Generating path response announces
- ✅ Filtering path responses in announce handlers
- ✅ Broadcasting path responses through the network
- ✅ Compatibility with the Reticulum protocol

All tests pass successfully, demonstrating correct end-to-end functionality.
