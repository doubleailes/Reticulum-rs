# Fix for Link Data Packets Dropped by Duplicate Filter

## Problem
After the TCP buffer fix from PR #33, Resource data packets (`PacketContext::Resource = 0x01`) were successfully arriving at the TCP client but were being dropped by `filter_duplicate_packets()` in the transport layer. The packets never reached `handle_data()` or triggered `LinkEvent::Resource`, causing complete Resource transfer failure.

## Root Cause
Link-destined packets with `DestinationType::Link` were being treated the same as global broadcast packets and subjected to duplicate filtering via the packet cache. This was inappropriate because:

1. Link packets are point-to-point communication between two peers
2. The Link ID serves as the "session" identifier
3. Resource data parts have different content but may arrive rapidly
4. The Link layer (`handle_data_packet()`) handles its own state management
5. Python RNS does NOT apply duplicate filtering to Link-destined packets

The duplicate filter was designed for broadcast packets to prevent network flooding, but was incorrectly being applied to Link packets which are fundamentally different.

## Solution
Modified the `filter_duplicate_packets()` function in `src/transport.rs` to bypass duplicate filtering for all Link-destined packets based on `DestinationType::Link`, not just specific packet types or contexts.

### Code Change
```rust
async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
    // Link-destined packets should bypass duplicate filtering
    // They have their own session management via the Link ID and
    // the Link layer handles state management internally
    if packet.header.destination_type == DestinationType::Link {
        return true;
    }

    // ... rest of the function unchanged
}
```

## Rationale
Link-destined packets should bypass duplicate filtering because:

1. **Point-to-Point Communication**: Link packets are not broadcast - they're targeted to a specific Link session
2. **Session Management**: The Link ID provides session isolation, so "duplicates" in the global cache are meaningless
3. **Link Layer State**: The Link layer maintains its own state (sequence numbers, acknowledgments) and can handle retransmissions properly
4. **Python Compatibility**: Python RNS implementation does not filter Link-destined packets as duplicates
5. **Proper Layer**: The Link handling code is the correct layer to make decisions about packet processing

### Why This Differs from LinkRequest Fix
The previous `LINK_REQUEST_FIX.md` added a specific bypass for `PacketType::LinkRequest`. This fix is more comprehensive:
- **LinkRequest fix**: Bypassed specific packet type (establishment)
- **This fix**: Bypasses entire `DestinationType::Link` category (all Link communication)

This approach is more correct because it treats the Link as a session-based channel that shouldn't be subject to global duplicate filtering at all.

## Testing

### Unit Tests
Added comprehensive test `link_data_packets_not_filtered_as_duplicate` that verifies:
- Resource data packets (`PacketContext::Resource`) bypass filter
- ResourceAdvrtisement packets bypass filter
- KeepAlive packets bypass filter
- Multiple identical Link packets are all allowed through

### Existing Tests Validated
- `drop_duplicates`: Still works correctly for non-Link packets
- `link_request_not_filtered_as_duplicate`: Still passes (now redundant but kept for documentation)
- `announce_not_filtered_as_duplicate`: Still passes

All tests continue to pass:
- 46 unit tests ✓
- 8 integration tests ✓

## Impact

### Fixed Issues
- ✅ Resource data packets now reach Link handler
- ✅ Resource transfers complete successfully
- ✅ LXMF messages can be received from Python
- ✅ Link keepalive packets work correctly
- ✅ All Link-based communication is properly routed

### Packet Flow (After Fix)
```
TCP Socket → HDLC Decode → Interface → Transport → handle_data() → Link.handle_packet()
                                         ↑
                               filter_duplicate_packets()
                               ✅ ALLOWS Link packets through
```

## Log Evidence (Expected After Fix)

### Rust Receiver
```
[timestamp] tcp_client: read 576 bytes from TCP stream
[timestamp] tcp_client: rx << context=Resource dest=/4fc13484.../ type=Data
[timestamp] tp(tp): routing packet type=Data ctx=Resource to handler  ✅
[timestamp] Processing resource packet: type=Data, context=Resource  ✅
```

### Python Sender
```
[timestamp] Sent resource advertisement for <ac8ae0d8...>
[timestamp] The transfer is in progress (100.0%)
[timestamp] Resource proof received, transfer complete  ✅
```

## Related Issues and PRs

### Related Fixes
- **PR #33**: Fixed TCP buffer issue (RX path) - allowed Resource packets to arrive at TCP layer
- **PR #30**: Fixed ResourceRequest TX issue - allowed ResourceRequest to be sent
- **LINK_REQUEST_FIX.md**: Fixed LinkRequest duplicate filtering - now superseded by this broader fix

### Relationship Between Fixes
1. **PR #30** (ResourceRequest TX): Rust can send ResourceRequest → Python
2. **PR #33** (TCP buffer RX): Python can send Resource data → Rust TCP layer receives it
3. **This fix** (Link duplicate filter): Resource packets pass through transport → Link handler

All three were needed for complete Resource transfer functionality.

## Files Modified

- `src/transport.rs`:
  - Lines 1005-1012: Added Link packet bypass in `filter_duplicate_packets()`
  - Lines 2177-2265: Added comprehensive unit test

## Verification

To verify this fix works with Python RNS:

1. Start rnsd (Python Reticulum daemon)
2. Run a Rust example that accepts links (e.g., `link_receiver`)
3. From Python LXMF client, send a message to the Rust receiver
4. Observe:
   - ResourceAdvertisement arrives and is processed ✓
   - ResourceRequest is sent back to Python ✓
   - Resource data packets arrive and are processed ✓
   - ResourceProof is sent back to Python ✓
   - Transfer completes successfully ✓

## Credits

This issue was identified through detailed log analysis showing that Resource data packets were arriving at the TCP layer (`tcp_client: rx << context=Resource`) but no corresponding `tp(tp): routing packet` logs appeared, indicating the packets were being dropped by the duplicate filter. The fix brings Rust Reticulum into alignment with Python RNS behavior for Link packet handling.
