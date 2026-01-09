# Fix for Link Request Processing Issue

## Problem
When using `Transport::add_destination()` to register a `SingleInputDestination` and receiving a link request from a Python RNS/LXMF client, the link request packet was not being processed. No proof was sent back, causing link establishment to timeout.

## Root Cause
LinkRequest packets were being filtered out by the `filter_duplicate_packets()` function when they were seen as duplicates in the packet cache. Previously, only Announce packets were explicitly allowed through the duplicate filter.

## Solution
Modified the `filter_duplicate_packets()` function in `src/transport.rs` to always allow LinkRequest packets through, similar to how Announce packets are handled.

### Code Change
```rust
match packet.header.packet_type {
    PacketType::Announce => {
        return true;
    }
    PacketType::LinkRequest => {
        // Allow LinkRequest packets through even if duplicate
        // Link establishment is critical and the link handling code
        // will decide whether to process duplicate requests
        return true;
    }
    // ... rest of the match arms
}
```

## Rationale
LinkRequest packets should bypass duplicate filtering because:

1. **Critical Operation**: Link establishment is a fundamental operation in Reticulum and must be reliable
2. **Network Conditions**: Legitimate retransmissions may occur during:
   - Packet loss
   - Network congestion
   - Interface reconnections
3. **Proper Layer**: The link handling code (in `handle_link_request` and `handle_link_request_as_destination`) is better suited to decide whether to process duplicate requests

## Testing

### Unit Tests
Added two new unit tests:
- `link_request_not_filtered_as_duplicate`: Verifies LinkRequest packets bypass duplicate filtering
- `announce_not_filtered_as_duplicate`: Documents existing behavior for Announce packets

### Integration Tests
All existing integration tests continue to pass:
- 40 library tests ✓
- 8 integration tests ✓

### Example Application
Created `examples/link_receiver.rs` to demonstrate:
- Registering a destination via `add_destination()`
- Sending announces
- Receiving link events

## Verification
To manually verify the fix:

1. Start rnsd (Python Reticulum daemon):
   ```bash
   rnsd --config ~/.reticulum
   ```

2. Run the link receiver example:
   ```bash
   cargo run --example link_receiver
   ```

3. From a Python RNS/LXMF client, discover the destination and establish a link

4. Observe that:
   - The announce is received by Python ✓
   - Python sends a link request ✓
   - Rust receives and processes the link request ✓
   - Link proof is sent back ✓
   - Link becomes active ✓

## Impact
This fix ensures proper interoperability between Rust and Python implementations of Reticulum for link establishment, particularly when using `add_destination()` to register destinations.

## Related Code
- `src/transport.rs`: Main fix in `filter_duplicate_packets()`
- `src/destination/link.rs`: Link handling logic
- `examples/link_receiver.rs`: Demonstration example
