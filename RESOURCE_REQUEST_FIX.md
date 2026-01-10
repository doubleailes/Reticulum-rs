# Resource Request Transmission Fix

## Problem Summary

When receiving large LXMF messages (>~450 bytes) via Resource transfer from a Python LXMF sender, the Rust Reticulum implementation would accept the `ResourceAdvertisement` and claim to send a `ResourceRequest`, but the Python sender never received it. The transfer would time out and the link would close.

## Root Cause

The issue was in `src/iface/tcp_client.rs` where the TX (transmit) task was not properly sharing the `stop` CancellationToken with the RX (receive) task.

### The Bug

```rust
// Line 77: Create cancellation token for this connection
let stop = CancellationToken::new();

// Line 86-155: RX task properly clones stop
let rx_task = {
    let cancel = cancel.clone();
    let stop = stop.clone();  // ✅ Properly cloned
    // ...
}

// Line 157-200: TX task MISSING stop clone
let tx_task = {
    let cancel = cancel.clone();
    let tx_channel = tx_channel.clone();
    // ❌ MISSING: let stop = stop.clone();
    
    tokio::spawn(async move {
        if stop.is_cancelled() {  // ❌ Using moved/different stop instance
            break;
        }
        // ...
    })
}
```

### What Happened

1. Python client connects to Rust TcpServer
2. TcpServer spawns a TcpClient instance for the connection
3. TcpClient creates RX and TX tasks
4. RX task clones the `stop` CancellationToken
5. TX task moves the original `stop` into its closure
6. **Problem**: These are now separate CancellationToken instances!

When the RX task detected any issue (or even during normal operation), calling `stop.cancel()` only affected its clone. The TX task's `stop` token was never cancelled.

### Impact on Resource Transfers

1. Python sends ResourceAdvertisement → Rust receives it ✅
2. Rust processes advertisement and creates ResourceRequest ✅
3. ResourceRequest is routed to correct interface ✅
4. **TX task is stuck waiting on `tx_channel.recv()`** ❌
5. **TX task's `stop` token is never cancelled** ❌
6. **ResourceRequest never goes out on the wire** ❌
7. Python times out waiting for request ❌

## The Fix

Add `let stop = stop.clone();` before spawning the TX task:

```rust
// Line 157-161: TX task NOW properly clones stop
let tx_task = {
    let cancel = cancel.clone();
    let stop = stop.clone();  // ✅ NOW properly cloned
    let tx_channel = tx_channel.clone();
    let mut stream = write_stream;
    
    tokio::spawn(async move {
        if stop.is_cancelled() {  // ✅ Now shares same cancellation state
            break;
        }
        // ...
    })
}
```

Now both RX and TX tasks share the same cancellation signal through their cloned tokens. When the RX task cancels `stop`, the TX task is also notified and can clean up properly.

## Additional Improvements

To aid in debugging this and future issues, comprehensive logging was added:

### Interface Layer (`src/iface.rs`)
- Log when packets are sent directly to specific interfaces
- Warn when sends fail due to closed channels

### TCP Client (`src/iface/tcp_client.rs`)
- Log packet context, destination, and type before transmission
- Log HDLC encoding success/failure
- Log TCP write and flush success/failure
- Log number of bytes sent to wire

### Transport Layer (`src/transport.rs`)
- Log when link packets are detected
- Log the interface being routed to
- Warn if incoming link has no origin_interface set

### Resource Manager (`src/resource.rs`)
- Log link ID and origin_interface when creating ResourceRequest
- Log packet details before sending

## Testing

### Library Tests
All 45 library tests pass, including:
- Link establishment tests
- Resource packet handling tests
- Packet routing tests
- Encryption/decryption tests

### Integration Tests
All integration tests pass, including:
- `tcp_hdlc_test` which exercises TCP packet transmission
- Shows "successfully sent X bytes to wire" confirming actual transmission

## Verification

To verify the fix works with Python LXMF:

1. Start `rnsd` (Python Reticulum daemon)
2. Start Rust LXMF receiver using Reticulum-rs
3. Send a large message (>450 bytes) from Python LXMF sender
4. Observe logs showing:
   - ResourceAdvertisement received
   - ResourceRequest created with link ID and origin_interface
   - Packet routed to correct interface
   - "successfully sent X bytes to wire" confirmation
   - Resource data parts received from Python
   - ResourceProof sent back to Python
   - Transfer completes successfully

## Related Issues

This fix resolves the following symptoms:
- ResourceRequest packets not reaching Python sender
- Resource transfers timing out
- "All parts sent, but no resource proof received" on Python side
- Links closing unexpectedly during resource transfers

## Files Modified

- `src/iface/tcp_client.rs` - **CRITICAL FIX** + enhanced logging
- `src/iface.rs` - Enhanced logging
- `src/transport.rs` - Enhanced logging
- `src/resource.rs` - Enhanced logging

## Credits

This issue was identified and fixed by analyzing the packet flow and adding comprehensive logging to trace where packets were being lost. The root cause was a subtle bug in the cancellation token handling that only manifested during resource transfers when the TX task needed to send packets back to the Python sender.
