# Reticulum-rs Ratchet Implementation

This implementation provides forward secrecy through automatic key rotation for Reticulum destinations, following the same approach as the original Python Reticulum implementation.

## Overview

The ratchet system automatically rotates encryption keys every time a destination sends an announce packet. This provides forward secrecy - even if current encryption keys are compromised, past and future communications remain secure.

## Key Features

- **Automatic Key Rotation**: Keys are rotated on each announce
- **Forward Secrecy**: Old keys cannot decrypt future messages
- **Backward Compatibility**: Multiple old keys are kept for decrypting delayed packets
- **Persistent Storage**: Ratchet state is saved to disk for recovery across restarts
- **Transparent Operation**: Ratchets work seamlessly with existing packet encryption/decryption

## Usage

### Basic Ratcheted Destination

```rust
use reticulum::destination::{DestinationName, RatchetedDestination};
use reticulum::identity::PrivateIdentity;
use rand_core::OsRng;
use std::path::PathBuf;

// Create a new destination with ratchet support
let identity = PrivateIdentity::new_from_rand(OsRng);
let destination = RatchetedDestination::new(
    identity,
    DestinationName::new("example_app", "ratchet.service"),
);

// Enable ratchets with persistent storage
let ratchet_file = PathBuf::from("/secure/path/to/ratchets.json");
destination.enable_ratchets(OsRng, ratchet_file)?;

// Announce (automatically rotates keys)
let announce_packet = destination.announce(OsRng, None)?;

// Check if ratchets are enabled
println!("Ratchets enabled: {}", destination.ratchets_enabled());
```

### Encryption and Decryption

```rust
// Encrypt data using current ratchet key
let plaintext = b"Secret message";
let mut encrypted_buffer = [0u8; 2048];
let ciphertext = destination.encrypt(OsRng, plaintext, &mut encrypted_buffer)?;

// Decrypt data (tries current + old keys automatically)
let mut decrypted_buffer = [0u8; 2048];
let decrypted = destination.decrypt(OsRng, ciphertext, &mut decrypted_buffer)?;

assert_eq!(plaintext, decrypted);
```

### Creating Data Packets

```rust
// Create an encrypted data packet
let data = b"Hello, ratcheted world!";
let packet = destination.create_data_packet(OsRng, data)?;

// The packet is automatically encrypted with the current ratchet key
```

## Key Rotation Behavior

1. **Initial State**: When ratchets are first enabled, a random key is generated
2. **Announce Rotation**: Each `announce()` call first sends the packet, then rotates to a new key
3. **Rotation Timing**: Key rotation happens **after** announce transmission (matching Python RNS)
4. **Old Key Retention**: Previous keys are kept for decryption (up to 16 keys by default)
5. **Key Derivation**: New keys are derived from previous keys using SHA-256 hashing

## Security Considerations

### File Storage Security

The ratchet file contains encryption keys and must be protected:

```rust
// Use secure file paths
let ratchet_file = PathBuf::from("/secure/app/data/destination_hash.ratchets");

// Set appropriate file permissions (Unix)
use std::os::unix::fs::PermissionsExt;
let mut perms = std::fs::metadata(&ratchet_file)?.permissions();
perms.set_mode(0o600); // Read/write for owner only
std::fs::set_permissions(&ratchet_file, perms)?;
```

### Key Management

- Keys are automatically rotated on announce
- Old keys are automatically cleaned up
- No manual key management required
- Keys are never reused

## Example: Echo Server with Ratchets

See `examples/ratchet_echo.rs` for a complete working example:

```bash
# Run the server
cargo run --example ratchet_echo server

# Run the client (in another terminal)
cargo run --example ratchet_echo client <destination_hash>
```

## Configuration

Default configuration can be adjusted in `src/destination/ratchet.rs`:

- `RATCHET_ROTATION_INTERVAL`: How often to rotate (default: every announce)
- `RATCHET_MAX_OLD_KEYS`: Maximum old keys to keep for decryption (default: 16)

## Implementation Details

### RatchetKey Structure

- `sequence`: Monotonically increasing counter
- `key`: 256-bit or 512-bit encryption key (depends on feature flags)

### RatchetState Structure

- `current_sequence`: Current sequence number
- `current_key`: Active encryption key
- `old_keys`: Array of previous keys for decryption
- `destination_hash`: Associated destination identifier
- `file_path`: Storage location for persistence

### Key Derivation

New keys are derived using:
```
new_key = SHA-256(old_key || sequence_number)
```

For keys larger than 256 bits, additional rounds are performed.

## Testing

Run the ratchet tests:

```bash
# Test the ratchet implementation
cargo test ratchet

# Test the example
cargo test --example ratchet_echo
```

## Compatibility

This implementation is compatible with:
- Original Python Reticulum ratchet specification
- All existing Reticulum packet formats
- Standard Reticulum cryptographic primitives

The ratchet system is transparent to existing code - destinations work exactly the same way, with automatic key rotation providing additional security.