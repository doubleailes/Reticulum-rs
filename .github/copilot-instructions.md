# Reticulum-rs Coding Guidelines for AI Agents

## Project Overview
**Reticulum-rs** is a Rust implementation of the Reticulum Network Stack—a cryptographic, decentralized mesh networking protocol. The codebase implements packet routing, identity-based cryptography, and pluggable transport interfaces (TCP, UDP, Kaonic gRPC).

## Architecture

### Core Modules (src/)
- **`identity.rs`**: ED25519 signing keys, X25519 key exchange, derived encryption keys. Traits: `EncryptIdentity`, `DecryptIdentity`, `HashIdentity`. Always use `OsRng` for random number generation.
- **`packet.rs`**: Packet format definitions (Header Type 1/2, PropagationType: Broadcast/Transport, DestinationType: Single/Group/Plain/Link). Max payload = 2048 bytes (`PACKET_MDU`). Packet structure includes address hashes, signatures, and encryption metadata.
- **`destination.rs`**: Endpoint abstraction using type-state pattern (`Input`/`Output` directions, `Single`/`Plain`/`Group` types). Manages routing addresses and link establishment.
- **`transport.rs`**: Central router maintaining tables (LinkTable, AnnounceTable, PathTable, PacketCache). Handles message forwarding, link lifecycle, and announce retransmission. Uses `Tokio` async + broadcast channels.
- **`iface.rs`**: Interface abstraction for physical/logical transports. Submodules: `tcp_server`, `tcp_client`, `udp`, `kaonic` (gRPC), `hdlc` (encoding). Each implements `Interface` trait with `InterfaceContext<T>` for spawn/initialization.
- **`crypt.rs`**: Fernet encryption (AES-128-CBC or AES-256-CBC via feature flag). Uses HKDF for key derivation.
- **`hash.rs`**: SHA256-based address hashing (10-byte hashes). `AddressHash` wraps address space.

### Key Design Patterns
1. **Type-State Pattern**: `Destination<T: Direction, U: Type>` encodes compile-time constraints on input/output and destination types.
2. **Trait-Based Extensibility**: Interface implementations extend `Interface` trait; encrypt/decrypt identity operations use traits, not concrete types.
3. **Async-First**: All I/O and transport operations use `tokio` with `Arc<Mutex<>>` for shared state. Avoid blocking calls in async contexts.
4. **Channel-Based Communication**: `mpsc` channels for inter-task messaging; `broadcast` for packet events.

## Critical Workflows

### Build & Compilation
```bash
cargo build --release          # Standard build
cargo test                     # Run tests (includes tcp_hdlc_test.rs)
cargo run --example <name>    # Run example
```
**Proto Compilation**: `build.rs` auto-compiles `proto/kaonic/kaonic.proto` via `tonic-build`. Adds `serde` derive attributes to generated types—do not manually edit generated files.

### Transport Setup (see examples/tcp_server.rs, examples/echo.rs)
1. Create `Transport` with `TransportConfig::new(name, identity, is_reachable)`.
2. Spawn interfaces via `transport.iface_manager().lock().await.spawn(interface, Interface::spawn)`.
3. Access RX via `transport.iface_rx()` (returns `InterfaceRxReceiver`).
4. Send packets via `transport.send_packet(packet)`.

### Testing Patterns
Tests spawn multiple transports with different identities, link them via TCP, and stress-test packet forwarding. Use `#[tokio::test]` and `CancellationToken` for cleanup. Example: [tests/tcp_hdlc_test.rs](tests/tcp_hdlc_test.rs#L32-L36).

## Project-Specific Conventions

### Error Handling
Use `RnsError` enum (OutOfMemory, InvalidArgument, IncorrectSignature, IncorrectHash, CryptoError, PacketError, ConnectionError). Avoid `Result<T>` unwrapping in production paths; prefer graceful degradation.

### Identity Management
`PrivateIdentity` is derived from a 64-byte secret. Use `PrivateIdentity::new_from_rand(OsRng)` for generation or `new_from_hex_string()` for deserialization. Store identities as hex strings. Encrypt/decrypt operations require `DerivedKey` (generated via HKDF).

### Packet Construction
Packets carry metadata in `Header` (type, propagation, destination type, signature) and data in `PacketDataBuffer`. Always validate packet context (signature verification, destination type matching) before processing. Use `PacketContext` for routing metadata.

### Interface Implementation
Each interface (TCP, UDP, Kaonic) must:
1. Implement RX loop reading from network, wrapping in `RxMessage`, sending to transport.
2. Implement TX loop receiving `TxMessage`, encoding packet, writing to network.
3. Handle `CancellationToken` for graceful shutdown.
4. Spawn as: `Interface::spawn(context: InterfaceContext<Self>)`.

### Feature Flags
- `alloc`: Enable heap allocation (default).
- `fernet-aes128`: Use AES-128-CBC (default AES-256-CBC). Affects `DERIVED_KEY_LENGTH`.

## Integration & Dependencies

### External Crates
- **Crypto**: `ed25519-dalek`, `x25519-dalek`, `sha2`, `aes`, `hkdf`.
- **Async**: `tokio` (full features), `tokio-stream`, `tokio-util`.
- **Serialization**: `serde`, `rmp` (MessagePack).
- **RPC**: `tonic`, `prost` (gRPC protocol buffers).
- **Logging**: `log`, `env_logger`.

### Cross-Module Communication
Transport acts as hub: receives packets from interfaces via `InterfaceRxReceiver`, forwards to destinations, routes via tables. Destinations receive via broadcast channels. Links encapsulate peer state and handle encryption/decryption per-destination.

## Adding New Interfaces
1. Create file in `src/iface/yourname.rs`.
2. Define struct implementing `Interface` trait.
3. Implement `spawn(context: InterfaceContext<Self>)` with RX/TX loops.
4. Register in `iface.rs` module declaration.
5. Use in examples/tests: `transport.iface_manager().lock().await.spawn(YourInterface::new(...), YourInterface::spawn)`.

## Code Examples

### Creating an Output Destination
```rust
let dest = SingleOutputDestination::new_from_identity(&identity, DestinationName::new_from_string("example"));
let dest_hash = dest.address_hash();
```

### Sending a Packet
```rust
let mut packet = Packet::default();
packet.data.resize(payload_size);
transport.send_packet(packet).await;
```

### Receiving from Transport
```rust
let mut rx = transport.iface_rx();
while let Ok(rx_msg) = rx.recv().await {
    log::info!("Received from {:?}", rx_msg.address);
}
```

## Reference

The python reference implementation of Reticulum can be found at: `reference/Reticulum`
It contains additional documentation on the Reticulum protocol and its features.