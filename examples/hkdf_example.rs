/// Example demonstrating the HKDF helper function
/// 
/// This example shows how to use the HKDF (HMAC-based Key Derivation Function)
/// helper from reticulum-rs to derive cryptographic keys. This is the same
/// primitive used by LXMF for stamp workblock generation.

use reticulum::crypt::hkdf;

fn main() {
    println!("=== HKDF Example ===\n");

    // Example 1: Basic key derivation
    println!("1. Basic key derivation:");
    let ikm = b"my secret input keying material";
    let salt = b"optional salt for additional entropy";
    let info = b"application context information";
    
    let derived_key = hkdf(32, ikm, Some(salt), Some(info));
    println!("   Derived 32-byte key: {:02x?}...", &derived_key[..8]);
    
    // Example 2: Derive keys without salt (uses default zero salt)
    println!("\n2. Derivation with default salt:");
    let derived_key2 = hkdf(64, ikm, None, Some(info));
    println!("   Derived 64-byte key: {:02x?}...", &derived_key2[..8]);
    
    // Example 3: Derive keys without context
    println!("\n3. Derivation without context:");
    let derived_key3 = hkdf(32, ikm, Some(salt), None);
    println!("   Derived 32-byte key: {:02x?}...", &derived_key3[..8]);
    
    // Example 4: LXMF-style stamp workblock generation
    println!("\n4. LXMF-style stamp workblock generation:");
    use sha2::{Digest, Sha256};
    
    let message_id = b"example_message_id_123";
    let expand_rounds = 3; // Use fewer rounds for demo
    
    let mut workblock = Vec::new();
    for n in 0..expand_rounds {
        // Create a unique salt for each round
        let n_bytes = (n as u32).to_le_bytes();
        let mut hasher = Sha256::new();
        hasher.update(message_id);
        hasher.update(&n_bytes);
        let salt = hasher.finalize();
        
        // Derive 256 bytes per round
        let round_data = hkdf(256, message_id, Some(&salt), None);
        workblock.extend_from_slice(&round_data);
    }
    
    println!("   Generated workblock of {} bytes from {} rounds", 
             workblock.len(), expand_rounds);
    println!("   First 16 bytes: {:02x?}...", &workblock[..16]);
    
    // Example 5: Determinism verification
    println!("\n5. Determinism verification:");
    let key1 = hkdf(32, ikm, Some(salt), Some(info));
    let key2 = hkdf(32, ikm, Some(salt), Some(info));
    println!("   Keys match: {}", key1 == key2);
    
    println!("\n=== Example complete ===");
}
