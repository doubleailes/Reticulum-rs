use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF (HMAC-based Key Derivation Function) using SHA-256.
///
/// This function mirrors the behavior of `RNS.Cryptography.hkdf` from the Python
/// Reticulum implementation. It derives cryptographic key material of a specified
/// length from input keying material (IKM) using HKDF with SHA-256.
///
/// # Arguments
///
/// * `length` - The desired output length in bytes. Must be greater than 0.
/// * `derive_from` - Input keying material (IKM) to derive keys from. Cannot be empty.
/// * `salt` - Optional salt value. If `None` or empty, a default salt of 32 zero bytes is used.
/// * `context` - Optional context and application specific information. If `None`, an empty byte slice is used.
///
/// # Returns
///
/// Returns a `Vec<u8>` containing the derived key material of the specified length.
///
/// # Panics
///
/// Panics if:
/// * `length` is 0 or exceeds the maximum allowed output (255 * 32 = 8160 bytes for SHA-256)
/// * `derive_from` is empty
///
/// # Examples
///
/// ```
/// use reticulum::crypt::hkdf;
///
/// // Derive a 32-byte key
/// let ikm = b"input keying material";
/// let salt = b"optional salt";
/// let info = b"application context";
/// let derived = hkdf(32, ikm, Some(salt), Some(info));
/// assert_eq!(derived.len(), 32);
///
/// // Derive with default salt and no context
/// let derived = hkdf(64, ikm, None, None);
/// assert_eq!(derived.len(), 64);
/// ```
///
/// # Determinism
///
/// This function is deterministic: given the same inputs, it will always produce
/// the same output. This is critical for LXMF stamp generation and verification.
pub fn hkdf(
    length: usize,
    derive_from: &[u8],
    salt: Option<&[u8]>,
    context: Option<&[u8]>,
) -> Vec<u8> {
    const HASH_LEN: usize = 32; // SHA-256 output length

    if length == 0 {
        panic!("Invalid output key length: length must be greater than 0");
    }

    if derive_from.is_empty() {
        panic!("Cannot derive key from empty input material");
    }

    // Use default salt of 32 zero bytes if none provided or empty
    let salt_bytes = match salt {
        Some(s) if !s.is_empty() => s,
        _ => &[0u8; HASH_LEN],
    };

    // Use empty context if none provided
    let context_bytes = context.unwrap_or(b"");

    // Create HKDF instance and expand to desired length
    let hkdf = Hkdf::<Sha256>::new(Some(salt_bytes), derive_from);
    
    let mut output = vec![0u8; length];
    hkdf.expand(context_bytes, &mut output)
        .expect("Invalid length for HKDF output");

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_hkdf_basic() {
        let ikm = b"test input keying material";
        let salt = b"test salt";
        let info = b"test info";
        
        let derived = hkdf(32, ikm, Some(salt), Some(info));
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"deterministic test";
        let salt = b"salt";
        let info = b"info";
        
        let derived1 = hkdf(64, ikm, Some(salt), Some(info));
        let derived2 = hkdf(64, ikm, Some(salt), Some(info));
        
        assert_eq!(derived1, derived2);
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"test ikm";
        let derived1 = hkdf(32, ikm, None, None);
        let derived2 = hkdf(32, ikm, Some(&[]), None);
        
        // Both should use the default zero salt
        assert_eq!(derived1, derived2);
    }

    #[test]
    fn test_hkdf_no_context() {
        let ikm = b"test ikm";
        let salt = b"salt";
        
        let derived1 = hkdf(32, ikm, Some(salt), None);
        let derived2 = hkdf(32, ikm, Some(salt), Some(&[]));
        
        // Both should use empty context
        assert_eq!(derived1, derived2);
    }

    #[test]
    fn test_hkdf_different_lengths() {
        let ikm = b"test ikm";
        let salt = b"salt";
        let info = b"info";
        
        let derived16 = hkdf(16, ikm, Some(salt), Some(info));
        let derived32 = hkdf(32, ikm, Some(salt), Some(info));
        let derived64 = hkdf(64, ikm, Some(salt), Some(info));
        let derived256 = hkdf(256, ikm, Some(salt), Some(info));
        
        assert_eq!(derived16.len(), 16);
        assert_eq!(derived32.len(), 32);
        assert_eq!(derived64.len(), 64);
        assert_eq!(derived256.len(), 256);
        
        // Shorter outputs should be prefixes of longer ones (HKDF property)
        assert_eq!(&derived32[..16], &derived16[..]);
        assert_eq!(&derived64[..32], &derived32[..]);
    }

    #[test]
    fn test_hkdf_known_vector_rfc5869() {
        // Test Vector 1 from RFC 5869
        // https://tools.ietf.org/html/rfc5869#appendix-A.1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        
        let okm = hkdf(42, &ikm, Some(&salt), Some(&info));
        
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ).unwrap();
        
        assert_eq!(okm, expected);
    }

    #[test]
    fn test_hkdf_known_vector_rfc5869_test3() {
        // Test Vector 3 from RFC 5869 - with empty salt and empty info
        // https://tools.ietf.org/html/rfc5869#appendix-A.3
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        
        // Using empty salt (None) - will use 32 zero bytes
        let okm = hkdf(42, &ikm, None, None);
        
        let expected = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        ).unwrap();
        
        assert_eq!(okm, expected);
    }

    #[test]
    #[should_panic(expected = "Invalid output key length")]
    fn test_hkdf_zero_length() {
        let ikm = b"test";
        hkdf(0, ikm, None, None);
    }

    #[test]
    #[should_panic(expected = "Cannot derive key from empty input material")]
    fn test_hkdf_empty_ikm() {
        hkdf(32, &[], None, None);
    }

    #[test]
    fn test_hkdf_large_output() {
        // Test with a larger output (3000 bytes)
        let ikm = b"test ikm for large output";
        let derived = hkdf(3000, ikm, None, None);
        assert_eq!(derived.len(), 3000);
    }

    #[test]
    fn test_hkdf_different_inputs_different_outputs() {
        let ikm1 = b"input1";
        let ikm2 = b"input2";
        
        let derived1 = hkdf(32, ikm1, None, None);
        let derived2 = hkdf(32, ikm2, None, None);
        
        assert_ne!(derived1, derived2);
    }

    #[test]
    fn test_hkdf_different_salts_different_outputs() {
        let ikm = b"test ikm";
        let salt1 = b"salt1";
        let salt2 = b"salt2";
        
        let derived1 = hkdf(32, ikm, Some(salt1), None);
        let derived2 = hkdf(32, ikm, Some(salt2), None);
        
        assert_ne!(derived1, derived2);
    }

    #[test]
    fn test_hkdf_lxmf_stamp_workblock_compatibility() {
        // This test simulates LXMF stamp workblock generation
        // as done in LXMF/LXStamper.py stamp_workblock function
        use sha2::{Digest, Sha256};
        
        let message_id = b"test_message_id_12345678";
        let expand_rounds: u32 = 10; // Use fewer rounds for testing
        
        let mut workblock = Vec::new();
        for n in 0..expand_rounds {
            // Serialize the round number (simulating msgpack.packb(n))
            let n_bytes = n.to_le_bytes();
            
            // Compute salt as Hash(material + n_bytes)
            let mut hasher = Sha256::new();
            hasher.update(message_id);
            hasher.update(&n_bytes);
            let salt = hasher.finalize();
            
            // Derive 256 bytes using HKDF
            let derived = hkdf(256, message_id, Some(&salt), None);
            workblock.extend_from_slice(&derived);
        }
        
        // Verify workblock size
        assert_eq!(workblock.len(), 256 * expand_rounds as usize);
        
        // Verify determinism - should get same result on second run
        let mut workblock2 = Vec::new();
        for n in 0..expand_rounds {
            let n_bytes = n.to_le_bytes();
            let mut hasher = Sha256::new();
            hasher.update(message_id);
            hasher.update(&n_bytes);
            let salt = hasher.finalize();
            let derived = hkdf(256, message_id, Some(&salt), None);
            workblock2.extend_from_slice(&derived);
        }
        
        assert_eq!(workblock, workblock2);
    }

    #[test]
    fn test_hkdf_different_contexts_different_outputs() {
        let ikm = b"test ikm";
        let salt = b"salt";
        let info1 = b"context1";
        let info2 = b"context2";
        
        let derived1 = hkdf(32, ikm, Some(salt), Some(info1));
        let derived2 = hkdf(32, ikm, Some(salt), Some(info2));
        
        assert_ne!(derived1, derived2);
    }
}
