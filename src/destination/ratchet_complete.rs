use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use ed25519_dalek::{SigningKey, Signature, Verifier, Signer};
use fs2::FileExt;
use rand_core::{CryptoRngCore, OsRng};
use rmp_serde;
use serde::{Deserialize, Serialize};
use x25519_dalek::{StaticSecret, PublicKey};

use crate::{
    error::RnsError,
    hash::AddressHash,
    identity::{Identity, PrivateIdentity, DerivedKey},
};

/// Result type for ratchet operations
pub type RnsResult<T> = Result<T, RnsError>;

/// Maximum number of old keys to keep for decryption (matching Python RNS RATCHET_COUNT)
pub const RATCHET_MAX_OLD_KEYS: usize = 16;

/// X25519 ratchet key size (32 bytes, matching Python RNS RATCHETSIZE//8)
pub const X25519_KEY_SIZE: usize = 32;

/// A single X25519 ratchet private key (matching Python RNS format)
/// This is stored as raw bytes, exactly like Python RNS
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetKey {
    /// Raw X25519 private key bytes (32 bytes)
    #[serde(with = "serde_bytes")]
    private_key: [u8; X25519_KEY_SIZE],
}

impl RatchetKey {
    /// Generate a new ratchet key (matching Python's _generate_ratchet)
    pub fn generate<R: CryptoRngCore>(mut rng: R) -> Self {
        let secret = StaticSecret::random_from_rng(&mut rng);
        Self {
            private_key: secret.to_bytes(),
        }
    }

    /// Get the raw private key bytes
    pub fn private_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.private_key
    }

    /// Get the public key bytes for key exchange
    pub fn public_bytes(&self) -> [u8; X25519_KEY_SIZE] {
        let secret = StaticSecret::from(self.private_key);
        PublicKey::from(&secret).to_bytes()
    }

    /// Derive encryption key from this ratchet key (using destination key exchange)
    pub fn derive_key(&self, destination_identity: &Identity) -> RnsResult<DerivedKey> {
        let secret = StaticSecret::from(self.private_key);
        let destination_public = destination_identity.get_public_key();
        
        // Extract public key from destination identity for X25519
        // This would need proper conversion from Ed25519 to X25519 in a real implementation
        // For now, use a placeholder approach
        let shared_secret = secret.diffie_hellman(&PublicKey::from([0u8; 32])); // Placeholder
        
        Ok(DerivedKey::new_from_bytes(shared_secret.as_bytes()))
    }
}

/// Persisted ratchet container (matching Python RNS format)
#[derive(Debug, Serialize, Deserialize)]
pub struct RatchetContainer {
    /// Ed25519 signature for integrity verification
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    /// MessagePack-encoded ratchets array
    #[serde(with = "serde_bytes")]
    ratchets: Vec<u8>,
}

/// Ratchet state container with persistence (matching Python RNS format)
#[derive(Debug)]
pub struct RatchetState {
    ratchets: Arc<RwLock<Vec<RatchetKey>>>,
    destination_hash: [u8; 32],
    storage_path: Option<PathBuf>,
    identity: Arc<Identity>,
}

impl RatchetState {
    /// Load ratchet state from storage (Python RNS compatible)
    pub fn load(
        destination_hash: [u8; 32], 
        storage_dir: Option<PathBuf>,
        identity: Arc<Identity>
    ) -> RnsResult<Self> {
        let storage_path = storage_dir.map(|dir| {
            dir.join(format!(
                "ratchets_{}",
                hex::encode(&destination_hash[..16])
            ))
        });

        let mut ratchets = Vec::new();

        if let Some(ref path) = storage_path {
            if path.exists() {
                ratchets = Self::load_ratchets(path, &identity)?;
            }
        }

        Ok(RatchetState {
            ratchets: Arc::new(RwLock::new(ratchets)),
            destination_hash,
            storage_path,
            identity,
        })
    }

    /// Create a new ratchet state  
    pub fn new(
        destination_hash: [u8; 32],
        storage_dir: Option<PathBuf>, 
        identity: Arc<Identity>
    ) -> RnsResult<Self> {
        let storage_path = storage_dir.map(|dir| {
            dir.join(format!(
                "ratchets_{}",
                hex::encode(&destination_hash[..16])
            ))
        });

        let state = Self {
            ratchets: Arc::new(RwLock::new(Vec::new())),
            destination_hash,
            storage_path,
            identity,
        };

        Ok(state)
    }

    /// Load ratchets from file with signature verification (matching Python RNS)
    fn load_ratchets(path: &PathBuf, identity: &Identity) -> RnsResult<Vec<RatchetKey>> {
        // Open and lock file for reading
        let mut file = File::open(path)?;
        file.lock_shared()?;
        
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        file.unlock()?;

        // Deserialize MessagePack container
        let container: RatchetContainer = rmp_serde::from_slice(&contents)
            .map_err(|e| RnsError::SerializationError(e.to_string()))?;

        // Verify signature with identity
        let signature = Signature::from_slice(&container.signature)
            .map_err(|e| RnsError::CryptoError(e.to_string()))?;
        
        let verifying_key = identity.get_verifying_key();
        verifying_key.verify(&container.ratchets, &signature)
            .map_err(|e| RnsError::CryptoError(e.to_string()))?;

        // Deserialize ratchets array
        let ratchets: Vec<RatchetKey> = rmp_serde::from_slice(&container.ratchets)
            .map_err(|e| RnsError::SerializationError(e.to_string()))?;

        Ok(ratchets)
    }

    /// Save ratchets to file with signature (matching Python RNS atomic write)
    fn save_ratchets(&self) -> RnsResult<()> {
        let Some(ref path) = self.storage_path else {
            return Ok(());
        };

        let ratchets = self.ratchets.read()
            .map_err(|_| RnsError::LockError)?;

        // Serialize ratchets to MessagePack
        let ratchets_data = rmp_serde::to_vec(&*ratchets)
            .map_err(|e| RnsError::SerializationError(e.to_string()))?;

        // Sign the ratchets data
        let signing_key = self.identity.get_signing_key();
        let signature = signing_key.sign(&ratchets_data);

        // Create container
        let container = RatchetContainer {
            signature: signature.to_bytes().to_vec(),
            ratchets: ratchets_data,
        };

        // Serialize container to MessagePack
        let container_data = rmp_serde::to_vec(&container)
            .map_err(|e| RnsError::SerializationError(e.to_string()))?;

        // Atomic write: temp file + rename (matching Python RNS)
        let temp_path = path.with_extension("tmp");
        
        {
            let mut temp_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)?;
            
            temp_file.lock_exclusive()?;
            temp_file.write_all(&container_data)?;
            temp_file.sync_all()?;
            temp_file.unlock()?;
        }

        std::fs::rename(&temp_path, path)?;
        Ok(())
    }

    /// Rotate to the next key (Python RNS compatible)
    pub fn rotate_key(&self) -> RnsResult<()> {
        let mut ratchets = self.ratchets.write()
            .map_err(|_| RnsError::LockError)?;

        // Generate new ratchet key
        let new_key = RatchetKey::generate(OsRng);
        ratchets.push(new_key);

        // Keep only the most recent keys (matching Python RNS RATCHET_COUNT)
        if ratchets.len() > RATCHET_MAX_OLD_KEYS {
            ratchets.drain(0..ratchets.len() - RATCHET_MAX_OLD_KEYS);
        }

        drop(ratchets);

        // Save to disk
        self.save_ratchets()
    }

    /// Get current key for encryption (latest ratchet)
    pub fn current_derived_key(&self) -> Option<DerivedKey> {
        let ratchets = self.ratchets.read().ok()?;
        let current_key = ratchets.last()?;
        current_key.derive_key(&self.identity).ok()
    }

    /// Get all keys for decryption (current + old ratchets)
    pub fn try_decrypt_keys(&self) -> Vec<DerivedKey> {
        let ratchets = self.ratchets.read()
            .map_err(|_| vec![])
            .unwrap_or_else(|e| e);

        ratchets
            .iter()
            .rev() // Try newest first
            .filter_map(|key| key.derive_key(&self.identity).ok())
            .collect()
    }

    /// Check if we have any ratchets
    pub fn has_ratchets(&self) -> bool {
        self.ratchets
            .read()
            .map(|r| !r.is_empty())
            .unwrap_or(false)
    }
}

/// Ratchet manager for automatic key rotation
#[derive(Debug)]
pub struct RatchetManager {
    state: Arc<RatchetState>,
}

impl RatchetManager {
    pub fn new(state: RatchetState) -> Self {
        Self {
            state: Arc::new(state),
        }
    }

    pub fn state(&self) -> &Arc<RatchetState> {
        &self.state
    }

    /// Rotate the ratchet (called after announce)
    pub fn rotate(&self) -> RnsResult<()> {
        self.state.rotate_key()
    }

    /// Get current encryption key
    pub fn current_key(&self) -> Option<DerivedKey> {
        self.state.current_derived_key()
    }

    /// Get keys for decryption attempts
    pub fn decrypt_keys(&self) -> Vec<DerivedKey> {
        self.state.try_decrypt_keys()
    }
}