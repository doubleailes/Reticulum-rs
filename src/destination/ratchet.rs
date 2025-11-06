use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    error::RnsError,
    hash::AddressHash,
    identity::{DERIVED_KEY_LENGTH, DerivedKey},
};

/// Ratchet rotation interval - rotate keys every announce
pub const RATCHET_ROTATION_INTERVAL: u32 = 1;

/// Maximum number of old keys to keep for decryption
pub const RATCHET_MAX_OLD_KEYS: usize = 16;

/// A single ratchet key with its sequence number
#[derive(Clone, Debug)]
pub struct RatchetKey {
    pub sequence: u32,
    pub key: [u8; DERIVED_KEY_LENGTH],
}

impl Serialize for RatchetKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RatchetKey", 2)?;
        state.serialize_field("sequence", &self.sequence)?;
        state.serialize_field("key", &self.key.to_vec())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RatchetKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Sequence,
            Key,
        }

        struct RatchetKeyVisitor;

        impl<'de> Visitor<'de> for RatchetKeyVisitor {
            type Value = RatchetKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct RatchetKey")
            }

            fn visit_map<V>(self, mut map: V) -> Result<RatchetKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut sequence = None;
                let mut key = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        Field::Sequence => {
                            if sequence.is_some() {
                                return Err(de::Error::duplicate_field("sequence"));
                            }
                            sequence = Some(map.next_value()?);
                        }
                        Field::Key => {
                            if key.is_some() {
                                return Err(de::Error::duplicate_field("key"));
                            }
                            let key_vec: Vec<u8> = map.next_value()?;
                            if key_vec.len() != DERIVED_KEY_LENGTH {
                                return Err(de::Error::invalid_length(
                                    key_vec.len(),
                                    &"DERIVED_KEY_LENGTH bytes",
                                ));
                            }
                            let mut key_array = [0u8; DERIVED_KEY_LENGTH];
                            key_array.copy_from_slice(&key_vec);
                            key = Some(key_array);
                        }
                    }
                }
                let sequence = sequence.ok_or_else(|| de::Error::missing_field("sequence"))?;
                let key = key.ok_or_else(|| de::Error::missing_field("key"))?;
                Ok(RatchetKey { sequence, key })
            }
        }

        const FIELDS: &[&str] = &["sequence", "key"];
        deserializer.deserialize_struct("RatchetKey", FIELDS, RatchetKeyVisitor)
    }
}

impl RatchetKey {
    pub fn new<R: CryptoRngCore>(mut rng: R, sequence: u32) -> Self {
        let mut key = [0u8; DERIVED_KEY_LENGTH];
        rng.fill_bytes(&mut key);
        Self { sequence, key }
    }

    pub fn derive_next<R: CryptoRngCore>(&self, _rng: R) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(&self.sequence.to_be_bytes());

        let hash = hasher.finalize();
        let mut new_key = [0u8; DERIVED_KEY_LENGTH];

        // Use hash as seed for new key generation
        if DERIVED_KEY_LENGTH <= 32 {
            new_key[..DERIVED_KEY_LENGTH].copy_from_slice(&hash[..DERIVED_KEY_LENGTH]);
        } else {
            // For larger keys, use the hash as a seed for additional randomness
            new_key[..32].copy_from_slice(&hash);
            // Fill remaining bytes with additional hash rounds
            for i in 1..(DERIVED_KEY_LENGTH / 32 + 1) {
                let mut hasher = Sha256::new();
                hasher.update(&hash);
                hasher.update(&i.to_be_bytes());
                let additional_hash = hasher.finalize();
                let start = i * 32;
                let end = std::cmp::min(start + 32, DERIVED_KEY_LENGTH);
                if start < DERIVED_KEY_LENGTH {
                    new_key[start..end].copy_from_slice(&additional_hash[..end - start]);
                }
            }
        }

        Self {
            sequence: self.sequence + 1,
            key: new_key,
        }
    }

    pub fn as_derived_key(&self) -> DerivedKey {
        DerivedKey::new_from_bytes(&self.key)
    }
}

/// Ratchet state for a destination
#[derive(Clone, Debug)]
pub struct RatchetState {
    /// Current sequence number
    pub current_sequence: u32,
    /// Current encryption key
    pub current_key: RatchetKey,
    /// Previous keys for decryption (oldest to newest)
    pub old_keys: Vec<RatchetKey>,
    /// Destination hash this ratchet belongs to
    pub destination_hash: AddressHash,
    /// File path for persistence
    pub file_path: Option<PathBuf>,
}

impl Serialize for RatchetState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RatchetState", 4)?;
        state.serialize_field("current_sequence", &self.current_sequence)?;
        state.serialize_field("current_key", &self.current_key)?;
        state.serialize_field("old_keys", &self.old_keys)?;
        state.serialize_field("destination_hash", &self.destination_hash.as_slice())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RatchetState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            CurrentSequence,
            CurrentKey,
            OldKeys,
            DestinationHash,
        }

        struct RatchetStateVisitor;

        impl<'de> Visitor<'de> for RatchetStateVisitor {
            type Value = RatchetState;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct RatchetState")
            }

            fn visit_map<V>(self, mut map: V) -> Result<RatchetState, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut current_sequence = None;
                let mut current_key = None;
                let mut old_keys = None;
                let mut destination_hash = None;

                while let Some(k) = map.next_key()? {
                    match k {
                        Field::CurrentSequence => {
                            if current_sequence.is_some() {
                                return Err(de::Error::duplicate_field("current_sequence"));
                            }
                            current_sequence = Some(map.next_value()?);
                        }
                        Field::CurrentKey => {
                            if current_key.is_some() {
                                return Err(de::Error::duplicate_field("current_key"));
                            }
                            current_key = Some(map.next_value()?);
                        }
                        Field::OldKeys => {
                            if old_keys.is_some() {
                                return Err(de::Error::duplicate_field("old_keys"));
                            }
                            old_keys = Some(map.next_value()?);
                        }
                        Field::DestinationHash => {
                            if destination_hash.is_some() {
                                return Err(de::Error::duplicate_field("destination_hash"));
                            }
                            let hash_vec: Vec<u8> = map.next_value()?;
                            if hash_vec.len() != 16 {
                                return Err(de::Error::invalid_length(hash_vec.len(), &"16 bytes"));
                            }
                            let mut hash_array = [0u8; 16];
                            hash_array.copy_from_slice(&hash_vec);
                            destination_hash = Some(AddressHash::new(hash_array));
                        }
                    }
                }

                let current_sequence =
                    current_sequence.ok_or_else(|| de::Error::missing_field("current_sequence"))?;
                let current_key =
                    current_key.ok_or_else(|| de::Error::missing_field("current_key"))?;
                let old_keys = old_keys.ok_or_else(|| de::Error::missing_field("old_keys"))?;
                let destination_hash =
                    destination_hash.ok_or_else(|| de::Error::missing_field("destination_hash"))?;

                Ok(RatchetState {
                    current_sequence,
                    current_key,
                    old_keys,
                    destination_hash,
                    file_path: None, // Will be set after loading
                })
            }
        }

        const FIELDS: &[&str] = &[
            "current_sequence",
            "current_key",
            "old_keys",
            "destination_hash",
        ];
        deserializer.deserialize_struct("RatchetState", FIELDS, RatchetStateVisitor)
    }
}

impl RatchetState {
    /// Create a new ratchet state
    pub fn new<R: CryptoRngCore>(
        mut rng: R,
        destination_hash: AddressHash,
        file_path: Option<PathBuf>,
    ) -> Self {
        let current_key = RatchetKey::new(&mut rng, 0);

        Self {
            current_sequence: 0,
            current_key,
            old_keys: Vec::new(),
            destination_hash,
            file_path,
        }
    }

    /// Rotate to the next key
    pub fn rotate_key<R: CryptoRngCore>(&mut self, rng: R) -> Result<(), RnsError> {
        // Move current key to old keys
        self.old_keys.push(self.current_key.clone());

        // Keep only the most recent old keys
        if self.old_keys.len() > RATCHET_MAX_OLD_KEYS {
            self.old_keys.remove(0);
        }

        // Generate new current key
        self.current_key = self.current_key.derive_next(rng);
        self.current_sequence = self.current_key.sequence;

        // Persist the state
        self.save()?;

        Ok(())
    }

    /// Get current key for encryption
    pub fn current_derived_key(&self) -> DerivedKey {
        self.current_key.as_derived_key()
    }

    /// Try to decrypt with current or old keys
    pub fn try_decrypt_keys(&self) -> Vec<DerivedKey> {
        let mut keys = vec![self.current_key.as_derived_key()];

        // Add old keys in reverse order (newest first)
        for key in self.old_keys.iter().rev() {
            keys.push(key.as_derived_key());
        }

        keys
    }

    /// Save ratchet state to file
    pub fn save(&self) -> Result<(), RnsError> {
        if let Some(path) = &self.file_path {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .map_err(|_| RnsError::IoError)?;

            let writer = BufWriter::new(file);
            serde_json::to_writer(writer, self).map_err(|_| RnsError::SerializationError)?;
        }
        Ok(())
    }

    /// Load ratchet state from file
    pub fn load(destination_hash: AddressHash, file_path: PathBuf) -> Result<Self, RnsError> {
        let file = File::open(&file_path).map_err(|_| RnsError::IoError)?;

        let reader = BufReader::new(file);
        let mut state: RatchetState =
            serde_json::from_reader(reader).map_err(|_| RnsError::SerializationError)?;

        // Verify destination hash matches
        if state.destination_hash != destination_hash {
            return Err(RnsError::InvalidHash);
        }

        state.file_path = Some(file_path);
        Ok(state)
    }

    /// Load or create ratchet state
    pub fn load_or_create<R: CryptoRngCore>(
        rng: R,
        destination_hash: AddressHash,
        file_path: PathBuf,
    ) -> Self {
        match Self::load(destination_hash, file_path.clone()) {
            Ok(state) => state,
            Err(_) => {
                // Create new state if loading fails
                let state = Self::new(rng, destination_hash, Some(file_path));
                let _ = state.save(); // Ignore save errors during creation
                state
            }
        }
    }
}

/// Manager for multiple ratchet states
#[derive(Default)]
pub struct RatchetManager {
    ratchets: Arc<RwLock<HashMap<AddressHash, RatchetState>>>,
}

impl RatchetManager {
    pub fn new() -> Self {
        Self {
            ratchets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Enable ratchets for a destination
    pub fn enable_ratchets<R: CryptoRngCore>(
        &self,
        rng: R,
        destination_hash: AddressHash,
        file_path: PathBuf,
    ) -> Result<(), RnsError> {
        let state = RatchetState::load_or_create(rng, destination_hash, file_path);

        let mut ratchets = self.ratchets.write().map_err(|_| RnsError::LockError)?;

        ratchets.insert(destination_hash, state);
        Ok(())
    }

    /// Rotate ratchet for a destination (called on announce)
    pub fn rotate_ratchet<R: CryptoRngCore>(
        &self,
        rng: R,
        destination_hash: AddressHash,
    ) -> Result<(), RnsError> {
        let mut ratchets = self.ratchets.write().map_err(|_| RnsError::LockError)?;

        if let Some(state) = ratchets.get_mut(&destination_hash) {
            state.rotate_key(rng)?;
        }

        Ok(())
    }

    /// Get current encryption key for a destination
    pub fn get_encryption_key(&self, destination_hash: AddressHash) -> Option<DerivedKey> {
        let ratchets = self.ratchets.read().ok()?;
        ratchets
            .get(&destination_hash)
            .map(|state| state.current_derived_key())
    }

    /// Get keys for decryption attempts (current + old keys)
    pub fn get_decryption_keys(&self, destination_hash: AddressHash) -> Vec<DerivedKey> {
        self.ratchets
            .read()
            .map(|r| {
                r.get(&destination_hash)
                    .map(|state| state.try_decrypt_keys())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Check if ratchets are enabled for a destination
    pub fn is_enabled(&self, destination_hash: AddressHash) -> bool {
        self.ratchets
            .read()
            .map(|r| r.contains_key(&destination_hash))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_ratchet_key_creation() {
        let key = RatchetKey::new(OsRng, 0);
        assert_eq!(key.sequence, 0);
        assert_ne!(key.key, [0u8; DERIVED_KEY_LENGTH]);
    }

    #[test]
    fn test_ratchet_key_derivation() {
        let key1 = RatchetKey::new(OsRng, 0);
        let key2 = key1.derive_next(OsRng);

        assert_eq!(key2.sequence, 1);
        assert_ne!(key1.key, key2.key);
    }

    #[test]
    fn test_ratchet_state() {
        let destination_hash = AddressHash::new([1u8; 16]);
        let mut state = RatchetState::new(OsRng, destination_hash, None);

        assert_eq!(state.current_sequence, 0);
        assert_eq!(state.old_keys.len(), 0);

        // Rotate key
        state.rotate_key(OsRng).unwrap();

        assert_eq!(state.current_sequence, 1);
        assert_eq!(state.old_keys.len(), 1);
    }
}
