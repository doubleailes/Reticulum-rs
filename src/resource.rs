use alloc::sync::Arc;
use alloc::vec::Vec;
use log::{trace, warn};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

use crate::destination::link::{Link, LinkResourcePacket};
use crate::error::RnsError;
use crate::hash::{Hash, HASH_SIZE};
use crate::packet::{Packet, PacketContext, PacketType, PACKET_MDU};
use crate::transport::Transport;

const WINDOW: usize = 4;
const RANDOM_HASH_SIZE: usize = 4;
const MAPHASH_LEN: usize = 4;
const RESOURCE_ADV_OVERHEAD: usize = 134;
const MAX_PARTS: usize = (PACKET_MDU - RESOURCE_ADV_OVERHEAD) / MAPHASH_LEN;
const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceStrategy {
    AcceptNone,
    AcceptAll,
}

#[derive(Debug)]
pub enum ResourceEvent {
    IncomingAccepted {
        hash: Hash,
        total_size: u64,
    },
    IncomingProgress {
        hash: Hash,
        received_parts: usize,
        total_parts: usize,
    },
    IncomingComplete {
        hash: Hash,
        data: Vec<u8>,
    },
    OutgoingComplete {
        hash: Hash,
    },
}

#[derive(Debug)]
pub enum ResourceError {
    Unsupported(&'static str),
    Invalid(&'static str),
    UnknownResource,
    Crypto(RnsError),
    Encode(rmp_serde::encode::Error),
    Decode(rmp_serde::decode::Error),
}

impl From<RnsError> for ResourceError {
    fn from(value: RnsError) -> Self {
        Self::Crypto(value)
    }
}

impl From<rmp_serde::encode::Error> for ResourceError {
    fn from(value: rmp_serde::encode::Error) -> Self {
        Self::Encode(value)
    }
}

impl From<rmp_serde::decode::Error> for ResourceError {
    fn from(value: rmp_serde::decode::Error) -> Self {
        Self::Decode(value)
    }
}

pub struct ResourceManager {
    link: Arc<Mutex<Link>>,
    outgoing: HashMap<Hash, OutgoingResource>,
    incoming: HashMap<Hash, IncomingResource>,
    strategy: ResourceStrategy,
}

impl ResourceManager {
    pub fn new(link: Arc<Mutex<Link>>) -> Self {
        Self {
            link,
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            strategy: ResourceStrategy::AcceptAll,
        }
    }

    pub fn set_strategy(&mut self, strategy: ResourceStrategy) {
        self.strategy = strategy;
    }

    pub async fn send(
        &mut self,
        transport: &Transport,
        data: Vec<u8>,
    ) -> Result<Hash, ResourceError> {
        let link = self.link.lock().await;
        let resource = OutgoingResource::new(&link, data)?;

        if resource.parts.len() > MAX_PARTS {
            return Err(ResourceError::Unsupported(
                "resource too large for current advertisement capacity",
            ));
        }

        let payload = resource.advertisement_payload()?;
        let packet = link.encrypted_context_packet(
            PacketContext::ResourceAdvrtisement,
            PacketType::Data,
            &payload,
        )?;
        drop(link);

        let _ = transport.send_packet(packet).await;
        let hash = resource.hash;
        self.outgoing.insert(hash, resource);
        Ok(hash)
    }

    pub async fn handle_packet(
        &mut self,
        transport: &Transport,
        message: &LinkResourcePacket,
    ) -> Result<Vec<ResourceEvent>, ResourceError> {
        match message.context {
            PacketContext::ResourceAdvrtisement => {
                self.handle_advertisement(transport, message.payload.as_slice())
                    .await
            }
            PacketContext::ResourceRequest => {
                self.handle_request(transport, message.payload.as_slice())
                    .await
            }
            PacketContext::Resource => {
                self.handle_data_part(transport, message.payload.as_slice())
                    .await
            }
            PacketContext::ResourceProof => self.handle_proof(message.payload.as_slice()),
            _ => Ok(Vec::new()),
        }
    }

    async fn handle_advertisement(
        &mut self,
        transport: &Transport,
        payload: &[u8],
    ) -> Result<Vec<ResourceEvent>, ResourceError> {
        if self.strategy == ResourceStrategy::AcceptNone {
            return Ok(Vec::new());
        }

        let adv = ResourceAdvertisementOwned::from_slice(payload)?;
        let mut adv_hash_bytes = [0u8; HASH_SIZE];
        adv_hash_bytes.copy_from_slice(adv.hash.as_slice());
        let adv_hash = Hash::new(adv_hash_bytes);

        if adv.parts as usize > MAX_PARTS {
            warn!("resource advertisement exceeds supported size, ignoring");
            return Ok(Vec::new());
        }

        if self.incoming.contains_key(&adv_hash) {
            trace!("resource {:?} already transferring", adv.hash);
            return Ok(Vec::new());
        }

        let mut resource = IncomingResource::new(adv)?;
        let mut events = Vec::new();
        events.push(ResourceEvent::IncomingAccepted {
            hash: resource.hash,
            total_size: resource.total_size,
        });

        if let Some(request_payload) = resource.next_request_payload() {
            let (packet, link_id, origin_iface) = {
                let link = self.link.lock().await;
                let link_id = *link.id();
                let origin_iface = link.origin_interface();
                log::info!(
                    "ResourceRequest: creating packet for link {} (origin_interface: {:?})",
                    link_id,
                    origin_iface
                );
                let packet = link.encrypted_context_packet(
                    PacketContext::ResourceRequest,
                    PacketType::Data,
                    &request_payload,
                )?;
                (packet, link_id, origin_iface)
            };
            log::info!(
                "ResourceRequest: sending packet - dest={} context={:?} origin_interface={:?}",
                link_id,
                packet.context,
                origin_iface
            );
            let _ = transport.send_packet(packet).await;
        }

        self.incoming.insert(resource.hash, resource);
        Ok(events)
    }

    async fn handle_request(
        &mut self,
        transport: &Transport,
        payload: &[u8],
    ) -> Result<Vec<ResourceEvent>, ResourceError> {
        let request = ResourceRequest::parse(payload)?;
        let resource = match self.outgoing.get(&request.hash) {
            Some(res) => res,
            None => return Ok(Vec::new()),
        };

        let packets = {
            let link = self.link.lock().await;
            resource.build_packets(&link, &request)?
        };

        for packet in packets {
            let _ = transport.send_packet(packet).await;
        }

        Ok(Vec::new())
    }

    async fn handle_data_part(
        &mut self,
        transport: &Transport,
        payload: &[u8],
    ) -> Result<Vec<ResourceEvent>, ResourceError> {
        let mut target = None;
        for (hash, resource) in self.incoming.iter() {
            if resource.matches_chunk(payload) {
                target = Some(*hash);
                break;
            }
        }

        let hash = match target {
            Some(hash) => hash,
            None => return Ok(Vec::new()),
        };

        let resource = self
            .incoming
            .get_mut(&hash)
            .ok_or(ResourceError::UnknownResource)?;

        let mut events = Vec::new();
        if let Some(progress) = resource.store_chunk(payload) {
            events.push(ResourceEvent::IncomingProgress {
                hash,
                received_parts: progress.received,
                total_parts: progress.total,
            });
        }

        if let Some(request_payload) = resource.next_request_payload() {
            let packet = {
                let link = self.link.lock().await;
                link.encrypted_context_packet(
                    PacketContext::ResourceRequest,
                    PacketType::Data,
                    &request_payload,
                )?
            };
            let _ = transport.send_packet(packet).await;
        }

        if resource.is_complete() {
            let data = {
                let link = self.link.lock().await;
                resource.assemble(&link)?
            };

            let proof_packet = {
                let link = self.link.lock().await;
                let payload = resource.proof_payload(&data);
                link.context_packet(PacketContext::ResourceProof, PacketType::Proof, &payload)?
            };
            let _ = transport.send_packet(proof_packet).await;

            events.push(ResourceEvent::IncomingComplete { hash, data });
            self.incoming.remove(&hash);
        }

        Ok(events)
    }

    fn handle_proof(&mut self, payload: &[u8]) -> Result<Vec<ResourceEvent>, ResourceError> {
        if payload.len() < HASH_SIZE * 2 {
            return Err(ResourceError::Invalid("resource proof too small"));
        }

        let mut hash_bytes = [0u8; HASH_SIZE];
        hash_bytes.copy_from_slice(&payload[..HASH_SIZE]);
        let hash = Hash::new(hash_bytes);
        let proof = &payload[HASH_SIZE..];

        if let Some(resource) = self.outgoing.get(&hash) {
            if resource.validate_proof(proof) {
                self.outgoing.remove(&hash);
                return Ok(vec![ResourceEvent::OutgoingComplete { hash }]);
            }
        }

        Ok(Vec::new())
    }
}

struct ResourceRequest {
    hash: Hash,
    map_hashes: Vec<[u8; MAPHASH_LEN]>,
}

impl ResourceRequest {
    fn parse(payload: &[u8]) -> Result<Self, ResourceError> {
        if payload.is_empty() {
            return Err(ResourceError::Invalid("empty resource request"));
        }

        if payload[0] != HASHMAP_IS_NOT_EXHAUSTED {
            return Err(ResourceError::Unsupported(
                "hashmap updates are not supported",
            ));
        }

        if payload.len() < 1 + HASH_SIZE {
            return Err(ResourceError::Invalid("request missing hash"));
        }

        let mut hash_bytes = [0u8; HASH_SIZE];
        hash_bytes.copy_from_slice(&payload[1..1 + HASH_SIZE]);
        let hash = Hash::new(hash_bytes);

        let mut hashes = Vec::new();
        let mut offset = 1 + HASH_SIZE;
        while offset + MAPHASH_LEN <= payload.len() {
            let mut entry = [0u8; MAPHASH_LEN];
            entry.copy_from_slice(&payload[offset..offset + MAPHASH_LEN]);
            hashes.push(entry);
            offset += MAPHASH_LEN;
        }

        Ok(Self {
            hash,
            map_hashes: hashes,
        })
    }
}

struct OutgoingResource {
    hash: Hash,
    random_hash: [u8; RANDOM_HASH_SIZE],
    expected_proof: [u8; HASH_SIZE],
    total_size: u64,
    transfer_size: u64,
    parts: Vec<ResourcePart>,
    lookup: HashMap<[u8; MAPHASH_LEN], usize>,
}

impl OutgoingResource {
    fn new(link: &Link, data: Vec<u8>) -> Result<Self, ResourceError> {
        if data.is_empty() {
            return Err(ResourceError::Invalid("resource data empty"));
        }

        let mut random_hash = [0u8; RANDOM_HASH_SIZE];
        OsRng.fill_bytes(&mut random_hash);

        let mut plaintext = Vec::with_capacity(RANDOM_HASH_SIZE + data.len());
        plaintext.extend_from_slice(&random_hash);
        plaintext.extend_from_slice(&data);

        let mut cipher_buf = vec![0u8; plaintext.len() + PACKET_MDU];
        let cipher = link.encrypt(&plaintext, &mut cipher_buf)?;
        let ciphertext = cipher.to_vec();

        let hash_bytes = digest_with_suffix(&data, &random_hash);
        let proof_bytes = digest_with_suffix(&data, &hash_bytes);

        let mut parts = Vec::new();
        let mut lookup = HashMap::new();
        for chunk in ciphertext.chunks(PACKET_MDU) {
            let map_hash = map_hash(chunk, &random_hash);
            lookup.insert(map_hash, parts.len());
            parts.push(ResourcePart {
                map_hash,
                data: chunk.to_vec(),
            });
        }

        Ok(Self {
            hash: Hash::new(hash_bytes),
            random_hash,
            expected_proof: proof_bytes,
            total_size: data.len() as u64,
            transfer_size: ciphertext.len() as u64,
            parts,
            lookup,
        })
    }

    fn advertisement_payload(&self) -> Result<Vec<u8>, ResourceError> {
        let hashmap_bytes = self
            .parts
            .iter()
            .flat_map(|part| part.map_hash)
            .collect::<Vec<u8>>();

        let payload = ResourceAdvertisementPayload {
            transfer_size: self.transfer_size,
            data_size: self.total_size,
            parts: self.parts.len() as u32,
            hash: self.hash.as_slice(),
            random_hash: &self.random_hash,
            original_hash: self.hash.as_slice(),
            segment_index: 1,
            total_segments: 1,
            request_id: None,
            flags: 0x01,
            hashmap: &hashmap_bytes,
        };

        Ok(rmp_serde::to_vec_named(&payload)?)
    }

    fn build_packets(
        &self,
        link: &Link,
        request: &ResourceRequest,
    ) -> Result<Vec<Packet>, ResourceError> {
        let mut packets = Vec::new();
        for map_hash in &request.map_hashes {
            if let Some(index) = self.lookup.get(map_hash) {
                let part = &self.parts[*index];
                let packet =
                    link.context_packet(PacketContext::Resource, PacketType::Data, &part.data)?;
                packets.push(packet);
            }
        }
        Ok(packets)
    }

    fn validate_proof(&self, proof: &[u8]) -> bool {
        proof == self.expected_proof
    }
}

struct ResourcePart {
    map_hash: [u8; MAPHASH_LEN],
    data: Vec<u8>,
}

struct IncomingResource {
    hash: Hash,
    random_hash: [u8; RANDOM_HASH_SIZE],
    total_size: u64,
    total_parts: usize,
    hashmap: Vec<[u8; MAPHASH_LEN]>,
    parts: Vec<Option<Vec<u8>>>,
    pending: HashSet<usize>,
}

struct ProgressUpdate {
    received: usize,
    total: usize,
}

impl IncomingResource {
    fn new(adv: ResourceAdvertisementOwned) -> Result<Self, ResourceError> {
        if adv.flags & 0x01 == 0 {
            return Err(ResourceError::Unsupported(
                "unencrypted resources unsupported",
            ));
        }
        if adv.flags & 0x02 != 0 {
            return Err(ResourceError::Unsupported(
                "compressed resources unsupported",
            ));
        }
        if adv.flags & 0x04 != 0 {
            return Err(ResourceError::Unsupported("split resources unsupported"));
        }

        let mut hash_bytes = [0u8; HASH_SIZE];
        hash_bytes.copy_from_slice(adv.hash.as_slice());
        let mut random_hash = [0u8; RANDOM_HASH_SIZE];
        random_hash.copy_from_slice(adv.random_hash.as_slice());

        let parts = adv.parts as usize;
        let hashmap_slice = adv.hashmap.as_slice();
        let hashmap_entries = hashmap_slice.len() / MAPHASH_LEN;
        if hashmap_entries != parts {
            return Err(ResourceError::Unsupported(
                "hashmap updates are not supported",
            ));
        }

        let mut hashmap = Vec::with_capacity(parts);
        for chunk in hashmap_slice.chunks_exact(MAPHASH_LEN) {
            let mut entry = [0u8; MAPHASH_LEN];
            entry.copy_from_slice(chunk);
            hashmap.push(entry);
        }

        Ok(Self {
            hash: Hash::new(hash_bytes),
            random_hash,
            total_size: adv.data_size,
            total_parts: parts,
            hashmap,
            parts: vec![None; parts],
            pending: HashSet::new(),
        })
    }

    fn matches_chunk(&self, data: &[u8]) -> bool {
        let map_hash = map_hash(data, &self.random_hash);
        self.hashmap.iter().any(|entry| entry == &map_hash)
    }

    fn store_chunk(&mut self, data: &[u8]) -> Option<ProgressUpdate> {
        let map_hash = map_hash(data, &self.random_hash);
        if let Some(index) = self.hashmap.iter().position(|entry| entry == &map_hash) {
            if self.parts[index].is_none() {
                self.parts[index] = Some(data.to_vec());
                self.pending.remove(&index);
                let received = self.parts.iter().filter(|part| part.is_some()).count();
                return Some(ProgressUpdate {
                    received,
                    total: self.total_parts,
                });
            }
        }
        None
    }

    fn next_request_payload(&mut self) -> Option<Vec<u8>> {
        if self.is_complete() {
            return None;
        }

        let mut hashes = Vec::new();
        for idx in 0..self.total_parts {
            if hashes.len() >= WINDOW {
                break;
            }
            if self.parts[idx].is_none() && !self.pending.contains(&idx) {
                hashes.push(self.hashmap[idx]);
                self.pending.insert(idx);
            }
        }

        if hashes.is_empty() {
            return None;
        }

        let mut payload = Vec::with_capacity(1 + HASH_SIZE + hashes.len() * MAPHASH_LEN);
        payload.push(HASHMAP_IS_NOT_EXHAUSTED);
        payload.extend_from_slice(self.hash.as_slice());
        for entry in hashes {
            payload.extend_from_slice(&entry);
        }

        Some(payload)
    }

    fn is_complete(&self) -> bool {
        self.parts.iter().all(|part| part.is_some())
    }

    fn assemble(&self, link: &Link) -> Result<Vec<u8>, ResourceError> {
        if !self.is_complete() {
            return Err(ResourceError::Invalid("resource not complete"));
        }

        let mut ciphertext = Vec::new();
        for part in &self.parts {
            ciphertext.extend_from_slice(part.as_ref().expect("complete part"));
        }

        let mut out_buf = vec![0u8; ciphertext.len() + PACKET_MDU];
        let plaintext = link.decrypt(&ciphertext, &mut out_buf)?;
        if plaintext.len() <= RANDOM_HASH_SIZE {
            return Err(ResourceError::Invalid("plaintext shorter than random hash"));
        }

        let payload = plaintext[RANDOM_HASH_SIZE..].to_vec();
        let hash_bytes = digest_with_suffix(&payload, &self.random_hash);
        if hash_bytes != *self.hash.as_slice() {
            return Err(ResourceError::Invalid("resource hash mismatch"));
        }

        Ok(payload)
    }

    fn proof_payload(&self, data: &[u8]) -> Vec<u8> {
        let proof_bytes = digest_with_suffix(data, self.hash.as_slice());
        let mut payload = Vec::with_capacity(HASH_SIZE * 2);
        payload.extend_from_slice(self.hash.as_slice());
        payload.extend_from_slice(&proof_bytes);
        payload
    }
}

#[derive(Serialize)]
struct ResourceAdvertisementPayload<'a> {
    #[serde(rename = "t")]
    transfer_size: u64,
    #[serde(rename = "d")]
    data_size: u64,
    #[serde(rename = "n")]
    parts: u32,
    #[serde(rename = "h", with = "serde_bytes")]
    hash: &'a [u8],
    #[serde(rename = "r", with = "serde_bytes")]
    random_hash: &'a [u8],
    #[serde(rename = "o", with = "serde_bytes")]
    original_hash: &'a [u8],
    #[serde(rename = "i")]
    segment_index: u32,
    #[serde(rename = "l")]
    total_segments: u32,
    #[serde(rename = "q", with = "serde_bytes")]
    request_id: Option<&'a [u8]>,
    #[serde(rename = "f")]
    flags: u8,
    #[serde(rename = "m", with = "serde_bytes")]
    hashmap: &'a [u8],
}

#[derive(Deserialize)]
struct ResourceAdvertisementOwned {
    #[serde(rename = "t")]
    transfer_size: u64,
    #[serde(rename = "d")]
    data_size: u64,
    #[serde(rename = "n")]
    parts: u32,
    #[serde(rename = "h", with = "serde_bytes")]
    hash: ByteBuf,
    #[serde(rename = "r", with = "serde_bytes")]
    random_hash: ByteBuf,
    #[serde(rename = "o", with = "serde_bytes")]
    original_hash: ByteBuf,
    #[serde(rename = "i")]
    segment_index: u32,
    #[serde(rename = "l")]
    total_segments: u32,
    #[serde(rename = "q", with = "serde_bytes")]
    request_id: Option<ByteBuf>,
    #[serde(rename = "f")]
    flags: u8,
    #[serde(rename = "m", with = "serde_bytes")]
    hashmap: ByteBuf,
}

impl ResourceAdvertisementOwned {
    fn from_slice(data: &[u8]) -> Result<Self, ResourceError> {
        Ok(rmp_serde::from_slice(data)?)
    }
}

fn digest_with_suffix(data: &[u8], suffix: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(suffix);
    let mut bytes = [0u8; HASH_SIZE];
    bytes.copy_from_slice(&hasher.finalize());
    bytes
}

fn map_hash(data: &[u8], random_hash: &[u8; RANDOM_HASH_SIZE]) -> [u8; MAPHASH_LEN] {
    let digest = digest_with_suffix(data, random_hash);
    let mut value = [0u8; MAPHASH_LEN];
    value.copy_from_slice(&digest[..MAPHASH_LEN]);
    value
}
