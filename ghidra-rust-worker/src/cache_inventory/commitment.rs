use anyhow::{Result, ensure};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cache::Snapshot;
use crate::configuration::validate_digest;
use crate::protocol::MAX_NAME_BYTES;

pub(super) const CHUNK_ENTRIES: usize = 256;
pub(super) const ROW_CHUNKS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("inventory-chunks-v1");
pub(super) const NAME_CHUNKS: TableDefinition<&str, &[u8]> = TableDefinition::new("name-chunks-v1");

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RowChunk {
    pub first_address: u64,
    pub last_address: u64,
    pub name_bytes: usize,
    pub sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NameChunk {
    pub ordinal: usize,
    pub entries: usize,
    pub sha256: String,
}

pub(crate) struct InventoryIntegrity {
    pub(super) rows: Vec<RowChunk>,
    pub(super) names: Vec<[u8; 32]>,
    // Inventory, index, and descriptor tables are immutable after installation.
    // The Cache owns the exclusive database; only pseudocode writes continue.
    // Verified chunks can therefore be reused without pinning read transactions.
    pub(super) verified_rows: Vec<bool>,
    pub(super) verified_names: Vec<bool>,
    /// The alias table is verified as a whole on first alias read.
    pub(super) verified_aliases: bool,
    pub(super) functions: usize,
    pub(super) arm: bool,
}

pub(super) fn manifest_hash(snapshot: &Snapshot, names: u64) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"rea-rust-ghidra-cache-manifest-v1\0");
    hash.update(snapshot.inventory_sha256.as_bytes());
    hash.update((snapshot.indexed_functions as u64).to_be_bytes());
    hash.update(snapshot.aliases_sha256.as_bytes());
    hash.update((snapshot.indexed_aliases as u64).to_be_bytes());
    hash.update(names.to_be_bytes());
    hash.update([u8::from(snapshot.arm)]);
    hash
}

pub(super) fn row_hash(ordinal: usize) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"rea-rust-ghidra-inventory-chunk-v1\0");
    hash.update((ordinal as u64).to_be_bytes());
    hash
}

pub(super) fn name_hash(ordinal: usize) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"rea-rust-ghidra-name-chunk-v1\0");
    hash.update((ordinal as u64).to_be_bytes());
    hash
}

pub(super) fn hash_row_descriptor(hash: &mut Sha256, ordinal: usize, chunk: &RowChunk) {
    hash.update((ordinal as u64).to_be_bytes());
    hash.update(chunk.first_address.to_be_bytes());
    hash.update(chunk.last_address.to_be_bytes());
    hash.update((chunk.name_bytes as u64).to_be_bytes());
    hash.update(chunk.sha256.as_bytes());
}

pub(super) fn name_descriptor_hash(last_name: &str, chunk: &NameChunk) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"rea-rust-ghidra-name-descriptor-v1\0");
    hash.update((chunk.ordinal as u64).to_be_bytes());
    hash.update((chunk.entries as u64).to_be_bytes());
    hash.update(chunk.sha256.as_bytes());
    hash_field(&mut hash, last_name.as_bytes());
    hash.finalize().into()
}

pub(super) fn hash_name_entry(hash: &mut Sha256, name: &str, resolution: &str) {
    hash_field(hash, name.as_bytes());
    hash_field(hash, resolution.as_bytes());
}

fn hash_field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

pub(super) fn decode_row_chunk(bytes: &[u8]) -> Result<RowChunk> {
    ensure!(
        bytes.len() <= 512,
        "Invalid inventory chunk descriptor size"
    );
    let chunk: RowChunk = serde_json::from_slice(bytes)?;
    validate_digest(&chunk.sha256)?;
    ensure!(
        chunk.first_address <= chunk.last_address,
        "Invalid inventory chunk address range"
    );
    ensure!(
        chunk.name_bytes <= CHUNK_ENTRIES * MAX_NAME_BYTES,
        "Invalid inventory name coverage"
    );
    Ok(chunk)
}

pub(super) fn decode_name_chunk(last_name: &str, bytes: &[u8]) -> Result<NameChunk> {
    ensure!(
        last_name.len() <= MAX_NAME_BYTES,
        "Invalid name chunk boundary"
    );
    ensure!(bytes.len() <= 256, "Invalid name chunk descriptor size");
    let chunk: NameChunk = serde_json::from_slice(bytes)?;
    validate_digest(&chunk.sha256)?;
    ensure!(
        (1..=CHUNK_ENTRIES).contains(&chunk.entries),
        "Invalid name chunk entry count"
    );
    Ok(chunk)
}
