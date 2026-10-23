use anyhow::{Context, Result, ensure};
use redb::{ReadTransaction, ReadableTable, ReadableTableMetadata};
use sha2::{Digest, Sha256};

use super::commitment::{
    CHUNK_ENTRIES, InventoryIntegrity, NAME_CHUNKS, ROW_CHUNKS, RowChunk, decode_name_chunk,
    decode_row_chunk, hash_row_descriptor, manifest_hash, name_descriptor_hash,
};
use crate::cache::{ADDRESSES, ALIASES, INVENTORY, NAMES, Snapshot};
use crate::configuration::validate_digest;
use crate::inventory::finish_inventory_hash;
use crate::protocol::{MAX_INVENTORY, MAX_INVENTORY_NAME_BYTES};

pub(crate) fn load(
    transaction: &ReadTransaction,
    snapshot: &Snapshot,
) -> Result<InventoryIntegrity> {
    let expected = snapshot
        .inventory_indexes_sha256
        .as_deref()
        .context("Saved inventory has no chunk commitment")?;
    validate_digest(expected)?;
    let name_entries = validate_counts(transaction, snapshot)?;
    let mut hash = manifest_hash(snapshot, name_entries);
    let row_chunks = snapshot.indexed_functions.div_ceil(CHUNK_ENTRIES);
    let name_chunks = (name_entries as usize).div_ceil(CHUNK_ENTRIES);
    let rows = load_rows(transaction, row_chunks, &mut hash)?;
    let names = load_names(transaction, name_entries as usize, &mut hash)?;
    ensure!(
        finish_inventory_hash(hash) == expected,
        "Saved chunk manifest commitment differs"
    );

    Ok(InventoryIntegrity {
        rows,
        names,
        verified_rows: vec![false; row_chunks],
        verified_names: vec![false; name_chunks],
        verified_aliases: false,
        functions: snapshot.indexed_functions,
        arm: snapshot.arm,
    })
}

fn load_rows(
    transaction: &ReadTransaction,
    expected_chunks: usize,
    hash: &mut Sha256,
) -> Result<Vec<RowChunk>> {
    let row_table = transaction.open_table(ROW_CHUNKS)?;
    ensure!(
        row_table.len()? == expected_chunks as u64,
        "Saved inventory chunk count differs"
    );
    let mut rows: Vec<RowChunk> = Vec::with_capacity(expected_chunks);
    let mut name_bytes = 0;
    for (ordinal, entry) in row_table.iter()?.enumerate() {
        let (key, value) = entry?;
        ensure!(
            key.value() == ordinal as u64,
            "Saved inventory chunk ordinal differs"
        );
        let chunk = decode_row_chunk(value.value())?;
        name_bytes += chunk.name_bytes;
        ensure!(
            name_bytes <= MAX_INVENTORY_NAME_BYTES,
            "Saved function names exceed the 32 MiB budget"
        );
        if let Some(previous) = rows.last() {
            ensure!(
                previous.last_address < chunk.first_address,
                "Saved inventory chunks overlap"
            );
        }
        hash_row_descriptor(hash, ordinal, &chunk);
        rows.push(chunk);
    }
    Ok(rows)
}

fn load_names(
    transaction: &ReadTransaction,
    entries: usize,
    hash: &mut Sha256,
) -> Result<Vec<[u8; 32]>> {
    let expected_chunks = entries.div_ceil(CHUNK_ENTRIES);
    let name_table = transaction.open_table(NAME_CHUNKS)?;
    ensure!(
        name_table.len()? == expected_chunks as u64,
        "Saved name chunk count differs"
    );
    let mut names = Vec::with_capacity(expected_chunks);
    let mut remaining = entries;
    for (ordinal, entry) in name_table.iter()?.enumerate() {
        let (key, value) = entry?;
        let chunk = decode_name_chunk(key.value(), value.value())?;
        ensure!(chunk.ordinal == ordinal, "Saved name chunk ordinal differs");
        let expected_entries = remaining.min(CHUNK_ENTRIES);
        ensure!(
            chunk.entries == expected_entries,
            "Saved name chunk coverage differs"
        );
        remaining -= chunk.entries;
        let digest = name_descriptor_hash(key.value(), &chunk);
        hash.update(digest);
        names.push(digest);
    }
    ensure!(remaining == 0, "Saved name chunks are incomplete");
    Ok(names)
}

pub(super) fn validate_counts(transaction: &ReadTransaction, snapshot: &Snapshot) -> Result<u64> {
    ensure!(
        snapshot.indexed_functions <= MAX_INVENTORY,
        "Saved inventory exceeds the limit"
    );
    let expected = snapshot.indexed_functions as u64;
    ensure!(
        transaction.open_table(INVENTORY)?.len()? == expected,
        "Saved inventory row count differs"
    );
    ensure!(
        transaction.open_table(ADDRESSES)?.len()? == expected,
        "Saved address index count differs"
    );
    ensure!(
        transaction.open_table(ALIASES)?.len()? == snapshot.indexed_aliases as u64,
        "Saved alias count differs"
    );
    let names = transaction.open_table(NAMES)?.len()?;
    ensure!(
        names <= expected + snapshot.indexed_aliases as u64,
        "Saved name index count exceeds the inventory"
    );
    Ok(names)
}
