use anyhow::{Context, Result, ensure};
use redb::{ReadableTable, ReadableTableMetadata, Table, TableDefinition, WriteTransaction};
use sha2::{Digest, Sha256};

use super::commitment::{
    CHUNK_ENTRIES, NAME_CHUNKS, NameChunk, ROW_CHUNKS, hash_name_entry, hash_row_descriptor,
    manifest_hash, name_descriptor_hash, name_hash,
};
use super::read_rows::read_row_chunk;
use crate::cache::{ADDRESSES, INVENTORY, NAMES, Snapshot};
use crate::inventory::{finish_inventory_hash, new_inventory_hash};
use crate::protocol::{MAX_INVENTORY, MAX_NAME_BYTES, address, parse_address};

const EXPECTED_NAMES: TableDefinition<&str, &str> =
    TableDefinition::new("inventory-upgrade-name-verification-v1");

pub(super) fn install(transaction: &WriteTransaction, snapshot: &Snapshot) -> Result<String> {
    build(transaction, snapshot, None)
}

pub(super) fn upgrade(transaction: &WriteTransaction, snapshot: &Snapshot) -> Result<String> {
    let mut expected_names = transaction.open_table(EXPECTED_NAMES)?;
    ensure!(
        expected_names.is_empty()?,
        "Saved name verification table is not empty"
    );
    let commitment = build(transaction, snapshot, Some(&mut expected_names))?;
    drop(expected_names);
    ensure!(
        transaction.delete_table(EXPECTED_NAMES)?,
        "Remove the completed name verification table"
    );
    Ok(commitment)
}

fn build(
    transaction: &WriteTransaction,
    snapshot: &Snapshot,
    mut expected_names: Option<&mut Table<'_, &str, &str>>,
) -> Result<String> {
    ensure!(
        snapshot.indexed_functions <= MAX_INVENTORY,
        "Saved inventory exceeds the limit"
    );
    let names = transaction.open_table(NAMES)?;
    ensure!(
        names.len()? <= (snapshot.indexed_functions + snapshot.indexed_aliases) as u64,
        "Saved name index count exceeds the inventory"
    );
    let mut hash = manifest_hash(snapshot, names.len()?);

    write_row_chunks(
        transaction,
        snapshot,
        &mut hash,
        expected_names.as_deref_mut(),
    )?;
    // An upgrade rebuilds the expected name index from saved rows and aliases.
    if let Some(expected) = expected_names.as_deref_mut() {
        super::index_aliases(transaction, expected)?;
    }
    write_name_chunks(transaction, &names, &mut hash, expected_names.as_deref())?;
    Ok(finish_inventory_hash(hash))
}

fn write_row_chunks(
    transaction: &WriteTransaction,
    snapshot: &Snapshot,
    manifest: &mut Sha256,
    mut expected_names: Option<&mut Table<'_, &str, &str>>,
) -> Result<()> {
    let inventory = transaction.open_table(INVENTORY)?;
    let addresses = transaction.open_table(ADDRESSES)?;
    let mut chunks = transaction.open_table(ROW_CHUNKS)?;
    let expected = snapshot.indexed_functions as u64;
    ensure!(
        inventory.len()? == expected,
        "Saved inventory row count differs"
    );
    ensure!(
        addresses.len()? == expected,
        "Saved address index count differs"
    );
    ensure!(chunks.is_empty()?, "Inventory chunks are already installed");
    let mut hash = new_inventory_hash();
    let mut previous_address = None;

    for ordinal in 0..snapshot.indexed_functions.div_ceil(CHUNK_ENTRIES) {
        let start = ordinal * CHUNK_ENTRIES;
        let end = (start + CHUNK_ENTRIES).min(snapshot.indexed_functions);
        let chunk = read_row_chunk(
            &inventory,
            &addresses,
            snapshot.arm,
            start..end,
            Some(&mut hash),
            expected_names.as_deref_mut(),
        )?;
        if let Some(previous) = previous_address {
            ensure!(
                previous < chunk.first_address,
                "Saved inventory addresses are not strictly ordered"
            );
        }
        previous_address = Some(chunk.last_address);
        hash_row_descriptor(manifest, ordinal, &chunk);
        let encoded = serde_json::to_vec(&chunk)?;
        chunks.insert(ordinal as u64, encoded.as_slice())?;
    }

    ensure!(
        finish_inventory_hash(hash) == snapshot.inventory_sha256,
        "Saved inventory commitment differs"
    );
    Ok(())
}

fn write_name_chunks(
    transaction: &WriteTransaction,
    names: &Table<'_, &str, &str>,
    manifest: &mut Sha256,
    expected_names: Option<&Table<'_, &str, &str>>,
) -> Result<()> {
    if let Some(expected) = expected_names {
        ensure!(
            expected.len()? == names.len()?,
            "Saved name index count differs"
        );
    }
    let mut chunks = transaction.open_table(NAME_CHUNKS)?;
    ensure!(chunks.is_empty()?, "Name chunks are already installed");
    let mut entries = names.iter()?;
    let mut remaining = names.len()? as usize;
    let mut ordinal = 0;

    while remaining > 0 {
        let count = remaining.min(CHUNK_ENTRIES);
        let mut hash = name_hash(ordinal);
        let mut last_name = String::new();
        for _ in 0..count {
            let (name, resolution) = entries.next().context("Saved name chunk is incomplete")??;
            validate_name_entry(name.value(), resolution.value())?;
            if let Some(expected) = expected_names {
                let saved = expected
                    .get(name.value())?
                    .context("Saved name index contains an unknown name")?;
                ensure!(
                    saved.value() == resolution.value(),
                    "Saved name index resolution differs"
                );
            }
            hash_name_entry(&mut hash, name.value(), resolution.value());
            last_name.clear();
            last_name.push_str(name.value());
        }
        let chunk = NameChunk {
            ordinal,
            entries: count,
            sha256: finish_inventory_hash(hash),
        };
        manifest.update(name_descriptor_hash(&last_name, &chunk));
        let encoded = serde_json::to_vec(&chunk)?;
        chunks.insert(last_name.as_str(), encoded.as_slice())?;
        remaining -= count;
        ordinal += 1;
    }
    Ok(())
}

pub(super) fn validate_name_entry(name: &str, resolution: &str) -> Result<()> {
    ensure!(name.len() <= MAX_NAME_BYTES, "Invalid saved name index key");
    if !resolution.is_empty() {
        let numeric_address =
            parse_address(resolution).context("Invalid saved name index address")?;
        ensure!(
            address(numeric_address) == resolution,
            "Noncanonical saved name index address"
        );
    }
    Ok(())
}
