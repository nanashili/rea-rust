use std::ops::Bound;

use anyhow::{Context, Result, ensure};
use redb::ReadTransaction;

use super::build::validate_name_entry;
use super::commitment::{
    InventoryIntegrity, NAME_CHUNKS, NameChunk, decode_name_chunk, hash_name_entry,
    name_descriptor_hash, name_hash,
};
use crate::cache::{Cache, NAMES};
use crate::inventory::finish_inventory_hash;

struct Boundary {
    last_name: String,
    chunk: NameChunk,
}

impl Cache {
    pub(super) fn verified_name(
        &self,
        transaction: &ReadTransaction,
        selector: &str,
    ) -> Result<Option<String>> {
        let mut integrity = self.inventory_integrity.borrow_mut();
        let integrity = integrity
            .as_mut()
            .context("Inventory commitment is not loaded")?;
        let chunks = transaction.open_table(NAME_CHUNKS)?;
        let previous = chunks.range(..selector)?.next_back().transpose()?;
        let previous = previous
            .map(|(key, value)| authenticate(integrity, key.value(), value.value()))
            .transpose()?;
        let selected = chunks.range(selector..)?.next().transpose()?;
        let selected = selected
            .map(|(key, value)| authenticate(integrity, key.value(), value.value()))
            .transpose()?;
        let ordinal = previous.as_ref().map_or(0, |value| value.chunk.ordinal + 1);
        let Some(selected) = selected else {
            ensure!(
                ordinal == integrity.names.len(),
                "Saved name chunk coverage is incomplete"
            );
            return Ok(None);
        };
        ensure!(
            selected.chunk.ordinal == ordinal,
            "Saved name chunk boundaries are not adjacent"
        );

        verify_chunk(transaction, integrity, previous.as_ref(), &selected)?;
        let names = transaction.open_table(NAMES)?;
        Ok(names.get(selector)?.map(|value| value.value().to_owned()))
    }
}

fn authenticate(integrity: &InventoryIntegrity, last_name: &str, bytes: &[u8]) -> Result<Boundary> {
    let chunk = decode_name_chunk(last_name, bytes)?;
    let expected = integrity
        .names
        .get(chunk.ordinal)
        .context("Unknown saved name chunk ordinal")?;
    ensure!(
        name_descriptor_hash(last_name, &chunk) == *expected,
        "Saved name chunk descriptor differs"
    );
    Ok(Boundary {
        last_name: last_name.to_owned(),
        chunk,
    })
}

fn verify_chunk(
    transaction: &ReadTransaction,
    integrity: &mut InventoryIntegrity,
    previous: Option<&Boundary>,
    selected: &Boundary,
) -> Result<()> {
    let ordinal = selected.chunk.ordinal;
    if integrity.verified_names[ordinal] {
        return Ok(());
    }

    let lower = previous.map_or(Bound::Unbounded, |value| {
        Bound::Excluded(value.last_name.as_str())
    });
    let upper = Bound::Included(selected.last_name.as_str());
    let names = transaction.open_table(NAMES)?;
    let mut hash = name_hash(ordinal);
    let mut count = 0;
    for entry in names.range::<&str>((lower, upper))? {
        let (name, resolution) = entry?;
        count += 1;
        ensure!(
            count <= selected.chunk.entries,
            "Saved name chunk has extra entries"
        );
        validate_name_entry(name.value(), resolution.value())?;
        hash_name_entry(&mut hash, name.value(), resolution.value());
    }
    ensure!(
        count == selected.chunk.entries,
        "Saved name chunk is incomplete"
    );
    ensure!(
        finish_inventory_hash(hash) == selected.chunk.sha256,
        "Saved name chunk commitment differs"
    );
    integrity.verified_names[ordinal] = true;
    Ok(())
}
