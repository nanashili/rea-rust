use std::ops::Range;

use anyhow::{Context, Result, ensure};
use redb::{ReadableTable, Table};
use sha2::Sha256;

use super::commitment::{CHUNK_ENTRIES, RowChunk, row_hash};
use super::{decode_function, index_name};
use crate::inventory::{finish_inventory_hash, update_inventory_hash};
use crate::protocol::{Function, parse_address};

pub(super) fn read_row_chunk(
    inventory: &impl ReadableTable<u64, &'static [u8]>,
    addresses: &impl ReadableTable<u64, u64>,
    arm: bool,
    range: Range<usize>,
    mut inventory_hash: Option<&mut Sha256>,
    mut expected_names: Option<&mut Table<'_, &str, &str>>,
) -> Result<RowChunk> {
    let mut hash = row_hash(range.start / CHUNK_ENTRIES);
    let mut first_address = None;
    let mut last_address = None;
    let mut next = range.start;
    let mut name_bytes = 0;

    for entry in inventory.range(range.start as u64..range.end as u64)? {
        let (ordinal, value) = entry?;
        ensure!(
            ordinal.value() == next as u64,
            "Saved inventory ordinal differs"
        );
        let function = decode_function(value.value())?;
        name_bytes += function.name.len();
        let numeric_address = validate_row(&function, addresses, arm, next, last_address)?;
        if let Some(names) = expected_names.as_deref_mut() {
            index_name(names, &function.name, &function.address)?;
        }

        if let Some(inventory_hash) = inventory_hash.as_deref_mut() {
            update_inventory_hash(inventory_hash, numeric_address, &function.name);
        }
        update_inventory_hash(&mut hash, numeric_address, &function.name);
        first_address.get_or_insert(numeric_address);
        last_address = Some(numeric_address);
        next += 1;
    }

    ensure!(next == range.end, "Saved inventory chunk is incomplete");
    Ok(RowChunk {
        first_address: first_address.context("Saved inventory chunk is empty")?,
        last_address: last_address.context("Saved inventory chunk is empty")?,
        name_bytes,
        sha256: finish_inventory_hash(hash),
    })
}

fn validate_row(
    function: &Function,
    addresses: &impl ReadableTable<u64, u64>,
    arm: bool,
    ordinal: usize,
    previous_address: Option<u64>,
) -> Result<u64> {
    let numeric_address = parse_address(&function.address).context("Invalid saved address")?;
    ensure!(
        !arm || numeric_address & 1 == 0,
        "Saved ARM address is not normalized"
    );
    if let Some(previous) = previous_address {
        ensure!(
            previous < numeric_address,
            "Saved inventory addresses are not strictly ordered"
        );
    }
    let indexed = addresses
        .get(numeric_address)?
        .context("Saved address index is missing a function")?;
    ensure!(
        indexed.value() == ordinal as u64,
        "Saved address index does not point to its inventory row"
    );
    Ok(numeric_address)
}
