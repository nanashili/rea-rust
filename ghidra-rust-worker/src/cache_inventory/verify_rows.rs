use std::ops::Range;

use anyhow::{Context, Result, ensure};
use redb::ReadTransaction;

use super::commitment::{CHUNK_ENTRIES, InventoryIntegrity};
use super::read_rows::read_row_chunk;
use crate::cache::{ADDRESSES, Cache, INVENTORY};

impl Cache {
    pub(super) fn verify_function_chunk(
        &self,
        transaction: &ReadTransaction,
        numeric_address: u64,
    ) -> Result<Option<Range<u64>>> {
        let mut integrity = self.inventory_integrity.borrow_mut();
        let integrity = integrity
            .as_mut()
            .context("Inventory commitment is not loaded")?;
        let ordinal = integrity
            .rows
            .partition_point(|chunk| chunk.last_address < numeric_address);
        let Some(chunk) = integrity.rows.get(ordinal) else {
            return Ok(None);
        };
        if numeric_address < chunk.first_address {
            return Ok(None);
        }

        verify_chunk(transaction, integrity, ordinal)?;
        let start = ordinal * CHUNK_ENTRIES;
        let end = (start + CHUNK_ENTRIES).min(integrity.functions);
        Ok(Some(start as u64..end as u64))
    }

    pub(super) fn verify_page_chunks(
        &self,
        transaction: &ReadTransaction,
        start: usize,
        end: usize,
    ) -> Result<()> {
        let mut integrity = self.inventory_integrity.borrow_mut();
        let integrity = integrity
            .as_mut()
            .context("Inventory commitment is not loaded")?;
        ensure!(
            end <= integrity.functions,
            "Page exceeds the committed inventory"
        );
        if start == end {
            return Ok(());
        }

        for ordinal in start / CHUNK_ENTRIES..=(end - 1) / CHUNK_ENTRIES {
            verify_chunk(transaction, integrity, ordinal)?;
        }
        Ok(())
    }
}

fn verify_chunk(
    transaction: &ReadTransaction,
    integrity: &mut InventoryIntegrity,
    ordinal: usize,
) -> Result<()> {
    if integrity.verified_rows[ordinal] {
        return Ok(());
    }

    let start = ordinal * CHUNK_ENTRIES;
    let end = (start + CHUNK_ENTRIES).min(integrity.functions);
    let inventory = transaction.open_table(INVENTORY)?;
    let addresses = transaction.open_table(ADDRESSES)?;
    let actual = read_row_chunk(
        &inventory,
        &addresses,
        integrity.arm,
        start..end,
        None,
        None,
    )?;
    let expected = &integrity.rows[ordinal];
    ensure!(
        actual.sha256 == expected.sha256
            && actual.name_bytes == expected.name_bytes
            && actual.first_address == expected.first_address
            && actual.last_address == expected.last_address,
        "Saved inventory chunk commitment differs"
    );
    integrity.verified_rows[ordinal] = true;
    Ok(())
}
