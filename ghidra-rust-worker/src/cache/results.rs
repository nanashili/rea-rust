use anyhow::{Result, ensure};
use redb::ReadableDatabase;
use serde::{Deserialize, Serialize};

use super::{Cache, RESULTS};
use crate::configuration::validate_digest;
use crate::encoding::{encode_bounded, json_sha256};
use crate::protocol::{BatchItem, Function, MAX_PSEUDOCODE_BYTES};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedResult {
    sha256: String,
    item: BatchItem,
}

#[derive(Serialize)]
struct PendingResult<'a> {
    sha256: String,
    item: &'a BatchItem,
}

impl Cache {
    pub fn result(&self, numeric_address: u64, function: &Function) -> Result<Option<BatchItem>> {
        self.read_result(numeric_address, function)
            .map_err(crate::failure::cache_integrity)
    }

    fn read_result(&self, numeric_address: u64, function: &Function) -> Result<Option<BatchItem>> {
        ensure!(
            !self.failed_commit.get(),
            "Cache durability is uncertain; restart the worker"
        );

        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(RESULTS)?;
        let Some(value) = table.get(numeric_address)? else {
            return Ok(None);
        };
        ensure!(
            value.value().len() <= 6 * MAX_PSEUDOCODE_BYTES + 65536,
            "Invalid cached result size"
        );

        let saved: SavedResult = serde_json::from_slice(value.value())?;
        validate_digest(&saved.sha256)?;
        ensure!(
            json_sha256(&saved.item)? == saved.sha256,
            "Cached pseudocode checksum differs"
        );
        let item = saved.item;
        ensure!(
            item.selector == function.address
                && item.address.as_ref() == Some(&function.address)
                && item.name.as_ref() == Some(&function.name)
                && item.error_code.is_none()
                && item.error_message.is_none()
                && item.pseudocode.as_ref().is_some_and(|code| {
                    !code.trim().is_empty() && code.len() <= MAX_PSEUDOCODE_BYTES
                }),
            "Cached pseudocode does not match its frozen function"
        );
        Ok(Some(item))
    }

    pub fn save_results<'a>(
        &self,
        completed: impl IntoIterator<Item = (u64, &'a BatchItem)>,
    ) -> Result<()> {
        let mut completed = completed.into_iter().peekable();
        if completed.peek().is_none() {
            return Ok(());
        }

        self.write_durable("Durably checkpoint completed pseudocode", |transaction| {
            let mut table = transaction.open_table(RESULTS)?;
            for (address, item) in completed {
                let saved = PendingResult {
                    sha256: json_sha256(item)?,
                    item,
                };
                let encoded = encode_bounded(&saved, 6 * MAX_PSEUDOCODE_BYTES + 65536)?;
                table.insert(address, encoded.as_slice())?;
            }
            Ok(())
        })
    }
}
