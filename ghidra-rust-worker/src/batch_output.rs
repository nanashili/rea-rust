use anyhow::{Context, Error, Result, ensure};
use serde_json::{Value, json};

use crate::cache::Cache;
use crate::encoding::encoded_size;
use crate::protocol::{
    BatchItem, Function, MAX_BATCH_BYTES, address, parse_address, truncate_utf8,
};

const MAX_JSON_ESCAPE_BYTES_PER_INPUT_BYTE: usize = 6;
const SUCCESS_ITEM_JSON_OVERHEAD_BYTES: usize = 256;
const MAX_ENCODED_SUCCESS_ITEM_BYTES: usize = SUCCESS_ITEM_JSON_OVERHEAD_BYTES
    + 2 * crate::protocol::MAX_ADDRESS_BYTES
    + MAX_JSON_ESCAPE_BYTES_PER_INPUT_BYTE * crate::protocol::MAX_NAME_BYTES
    + MAX_JSON_ESCAPE_BYTES_PER_INPUT_BYTE * crate::protocol::MAX_PSEUDOCODE_BYTES;
const MAX_UNCONFIRMED_BYTES: usize = MAX_BATCH_BYTES / 6;
const MAX_RESERVED_RECOVERY_BYTES: usize =
    MAX_BATCH_BYTES - MAX_UNCONFIRMED_BYTES - MAX_ENCODED_SUCCESS_ITEM_BYTES;

#[derive(Clone, Copy, PartialEq)]
enum Persistence {
    NoPseudocode,
    Unconfirmed,
    Confirmed,
}

struct Completed {
    address: u64,
    item: BatchItem,
    persistence: Persistence,
}

pub(super) struct BatchOutput {
    completed: Vec<Completed>,
    encoded_bytes: usize,
    reserved_bytes: usize,
    pending_bytes: usize,
    fallback_sizes: Vec<usize>,
}

impl BatchOutput {
    pub fn new(functions: &[Function]) -> Result<Self> {
        let fallback_sizes = functions
            .iter()
            .map(|function| encoded_size(&output_limit(function, true)))
            .collect::<Result<Vec<_>>>()?;
        let reserved_bytes = fallback_sizes.iter().sum();
        ensure!(
            reserved_bytes <= MAX_RESERVED_RECOVERY_BYTES,
            "Fallback metadata leaves insufficient room for one maximum-sized result"
        );
        Ok(Self {
            completed: Vec::with_capacity(functions.len()),
            encoded_bytes: 0,
            reserved_bytes,
            pending_bytes: 0,
            fallback_sizes,
        })
    }

    pub fn record(
        &mut self,
        cache: &Cache,
        function: &Function,
        item: BatchItem,
        fresh: bool,
    ) -> Result<()> {
        self.retain(function, item, fresh)?;

        if let Err(bounding_error) = self.fit_output() {
            if !self.has_unconfirmed_results() {
                return Err(bounding_error);
            }

            self.persist_pending(cache).context(format!(
                "Persist pseudocode before limiting the batch reply; fitting the reply also failed: {bounding_error:#}"
            ))?;
            self.fit_output()
                .context("Fit the batch reply after persisting completed pseudocode")?;
        }

        if self.pending_bytes >= MAX_UNCONFIRMED_BYTES {
            self.persist_pending(cache)
                .context("Persist the bounded batch of completed pseudocode")?;
        }

        Ok(())
    }

    fn retain(&mut self, function: &Function, item: BatchItem, fresh: bool) -> Result<()> {
        let address = parse_address(&function.address).context("Invalid selected address")?;
        let persistence = match (item.pseudocode.is_some(), fresh) {
            (false, _) => Persistence::NoPseudocode,
            (true, true) => Persistence::Unconfirmed,
            (true, false) => Persistence::Confirmed,
        };
        let item_bytes = encoded_size(&item)?;
        self.encoded_bytes += item_bytes;
        self.reserved_bytes -= self.fallback_sizes[self.completed.len()];
        if persistence == Persistence::Unconfirmed {
            self.pending_bytes += item_bytes;
        }
        self.completed.push(Completed {
            address,
            item,
            persistence,
        });
        Ok(())
    }

    fn has_unconfirmed_results(&self) -> bool {
        self.completed
            .iter()
            .any(|entry| entry.persistence == Persistence::Unconfirmed)
    }

    fn persist_pending(&mut self, cache: &Cache) -> Result<()> {
        let pending_indices = self
            .completed
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                (entry.persistence == Persistence::Unconfirmed).then_some(index)
            })
            .collect::<Vec<_>>();

        if pending_indices.is_empty() {
            return Ok(());
        }

        cache
            .save_results(pending_indices.iter().map(|index| {
                let entry = &self.completed[*index];
                (entry.address, &entry.item)
            }))
            .context("Durably save the completed pseudocode batch")?;

        for index in pending_indices {
            self.completed[index].persistence = Persistence::Confirmed;
        }
        self.pending_bytes = 0;

        Ok(())
    }

    fn fit_output(&mut self) -> Result<()> {
        for entry in self.completed.iter_mut().rev() {
            if self.encoded_bytes + self.reserved_bytes <= MAX_BATCH_BYTES {
                return Ok(());
            }
            // A failed commit must keep its full recovery data in the reply.
            // Confirmed pseudocode remains retrievable from the saved cache.
            if entry.persistence == Persistence::Unconfirmed {
                continue;
            }
            let function = Function {
                address: entry
                    .item
                    .address
                    .clone()
                    .context("Missing completed address")?,
                name: entry.item.name.clone().context("Missing completed name")?,
            };
            let replacement = output_limit(&function, entry.persistence == Persistence::Confirmed);
            let old_size = encoded_size(&entry.item)?;
            let replacement_size = encoded_size(&replacement)?;
            if replacement_size < old_size {
                self.encoded_bytes -= old_size - replacement_size;
                entry.item = replacement;
            }
        }
        ensure!(
            self.encoded_bytes + self.reserved_bytes <= MAX_BATCH_BYTES,
            "Partial recovery data exceeds the batch output limit"
        );
        Ok(())
    }

    pub fn checkpoint(&mut self, cache: &Cache) -> Result<()> {
        self.persist_pending(cache)?;
        cache.checkpoint()
    }

    pub fn into_reply(self, inventory_sha256: &str) -> Value {
        let durability = self.durability();
        let items = self
            .completed
            .into_iter()
            .map(|entry| entry.item)
            .collect::<Vec<_>>();
        json!({
            "total": items.len(),
            "completed": items.len(),
            "items": items,
            "inventory_sha256": inventory_sha256,
            "durability": durability
        })
    }

    pub fn into_partial(self, inventory_sha256: &str, error: Error) -> Result<Value> {
        if self.completed.is_empty() {
            return Err(error);
        }

        let cause_code = crate::failure::code(&error);
        let mut message = format!("{error:#}");
        truncate_utf8(&mut message, 4096);
        let mut reply = self.into_reply(inventory_sha256);
        reply["failure"] = json!({
            "error_code": "BATCH_INTERRUPTED",
            "error_message": message,
            "cause_code": cause_code
        });
        Ok(reply)
    }

    fn durability(&self) -> Value {
        let mut confirmed = Vec::new();
        let mut unconfirmed = Vec::new();
        for entry in &self.completed {
            let addresses = match entry.persistence {
                Persistence::Confirmed => &mut confirmed,
                Persistence::Unconfirmed => &mut unconfirmed,
                Persistence::NoPseudocode => continue,
            };
            let selected = address(entry.address);
            if !addresses.contains(&selected) {
                addresses.push(selected);
            }
        }
        unconfirmed.retain(|selected| !confirmed.contains(selected));
        json!({"confirmed_addresses": confirmed, "unconfirmed_addresses": unconfirmed})
    }
}

fn output_limit(function: &Function, has_pseudocode: bool) -> BatchItem {
    if has_pseudocode {
        return BatchItem::failure(
            function,
            "BATCH_OUTPUT_LIMIT",
            "The batch output limit was reached. Retrieve this saved address in a smaller cache-only batch.",
        );
    }
    BatchItem::failure(
        function,
        "OUTPUT_LIMIT",
        "The batch output limit was reached before this result could be returned.",
    )
}
