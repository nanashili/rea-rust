use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::configuration::validate_digest;
use crate::encoding::encoded_size;
use crate::protocol::{
    MAX_BATCH_BYTES, MAX_INVENTORY, MAX_NAME_BYTES, Segment, address, parse_address,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub config_identity: String,
    pub target_sha256: String,
    pub inventory_sha256: String,
    // Older snapshots are verified and upgraded transactionally before use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_indexes_sha256: Option<String>,
    pub indexed_functions: usize,
    /// Commitment and count of additional loader symbols at inventory entries.
    pub aliases_sha256: String,
    pub indexed_aliases: usize,
    pub language: String,
    pub arm: bool,
    pub segments: Vec<Segment>,
}

impl Snapshot {
    pub fn validate(&self, identity: &str, target_sha256: &str) -> Result<()> {
        ensure!(
            self.config_identity == identity,
            "Saved configuration differs"
        );
        ensure!(
            self.target_sha256 == target_sha256,
            "Saved target identity differs"
        );
        validate_digest(&self.inventory_sha256)?;
        if let Some(indexes_sha256) = self.inventory_indexes_sha256.as_deref() {
            validate_digest(indexes_sha256)?;
        }
        ensure!(
            self.indexed_functions <= MAX_INVENTORY,
            "Saved inventory exceeds the limit"
        );
        validate_digest(&self.aliases_sha256)?;
        // Rows and aliases are both admitted loader entries.
        ensure!(
            self.indexed_aliases <= MAX_INVENTORY - self.indexed_functions,
            "Saved aliases exceed the inventory limit"
        );
        ensure!(
            !self.language.is_empty() && self.language.len() <= MAX_NAME_BYTES,
            "Invalid saved language"
        );
        ensure!(
            self.segments.len() <= 4096,
            "Saved section list exceeds the limit"
        );
        let mut encoded_bytes = 0_usize;
        for segment in &self.segments {
            validate_segment(segment)?;
            encoded_bytes += encoded_size(segment)?;
            ensure!(
                encoded_bytes <= MAX_BATCH_BYTES,
                "Saved section output exceeds the limit"
            );
        }
        Ok(())
    }
}

fn validate_segment(segment: &Segment) -> Result<()> {
    ensure!(
        segment.name.len() <= MAX_NAME_BYTES,
        "Invalid saved section name"
    );
    let start = parse_address(&segment.address);
    let end = parse_address(&segment.end);
    ensure!(
        start.is_some_and(|start| address(start) == segment.address)
            && end.is_some_and(|end| address(end) == segment.end)
            && start <= end,
        "Invalid saved section range"
    );
    Ok(())
}
