//! Saved derived references, bound to the frozen inventory they were
//! derived from.
use anyhow::{Context, Result, ensure};
use redb::{ReadableDatabase, TableDefinition, TableError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Cache, META};
use crate::analysis::references::{Kind, Reference};
use crate::cache::Snapshot;
use crate::configuration::validate_digest;

/// `(target, source, kind) -> containing function`.
const REFERENCES_TO: TableDefinition<(u64, u64, u8), u64> = TableDefinition::new("references-to-v1");
/// `(function, source, target, kind) -> ()`.
const REFERENCES_FROM: TableDefinition<(u64, u64, u64, u8), ()> = TableDefinition::new("references-from-v1");
const MANIFEST_KEY: &str = "references_manifest";

/// Commitment for the saved reference set.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReferenceManifest {
    pub inventory_sha256: String,
    pub references: u64,
    pub sha256: String,
}

/// Digest of a sorted reference list, in `(function, source, target, kind)` order.
pub(crate) fn digest(references: &[Reference]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"rea-rust-ghidra-references-v1\0");
    for reference in references {
        hash.update(reference.function.to_be_bytes());
        hash.update(reference.source.to_be_bytes());
        hash.update(reference.target.to_be_bytes());
        hash.update([reference.kind as u8]);
    }
    format!("{:x}", hash.finalize())
}

impl Cache {
    /// The saved reference manifest for this inventory, if one was committed.
    pub(crate) fn reference_manifest(&self, snapshot: &Snapshot) -> Result<Option<ReferenceManifest>> {
        let transaction = self.database.begin_read()?;
        let table = match transaction.open_table(META) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let Some(value) = table.get(MANIFEST_KEY)? else {
            return Ok(None);
        };
        let manifest: ReferenceManifest =
            serde_json::from_slice(value.value()).context("Decode the saved reference manifest")?;
        validate_digest(&manifest.sha256)?;
        ensure!(
            manifest.inventory_sha256 == snapshot.inventory_sha256,
            "Saved references belong to another inventory"
        );
        Ok(Some(manifest))
    }

    /// Durably save `references` (sorted by function, source, target, kind).
    pub(crate) fn save_references(
        &self,
        snapshot: &Snapshot,
        references: &[Reference],
    ) -> Result<ReferenceManifest> {
        let manifest = ReferenceManifest {
            inventory_sha256: snapshot.inventory_sha256.clone(),
            references: references.len() as u64,
            sha256: digest(references),
        };
        self.write_durable("Durably save derived references", |transaction| {
            transaction.delete_table(REFERENCES_TO)?;
            transaction.delete_table(REFERENCES_FROM)?;
            {
                let mut from = transaction.open_table(REFERENCES_FROM)?;
                for reference in references {
                    from.insert(
                        (reference.function, reference.source, reference.target, reference.kind as u8),
                        (),
                    )?;
                }
            }
            {
                let mut sorted: Vec<&Reference> = references
                    .iter()
                    .filter(|reference| reference.kind != Kind::IndirectCall)
                    .collect();
                sorted.sort_by_key(|reference| (reference.target, reference.source, reference.kind));
                let mut to = transaction.open_table(REFERENCES_TO)?;
                for reference in sorted {
                    to.insert(
                        (reference.target, reference.source, reference.kind as u8),
                        reference.function,
                    )?;
                }
            }
            let encoded = serde_json::to_vec(&manifest)?;
            transaction.open_table(META)?.insert(MANIFEST_KEY, encoded.as_slice())?;
            Ok(())
        })?;
        Ok(manifest)
    }

    /// References whose target is `target`, ordered by source; at most
    /// `limit` after skipping `offset`. Returns the page and the total.
    pub(crate) fn references_to(
        &self,
        target: u64,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<Reference>, usize)> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(REFERENCES_TO)?;
        let mut page = Vec::new();
        let mut total = 0;
        for entry in table.range((target, 0, 0)..=(target, u64::MAX, u8::MAX))? {
            let (key, function) = entry?;
            let (target, source, kind) = key.value();
            if total >= offset && page.len() < limit {
                page.push(Reference {
                    function: function.value(),
                    source,
                    target,
                    kind: Kind::from_code(kind).context("Invalid saved reference kind")?,
                });
            }
            total += 1;
        }
        Ok((page, total))
    }

    /// References from instructions in `function`, ordered by source.
    pub(crate) fn references_from(
        &self,
        function: u64,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<Reference>, usize)> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(REFERENCES_FROM)?;
        let mut page = Vec::new();
        let mut total = 0;
        for entry in table.range((function, 0, 0, 0)..=(function, u64::MAX, u64::MAX, u8::MAX))? {
            let (key, _) = entry?;
            let (function, source, target, kind) = key.value();
            if total >= offset && page.len() < limit {
                page.push(Reference {
                    function,
                    source,
                    target,
                    kind: Kind::from_code(kind).context("Invalid saved reference kind")?,
                });
            }
            total += 1;
        }
        Ok((page, total))
    }
}
