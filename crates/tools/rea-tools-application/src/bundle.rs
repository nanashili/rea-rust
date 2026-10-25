//! Authenticate an already shape-validated Evidence bundle.
//!
//! Compatibility owner: `authenticateParsedEvidenceBundle` /
//! `parseEvidenceBundle` in `src/domain/evidenceBundle.ts`. The native
//! `EvidenceBundle` owner authenticates records, residual-unknown histories
//! and canonical manifests; this adapter reproduces the original checks'
//! precedence and wording.
use crate::rejection::Rejection;
use rea_core::evidence::bundle::{EvidenceBundle, EvidenceBundleError};
use rea_core::evidence::record::{EvidenceRecord, EvidenceRecordError};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Authenticated bundle facts keyed by Evidence ID.
pub struct AuthenticatedBundle {
    pub records: Vec<Value>,
    pub by_id: HashMap<String, Value>,
    pub unknown_ids: BTreeSet<String>,
}

/// `authenticateParsedEvidenceBundle(bundle)`.
pub fn authenticate(bundle: &Value) -> Result<AuthenticatedBundle, Rejection> {
    let records = bundle["records"].as_array().cloned().unwrap_or_default();
    let mut ids = HashSet::new();
    for record in &records {
        if !ids.insert(record["evidence_id"].as_str().unwrap_or_default()) {
            return Err(Rejection::type_error(
                "Evidence bundle contains duplicate record IDs",
            ));
        }
    }
    for (index, record) in records.iter().enumerate() {
        let raw = serde_json::value::to_raw_value(record)
            .map_err(|error| Rejection::type_error(error.to_string()))?;
        match EvidenceRecord::parse(&raw) {
            Ok(_) => {}
            Err(EvidenceRecordError::SemanticIdMismatch) => {
                return Err(Rejection::nested(
                    &format!("records.{index}.evidence_id"),
                    "Evidence semantic identifier does not match its record",
                ));
            }
            Err(other) => {
                return Err(Rejection::nested(
                    &format!("records.{index}"),
                    &other.to_string(),
                ));
            }
        }
    }
    let raw = serde_json::value::to_raw_value(bundle)
        .map_err(|error| Rejection::type_error(error.to_string()))?;
    EvidenceBundle::parse(&raw).map_err(|error| match error {
        EvidenceBundleError::Unknown(error) => Rejection::unclassified(error.to_string()),
        EvidenceBundleError::Invalid(_) | EvidenceBundleError::RecordAt { .. } => {
            Rejection::type_error("Evidence bundle manifests are not canonical")
        }
        other => Rejection::type_error(other.to_string()),
    })?;
    let by_id = records
        .iter()
        .map(|record| {
            (
                record["evidence_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                record.clone(),
            )
        })
        .collect();
    let unknown_ids = bundle["unknowns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|unknown| unknown["unknown_id"].as_str())
        .map(str::to_owned)
        .collect();
    Ok(AuthenticatedBundle {
        records,
        by_id,
        unknown_ids,
    })
}
