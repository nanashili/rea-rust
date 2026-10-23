//! Strict, canonical Evidence bundle admission for native import.

use crate::{
    canonical_json,
    evidence::record::EvidenceRecord,
    evidence::record::EvidenceRecordError,
    residual_unknown::{ResidualUnknown, ResidualUnknownError, validate_histories},
};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt};

/// Authenticated, canonical bundle supported by the native retained-record owner.
pub struct EvidenceBundle {
    records: Vec<EvidenceRecord>,
    unknowns: Vec<ResidualUnknown>,
    canonical_sha256: String,
}

/// Bundle shape, identity, ordering, or manifest validation failed.
#[derive(Debug)]
pub enum EvidenceBundleError {
    /// A contained Evidence record failed validation or authentication.
    Record(EvidenceRecordError),
    /// A contained residual-unknown revision or graph failed validation.
    Unknown(ResidualUnknownError),
    /// The bundle failed a strict shape or canonical invariant.
    Invalid(String),
    /// Canonical comparison could not preserve an admitted value.
    Canonical(canonical_json::Error),
    /// A temporary raw JSON value could not be encoded.
    Encoding(serde_json::Error),
}

impl fmt::Display for EvidenceBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(error) => error.fmt(formatter),
            Self::Unknown(error) => error.fmt(formatter),
            Self::Invalid(message) => formatter.write_str(message),
            Self::Canonical(error) => error.fmt(formatter),
            Self::Encoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for EvidenceBundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Record(error) => Some(error),
            Self::Unknown(error) => Some(error),
            Self::Canonical(error) => Some(error),
            Self::Encoding(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl EvidenceBundle {
    /// Parse a bundle, authenticate every record, and verify all canonical manifests.
    pub fn parse(input: &RawValue) -> Result<Self, EvidenceBundleError> {
        let shape: BundleShape<'_> = serde_json::from_str(input.get())
            .map_err(|error| EvidenceBundleError::Invalid(error.to_string()))?;

        let mut records = Vec::with_capacity(shape.records.len());
        for raw in &shape.records {
            records.push(EvidenceRecord::parse(raw).map_err(EvidenceBundleError::Record)?);
        }

        let mut unknowns = Vec::with_capacity(shape.unknowns.len());
        for raw in &shape.unknowns {
            unknowns.push(ResidualUnknown::parse(raw).map_err(EvidenceBundleError::Unknown)?);
        }

        validate_record_order(&records)?;
        validate_unknown_order(&unknowns)?;
        validate_manifests(&shape, &records)?;
        validate_histories(unknowns.iter(), records.iter())
            .map_err(EvidenceBundleError::Unknown)?;
        let canonical_sha256 =
            canonical_json::digest_raw(input).map_err(EvidenceBundleError::Canonical)?;

        Ok(Self {
            records,
            unknowns,
            canonical_sha256,
        })
    }

    /// Authenticated records in their canonical Evidence ID order.
    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }

    /// Complete authenticated residual-unknown histories in canonical order.
    pub fn unknowns(&self) -> &[ResidualUnknown] {
        &self.unknowns
    }

    /// SHA-256 of this authenticated bundle's canonical JSON representation.
    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }

    /// Transfer validated bundle contents into the retained owner without
    /// duplicating large Evidence payloads.
    pub fn into_parts(self) -> (Vec<EvidenceRecord>, Vec<ResidualUnknown>) {
        (self.records, self.unknowns)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleShape<'a> {
    #[serde(borrow)]
    artifacts: Vec<&'a RawValue>,
    #[serde(borrow)]
    providers: Vec<&'a RawValue>,
    #[serde(borrow)]
    environments: Vec<&'a RawValue>,
    #[serde(borrow)]
    scenarios: Vec<&'a RawValue>,
    #[serde(borrow)]
    captures: Vec<&'a RawValue>,
    #[serde(borrow)]
    unknowns: Vec<&'a RawValue>,
    #[serde(borrow)]
    records: Vec<&'a RawValue>,
}

fn validate_record_order(records: &[EvidenceRecord]) -> Result<(), EvidenceBundleError> {
    let mut previous: Option<&str> = None;
    for record in records {
        let current = record.evidence_id();
        if let Some(previous) = previous {
            if current == previous {
                return invalid("Evidence bundle contains duplicate record IDs");
            }
            if current < previous {
                return invalid("Evidence bundle records are not in canonical order");
            }
        }
        previous = Some(current);
    }
    Ok(())
}

fn validate_unknown_order(unknowns: &[ResidualUnknown]) -> Result<(), EvidenceBundleError> {
    let mut previous: Option<(&str, u64)> = None;
    for unknown in unknowns {
        let current = (unknown.unknown_id(), unknown.revision());
        if previous.is_some_and(|previous| current <= previous) {
            return invalid("Evidence bundle residual unknowns are not in canonical order");
        }
        previous = Some(current);
    }
    Ok(())
}

fn validate_manifests(
    shape: &BundleShape<'_>,
    records: &[EvidenceRecord],
) -> Result<(), EvidenceBundleError> {
    let artifacts = unique_manifests(records.iter().filter_map(EvidenceRecord::artifact_manifest))?;
    let providers = unique_manifests(records.iter().map(EvidenceRecord::provider_manifest))?;
    let environments = unique_manifests(
        records
            .iter()
            .filter_map(EvidenceRecord::environment_manifest),
    )?;
    let scenarios = records
        .iter()
        .filter_map(EvidenceRecord::scenario_manifest)
        .map(copy_raw)
        .collect::<Result<Vec<_>, _>>()?;
    let captures = records
        .iter()
        .filter_map(EvidenceRecord::capture_manifest)
        .map(copy_raw)
        .collect::<Result<Vec<_>, _>>()?;

    compare_manifest_array("artifacts", &shape.artifacts, &artifacts)?;
    compare_manifest_array("providers", &shape.providers, &providers)?;
    compare_manifest_array("environments", &shape.environments, &environments)?;
    compare_manifest_array("scenarios", &shape.scenarios, &scenarios)?;
    compare_manifest_array("captures", &shape.captures, &captures)?;
    Ok(())
}

fn unique_manifests<'a>(
    values: impl Iterator<Item = &'a RawValue>,
) -> Result<Vec<Box<RawValue>>, EvidenceBundleError> {
    let mut unique = BTreeMap::new();
    for value in values {
        // The owner constructs each manifest with the same declared property
        // order as createEvidenceBundle, which is also its unique-sort key.
        unique.insert(value.get().to_owned(), copy_raw(value)?);
    }
    Ok(unique.into_values().collect())
}

fn compare_manifest_array(
    name: &'static str,
    actual: &[&RawValue],
    expected: &[Box<RawValue>],
) -> Result<(), EvidenceBundleError> {
    if actual.len() != expected.len() {
        return invalid(format!(
            "Evidence bundle {name} manifest does not match its records"
        ));
    }
    for (actual, expected) in actual.iter().zip(expected) {
        if canonical_bytes(actual)? != canonical_bytes(expected)? {
            return invalid(format!(
                "Evidence bundle {name} manifest does not match its records"
            ));
        }
    }
    Ok(())
}

fn canonical_bytes(raw: &RawValue) -> Result<Vec<u8>, EvidenceBundleError> {
    let mut bytes = Vec::new();
    canonical_json::write(raw, &mut bytes).map_err(EvidenceBundleError::Canonical)?;
    Ok(bytes)
}

fn copy_raw(raw: &RawValue) -> Result<Box<RawValue>, EvidenceBundleError> {
    RawValue::from_string(raw.get().to_owned()).map_err(EvidenceBundleError::Encoding)
}

fn invalid<T>(message: impl Into<String>) -> Result<T, EvidenceBundleError> {
    Err(EvidenceBundleError::Invalid(message.into()))
}
