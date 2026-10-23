//! Application workflow for bounded PE target identity resolution.
//!
//! Stable-file ownership remains here while PE interpretation stays in
//! `rea-rust-analysis::pe_target`; adapters can bind this operation later.

use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use rea_core::{
    evidence::{
        Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
    },
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::pe;
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_pe_target";
const PROVIDER: Provider = Provider {
    id: "rust-pe-target",
    name: "REA Rust PE target resolver",
    version: Some("1"),
};
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub struct PeTargetAnalyzer;

impl ArtifactAnalyzer for PeTargetAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = pe::target::MAX_INPUT_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, snapshot)
    }
}

pub struct PeTargetInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, PeTargetAnalyzer>,
}

impl<F: rea_host::fs::stable_file::FileAccess> PeTargetInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
        }
    }

    pub fn with_records(
        access: Arc<F>,
        records: Arc<crate::ledger::artifact_records::ArtifactRecords>,
    ) -> Self {
        Self {
            inner: ArtifactInspection::with_records(access, records),
        }
    }

    pub fn records(&self) -> &Arc<crate::ledger::artifact_records::ArtifactRecords> {
        self.inner.records()
    }

    pub fn close(&mut self) -> Result<(), Failure> {
        self.inner.close()
    }

    pub fn inspect(
        &mut self,
        path: &str,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect(path, cancellation, completion)
    }
}

#[derive(Debug, Serialize)]
struct Report {
    path: String,
    sha256: String,
    #[serde(flatten)]
    target: pe::target::Inspection,
}

fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
    let target =
        pe::target::inspect(&snapshot.bytes).map_err(|error| parse_failure(path, error))?;
    let architecture = match target.architecture {
        "x86" => Some(Architecture::X86),
        "x86_64" => Some(Architecture::X86_64),
        "arm" => Some(Architecture::Arm),
        "arm64" => Some(Architecture::Arm64),
        _ => None,
    };
    let subject = Subject::new(
        path,
        snapshot.sha256.clone(),
        NativeFormat::Pe,
        architecture,
    )
    .map_err(|error| execution(path, error.to_string()))?;
    let limitations = target.limitations.clone();
    let mut locations = vec![Location::ArtifactPath {
        path: path.to_owned(),
    }];
    if let Some(code_view) = &target.code_view {
        let end = code_view.data_offset.saturating_add(code_view.data_bytes) as u64;
        locations.push(Location::FileOffsetRange {
            start: code_view.data_offset as u64,
            end,
        });
    }
    if let Some(load_config) = &target.mitigations.load_config {
        locations.push(Location::FileOffsetRange {
            start: load_config.file_offset as u64,
            end: load_config.file_offset.saturating_add(load_config.size) as u64,
        });
    }
    if let Some(relocations) = &target.relocations {
        for block in &relocations.blocks {
            for entry in &block.entries {
                if let Some(file_offset) = entry.file_offset {
                    locations.push(Location::FileOffsetRange {
                        start: file_offset as u64,
                        end: file_offset.saturating_add(1) as u64,
                    });
                }
            }
        }
    }
    if let Some(tls) = &target.tls {
        for callback in &tls.callbacks {
            if let Some(file_offset) = callback.file_offset {
                locations.push(Location::FileOffsetRange {
                    start: file_offset as u64,
                    end: file_offset.saturating_add(1) as u64,
                });
            }
        }
    }
    if let Some(delay_imports) = &target.delay_imports {
        for library in delay_imports {
            push_file_location(&mut locations, &library.descriptor_location);
            if let Some(name_location) = &library.name_location {
                push_file_location(&mut locations, name_location);
            }
            for symbol in &library.symbols {
                push_file_location(&mut locations, &symbol.location);
                if let Some(name_location) = &symbol.name_location {
                    push_file_location(&mut locations, name_location);
                }
            }
        }
    }
    if let Some(certificates) = &target.certificates {
        for entry in &certificates.entries {
            locations.push(Location::FileOffsetRange {
                start: entry.location.offset as u64,
                end: entry.location.offset.saturating_add(entry.location.bytes) as u64,
            });
        }
    }
    let report = Report {
        path: path.to_owned(),
        sha256: snapshot.sha256,
        target,
    };
    match json_output::admitted_length(&report, MAX_OUTPUT_BYTES) {
        Ok(_) => {}
        Err(json_output::Error::Limit { maximum }) => {
            return Err(resource(path, maximum));
        }
        Err(json_output::Error::Encoding(error)) => {
            return Err(execution(path, error.to_string()));
        }
    }
    let evidence = ArtifactEvidence::new(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: report,
            limitations,
            locations,
        },
    )
    .map_err(|error| execution(path, error.to_string()))?;
    Ok(Arc::new(evidence))
}

fn resource(path: &str, maximum: usize) -> Failure {
    let mut fields = details();
    fields.insert("path", Detail::Text(path.to_owned()));
    fields.insert("resource", Detail::Text("output".into()));
    fields.insert(
        "reported_limits",
        Detail::Fields(BTreeMap::from([(
            "maximum_output_bytes",
            Detail::Count(maximum as u64),
        )])),
    );
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        format!("PE target report for {path} exceeds the inline output budget."),
        false,
        "Select a target whose bounded PE report fits within the output limit.".into(),
        fields,
    )
}

fn push_file_location(locations: &mut Vec<Location>, range: &pe::target::FileRange) {
    locations.push(Location::FileOffsetRange {
        start: range.offset as u64,
        end: range.offset.saturating_add(range.bytes) as u64,
    });
}

fn parse_failure(path: &str, error: pe::target::Error) -> Failure {
    match error {
        pe::target::Error::ResourceLimit(reason) => {
            let mut fields = details();
            fields.insert("path", Detail::Text(path.to_owned()));
            fields.insert("resource", Detail::Text("memory".into()));
            fields.insert("reason", Detail::Text(reason.into()));
            Failure::new(
                "resource_constraint",
                "resource_constraint",
                format!("Selected target {path}: {reason}"),
                false,
                "Review the reported PE target memory limit or select a smaller file.".into(),
                fields,
            )
        }
        pe::target::Error::Unsupported(reason) => {
            let mut fields = details();
            fields.insert("path", Detail::Text(path.to_owned()));
            fields.insert("reason", Detail::Text(reason.into()));
            Failure::new(
                "unsupported_target",
                "unsupported_target",
                format!("Unsupported target for {OPERATION} at {path}: {reason}"),
                false,
                "Select a supported PE target.".into(),
                fields,
            )
        }
        pe::target::Error::Malformed(reason) => crate::artifacts::inspection::invalid_for(
            OPERATION,
            "invalid_format",
            format!("Selected artifact {path}: {reason}"),
        ),
    }
}

fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([
        ("operation", Detail::Text(OPERATION.into())),
        ("provider_id", Detail::Text(PROVIDER.id.into())),
    ])
}

fn execution(path: &str, reason: String) -> Failure {
    let mut fields = details();
    fields.insert("path", Detail::Text(path.into()));
    fields.insert("reason", Detail::Text(reason));
    Failure::new(
        "execution_failure",
        "execution_failure",
        "PE target resolution could not complete.".into(),
        false,
        "Review the reported diagnostics before retrying.".into(),
        fields,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_target_is_rejected_before_evidence_commit() {
        let result = build_evidence(
            "/tmp/target.exe",
            Snapshot {
                bytes: b"MZ\0\0".to_vec(),
                sha256: "a".repeat(64),
            },
        );
        assert!(result.is_err());
    }
}
