//! Application-owned Evidence projection for the native ELF layout reader.
use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use rea_core::{
    evidence::{
        Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
    },
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::{binary_layout, image};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_binary_layout";
const PROVIDER: Provider = Provider {
    id: "rust-elf-layout",
    name: "REA Rust ELF layout reader",
    version: Some("1"),
};
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub struct BinaryLayoutAnalyzer;
impl ArtifactAnalyzer for BinaryLayoutAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = image::MAX_INPUT_BYTES;
    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, snapshot)
    }
}
pub struct BinaryLayoutInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, BinaryLayoutAnalyzer>,
}
impl<F: rea_host::fs::stable_file::FileAccess> BinaryLayoutInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
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
    artifact: Artifact,
    #[serde(flatten)]
    layout: binary_layout::Layout,
    limitations: Vec<String>,
}
#[derive(Debug, Serialize)]
struct Artifact {
    path: String,
    sha256: String,
    bytes: usize,
}
fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
    let layout = binary_layout::read(&snapshot.bytes).map_err(|e| failure_for(e, path))?;
    let report = Report {
        artifact: Artifact {
            path: path.into(),
            sha256: snapshot.sha256.clone(),
            bytes: snapshot.bytes.len(),
        },
        layout,
        limitations: limitations(),
    };
    match json_output::admitted_length(&report, MAX_OUTPUT_BYTES) {
        Ok(_) => {}
        Err(json_output::Error::Limit { maximum }) => return Err(resource(path, maximum)),
        Err(json_output::Error::Encoding(e)) => return Err(execution(path, e.to_string())),
    }
    let subject = Subject::new(
        path,
        snapshot.sha256,
        NativeFormat::Elf,
        Some(Architecture::X86_64),
    )
    .map_err(|e| execution(path, e.to_string()))?;
    let locations = vec![Location::ArtifactPath { path: path.into() }];
    let limits = report.limitations.clone();
    Ok(Arc::new(
        ArtifactEvidence::new(
            subject,
            PROVIDER,
            Observation {
                operation: OPERATION,
                result: report,
                limitations: limits,
                locations,
            },
        )
        .map_err(|e| execution(path, e.to_string()))?,
    ))
}
fn limitations() -> Vec<String> {
    vec!["This profile inspects ELF EXEC/DYN/REL layout only. It does not launch the target, resolve loaded libraries, or establish runtime behavior.".into(),"Names include source ranges where resolvable; relocation inventory completeness and convenience linkage maps remain unknown.".into(),"Mitigation values are inferred static indicators and do not prove runtime protection coverage.".into()]
}
fn failure_for(error: binary_layout::Error, path: &str) -> Failure {
    match error {
        binary_layout::Error::InputLimit => resource(path, image::MAX_INPUT_BYTES),
        binary_layout::Error::Unsupported(reason) => {
            let mut f = details();
            f.insert("path", Detail::Text(path.into()));
            Failure::new(
                "unsupported_target",
                "unsupported_target",
                format!("Unsupported target for {OPERATION} at {path}: {reason}"),
                false,
                "Select a target supported by this operation.".into(),
                f,
            )
        }
        binary_layout::Error::Format(reason) => crate::artifacts::inspection::invalid_for(
            OPERATION,
            "invalid_format",
            reason.to_string(),
        ),
        binary_layout::Error::Message(reason) => {
            crate::artifacts::inspection::invalid_for(OPERATION, "invalid_format", reason)
        }
    }
}
fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([("operation", Detail::Text(OPERATION.into()))])
}
fn execution(path: &str, reason: String) -> Failure {
    let mut f = details();
    f.insert("provider_id", Detail::Text(PROVIDER.id.into()));
    f.insert("diagnostics", Detail::Text(format!("{path}: {reason}")));
    Failure::new(
        "execution_failure",
        "execution_failure",
        "Analysis could not complete.".into(),
        false,
        "Review the reported details.".into(),
        f,
    )
}
fn resource(path: &str, maximum: usize) -> Failure {
    let mut f = details();
    f.insert("resource", Detail::Text("memory".into()));
    f.insert(
        "reported_limits",
        Detail::Fields(BTreeMap::from([(
            "maximum_output_bytes",
            Detail::Count(maximum as u64),
        )])),
    );
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        format!("Complete ELF layout for {path} exceeds the inline output budget."),
        false,
        "Select an artifact and output that fit within the reported resource boundary.".into(),
        f,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_non_elf_is_typed() {
        let error = binary_layout::read(b"MZ").unwrap_err();
        assert!(matches!(error, binary_layout::Error::Format(_)));
    }
}
