//! Evidence projection for supplied ELF core files.
use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use rea_core::{
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::{Detail, Failure},
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::recorded_crash;
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};
pub const OPERATION: &str = "inspect_recorded_crash";
const PROVIDER: Provider = Provider {
    id: "rust-recorded-crash",
    name: "REA Rust ELF core reader",
    version: Some("1"),
};
#[derive(Default)]
pub struct Analyzer;
impl ArtifactAnalyzer for Analyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = 1024 * 1024 * 1024;
    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build(path, snapshot)
    }
}
pub struct Inspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, Analyzer>,
}
impl<F: rea_host::fs::stable_file::FileAccess> Inspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
        }
    }
    pub fn inspect(
        &mut self,
        path: &str,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect(path, cancellation, completion)
    }
    pub fn close(&mut self) -> Result<(), Failure> {
        self.inner.close()
    }
}
#[derive(Serialize)]
struct Report {
    artifact: Artifact,
    #[serde(flatten)]
    decoded: recorded_crash::Report,
}
#[derive(Serialize)]
struct Artifact {
    path: String,
    sha256: String,
    bytes: usize,
}
fn build(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
    let decoded =
        recorded_crash::inspect(&snapshot.bytes).map_err(|reason| invalid(path, reason))?;
    let report = Report {
        artifact: Artifact {
            path: path.into(),
            sha256: snapshot.sha256.clone(),
            bytes: snapshot.bytes.len(),
        },
        decoded,
    };
    let architecture = if report.decoded.architecture == "aarch64-little-endian" {
        rea_core::evidence::Architecture::Arm64
    } else {
        rea_core::evidence::Architecture::X86_64
    };
    let subject = Subject::new(path, snapshot.sha256, NativeFormat::Elf, Some(architecture))
        .map_err(|error| execution(path, error.to_string()))?;
    let mut limitations = report.decoded.limitations.clone();
    limitations.push("No target execution or live process attachment is performed.".into());
    Ok(Arc::new(
        ArtifactEvidence::new(
            subject,
            PROVIDER,
            Observation {
                operation: OPERATION,
                result: report,
                limitations,
                locations: vec![Location::ArtifactPath { path: path.into() }],
            },
        )
        .map_err(|error| execution(path, error.to_string()))?,
    ))
}
fn invalid(path: &str, reason: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_format",
        format!("Unable to decode ELF core {path}: {reason}"),
        false,
        "Select a supported Linux ELF core file.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn execution(path: &str, reason: String) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        format!("ELF core inspection failed for {path}: {reason}"),
        false,
        "Review the reported artifact and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
