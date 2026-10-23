//! Shared Go build-information inspection over stable artifact snapshots.
//!
//! The format reader owns byte interpretation. This application boundary owns
//! Evidence identity, source locations, limitations, and output admission.

use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use rea_core::{
    evidence::{
        Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
    },
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::{go, image};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_go_binary";
const PROVIDER: Provider = Provider {
    id: "go-build-info",
    name: "REA Go build-information reader",
    version: Some("1"),
};
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const EXECUTION_MESSAGE: &str = "Analysis could not complete. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";

#[derive(Default)]
pub struct GoBinaryAnalyzer;

impl ArtifactAnalyzer for GoBinaryAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = image::MAX_INPUT_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, snapshot)
    }
}

pub struct GoInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, GoBinaryAnalyzer>,
}

impl<F: rea_host::fs::stable_file::FileAccess> GoInspection<F> {
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
struct Artifact {
    path: String,
    sha256: String,
    bytes: usize,
}

#[derive(Debug, Serialize)]
struct Report {
    artifact: Artifact,
    #[serde(flatten)]
    image: go::binary::Image,
    limitations: Vec<String>,
}

fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
    let parsed = go::binary::read(&snapshot.bytes).map_err(|error| image_failure(error, path))?;
    let format = match parsed.format {
        image::Format::Elf => NativeFormat::Elf,
        image::Format::Pe => NativeFormat::Pe,
        image::Format::Macho => NativeFormat::MachO,
    };
    let architecture = architecture_for(&parsed.architecture);
    let locations = locations_for(path, &parsed);
    let limitations = limitations_for(&parsed);
    let report = Report {
        artifact: Artifact {
            path: path.to_owned(),
            sha256: snapshot.sha256.clone(),
            bytes: snapshot.bytes.len(),
        },
        image: parsed,
        limitations: limitations.clone(),
    };

    drop(snapshot.bytes);
    admit_report_length(path, &report)?;

    let subject = Subject::new(path, snapshot.sha256, format, architecture)
        .map_err(|error| execution(path, error.to_string()))?;
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

/// Inspect caller-supplied bytes without acquiring the selected path.
///
/// The ordinary inspection workflow owns stable filesystem reads.  Captured
/// callers already own acquisition, so this entry point only parses the
/// supplied snapshot and returns the same authenticated Evidence envelope.
pub fn inspect_bytes(
    path: &str,
    bytes: Vec<u8>,
    declared_sha256: Option<&str>,
) -> Result<Value, Failure> {
    if !std::path::Path::new(path).is_absolute() || path.contains('\0') {
        return Err(crate::artifacts::inspection::invalid_for(
            OPERATION,
            "invalid_input",
            "captured artifact path must be absolute and NUL-free".into(),
        ));
    }

    let digest = format!("{:x}", Sha256::digest(&bytes));
    if let Some(declared) = declared_sha256 {
        if declared != digest {
            return Err(crate::artifacts::inspection::invalid_for(
                OPERATION,
                "invalid_input",
                "sha256 does not match the supplied bytes".into(),
            ));
        }
    }

    let evidence = build_evidence(
        path,
        Snapshot {
            bytes,
            sha256: digest,
        },
    )?;
    serde_json::to_value(&*evidence).map_err(|error| execution(path, error.to_string()))
}

fn architecture_for(architecture: &str) -> Option<Architecture> {
    match architecture {
        "386" => Some(Architecture::X86),
        "amd64" => Some(Architecture::X86_64),
        "arm" => Some(Architecture::Arm),
        "arm64" => Some(Architecture::Arm64),
        "mips" => Some(Architecture::Mips),
        "riscv" => Some(Architecture::Riscv),
        "powerpc" => Some(Architecture::Powerpc),
        "hexagon" => Some(Architecture::Hexagon),
        _ => None,
    }
}

fn locations_for(path: &str, parsed: &go::binary::Image) -> Vec<Location> {
    let mut locations = vec![Location::ArtifactPath {
        path: path.to_owned(),
    }];
    if let Some(info) = &parsed.build_info {
        locations.push(Location::FileOffsetRange {
            start: info.header_offset as u64,
            end: info.header_offset as u64 + 32,
        });
    }
    locations
}

fn limitations_for(parsed: &go::binary::Image) -> Vec<String> {
    let info = parsed.build_info.as_ref();
    let module = info.map(|info| &info.module);
    let mut limitations = vec![
        "Embedded build metadata is observed file content, not proof of compiler identity, dependency authenticity or runtime behavior.".into(),
        "Only Go build information is inspected; function names, source mappings, type metadata and decompiled code are not recovered.".into(),
        "Resource guards bound stable artifact reads and cumulative header searches to 256 MiB each, aggregate embedded strings to 1 MiB, structural table decoding to 16 MiB and complete metadata payloads to 8 MiB; these are not operating-system memory or CPU limits.".into(),
    ];

    append_string_encoding_limitation(&mut limitations, info);
    append_missing_metadata_limitation(&mut limitations, info);
    append_missing_main_module_limitation(&mut limitations, module);
    append_incomplete_module_limitation(&mut limitations, module);

    limitations
}

fn append_string_encoding_limitation(
    limitations: &mut Vec<String>,
    info: Option<&go::binary::BuildInfo>,
) {
    if info.is_some_and(|info| info.go_version.is_none() || info.module_text.is_none()) {
        limitations.push(
            "Some embedded Go strings contain non-UTF8 bytes; undecodable text is null and exact source bytes are preserved as base64.".into(),
        );
    }
}

fn append_missing_metadata_limitation(
    limitations: &mut Vec<String>,
    info: Option<&go::binary::BuildInfo>,
) {
    if info.is_none() {
        limitations.push(
            "No recognized Go build-info record was found in the inspected image; absent metadata does not establish that the binary is not Go.".into(),
        );
    }
}

fn append_missing_main_module_limitation(
    limitations: &mut Vec<String>,
    module: Option<&rea_rust_analysis::go::module::Metadata>,
) {
    if module.is_some_and(|module| module.main.is_none()) {
        limitations.push(
            "Dependency coverage is unknown because no main-module record was decoded from the embedded module information, as in GOPATH-mode builds. Decoded dependency records remain visible; an empty list does not establish the absence of dependencies.".into(),
        );
    }
}

fn append_incomplete_module_limitation(
    limitations: &mut Vec<String>,
    module: Option<&rea_rust_analysis::go::module::Metadata>,
) {
    if module.is_some_and(|module| !module.complete) {
        limitations.push(
            "Some embedded module-text records could not be parsed completely; their original lines are preserved and additional metadata remains unknown.".into(),
        );
    }
}

fn admit_report_length(path: &str, report: &Report) -> Result<(), Failure> {
    match json_output::admitted_length(report, MAX_OUTPUT_BYTES) {
        Ok(_) => Ok(()),
        Err(json_output::Error::Limit { maximum }) => Err(resource(
            "transport",
            format!(
                "Complete Go metadata for {path} exceeds the inline output budget; no partial success is returned."
            ),
            "maximum_output_bytes",
            maximum,
            None,
        )),
        Err(json_output::Error::Encoding(error)) => Err(execution(path, error.to_string())),
    }
}

fn image_failure(error: go::binary::Error, path: &str) -> Failure {
    match error {
        go::binary::Error::Unsupported(reason) => {
            let mut fields = details();
            fields.insert("path", text(path));
            fields.insert("reason", text(reason));
            Failure::new(
                "unsupported_target",
                "unsupported_target",
                format!("Unsupported target for {OPERATION} at {path}: {reason}"),
                false,
                "Select a target supported by this operation or choose an operation supporting the reported target format.".into(),
                fields,
            )
        }
        go::binary::Error::Resource { stage, maximum } => {
            let (kind, boundary) = if stage == "Go build-info header search" {
                ("cpu", "search")
            } else if stage == "structure" {
                ("memory", "structure")
            } else {
                ("memory", "build-info")
            };
            resource(
                kind,
                format!("Selected artifact {path}: {error}"),
                "maximum_bytes",
                maximum,
                Some(boundary),
            )
        }
        go::binary::Error::Malformed(reason) => crate::artifacts::inspection::invalid_for(
            OPERATION,
            "invalid_format",
            format!("Selected artifact {path}: {reason}"),
        ),
    }
}

fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([("operation", text(OPERATION))])
}

fn text(value: impl Into<String>) -> Detail {
    Detail::Text(value.into())
}

fn execution(path: &str, reason: String) -> Failure {
    let mut fields = details();
    fields.insert("provider_id", text(PROVIDER.id));
    fields.insert(
        "diagnostics",
        Detail::Fields(BTreeMap::from([
            ("path", text(path)),
            ("reason", text(reason)),
        ])),
    );
    Failure::new(
        "execution_failure",
        "execution_failure",
        EXECUTION_MESSAGE.into(),
        false,
        EXECUTION_MESSAGE.into(),
        fields,
    )
}

fn resource(
    kind: &'static str,
    reason: String,
    limit: &'static str,
    maximum: usize,
    boundary: Option<&'static str>,
) -> Failure {
    let mut fields = details();
    fields.insert("resource", text(kind));
    fields.insert("reason", text(reason.clone()));
    fields.insert(
        "reported_limits",
        Detail::Fields(BTreeMap::from([(limit, Detail::Count(maximum as u64))])),
    );
    if let Some(boundary) = boundary {
        fields.insert("boundary", text(boundary));
    }

    let retryable = kind == "capacity";
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason,
        retryable,
        if retryable {
            "Wait for an active analysis to complete, then retry within the reported admission limits.".into()
        } else {
            "Select an artifact and output that fit within the reported resource boundary.".into()
        },
        fields,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_absent_build_information_as_unknown_metadata() {
        let image = go::binary::Image {
            format: image::Format::Elf,
            architecture: "amd64".into(),
            bits: 64,
            byte_order: image::ByteOrder::Little,
            build_info: None,
        };

        let limitations = limitations_for(&image);

        assert!(
            limitations
                .iter()
                .any(|limitation| { limitation.contains("absent metadata does not establish") })
        );
        assert!(matches!(
            architecture_for(&image.architecture),
            Some(Architecture::X86_64)
        ));
    }

    #[test]
    fn prefixes_malformed_format_issues_with_the_selected_artifact() {
        let failure = image_failure(
            go::binary::Error::Malformed("Go build-info header is truncated"),
            "/artifacts/program",
        );

        assert_eq!(failure.code(), "invalid_request");
        let serialized = serde_json::to_value(failure).unwrap();
        assert_eq!(serialized["category"], "invalid_input");
        let issue = &serialized["details"]["issues"][0];
        assert_eq!(issue["path"], serde_json::json!(["path"]));
        assert_eq!(issue["reason"], "invalid_format");
        assert_eq!(
            issue["message"],
            "Selected artifact /artifacts/program: Go build-info header is truncated"
        );
    }
}
