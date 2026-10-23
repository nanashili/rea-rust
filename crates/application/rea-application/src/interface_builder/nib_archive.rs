//! Read-only inspection of one compiled Interface Builder NIB archive.
//!
//! The analysis crate owns the NIBArchive tables and serialized values. This
//! workflow owns stable file access, Evidence identity, failure projection,
//! and the output budget.

use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use base64::Engine;
use rea_core::{
    cancellation::Cancellation,
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::{FileAccess, Snapshot};
use rea_rust_analysis::nib::{self, NibArchiveError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_nib_archive";
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const PROVIDER: Provider = Provider {
    id: "rust-nib-archive-reader",
    name: "REA Rust NIB archive reader",
    version: Some("1"),
};

/// Inspect caller-supplied NIBArchive bytes or already decoded archive facts.
///
/// This public projection never opens a path and never instantiates archived
/// classes.  `bytes_base64` is decoded only to feed the read-only archive
/// parser.  A caller may instead provide `report`, or an Evidence object
/// containing `normalized_result`, when decoding has already happened in an
/// owned producer.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| public_failure("input must be an object"))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| public_failure("path is required"))?;

    let (report, archive_sha256) =
        if let Some(encoded) = object.get("bytes_base64").and_then(Value::as_str) {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| public_failure(&format!("bytes_base64 is invalid: {error}")))?;
            let digest = hex_digest(&bytes);
            if let Some(declared) = object.get("sha256").and_then(Value::as_str)
                && !declared.eq_ignore_ascii_case(&digest)
            {
                return Err(public_failure("sha256 does not match bytes_base64"));
            }
            let report = nib::decode_nib_archive(&bytes)
                .map_err(|error| public_failure(&error.to_string()))?;
            (
                serde_json::to_value(report).map_err(|error| public_failure(&error.to_string()))?,
                digest,
            )
        } else {
            let source = object
                .get("report")
                .or_else(|| object.get("evidence"))
                .ok_or_else(|| public_failure("bytes_base64, report, or evidence is required"))?;
            let report = source
                .get("normalized_result")
                .and_then(|result| result.get("report").or(Some(result)))
                .or_else(|| source.get("report"))
                .cloned()
                .ok_or_else(|| public_failure("decoded NIB facts must include a report"))?;
            if !report.is_object() {
                return Err(public_failure("decoded NIB report must be an object"));
            }
            let digest = object
                .get("sha256")
                .and_then(Value::as_str)
                .or_else(|| {
                    source
                        .pointer("/subject/digest/sha256")
                        .and_then(Value::as_str)
                })
                .unwrap_or("")
                .to_owned();
            (report, digest)
        };

    let mut limitations = vec![
        "The adapter decodes serialized archive values and never instantiates archived classes."
            .to_owned(),
    ];
    if let Some(items) = report.get("limitations").and_then(Value::as_array) {
        limitations.extend(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned),
        );
    }
    limitations.sort();
    limitations.dedup();
    Ok(json!({
        "archive_path": path,
        "archive_sha256": archive_sha256,
        "report": report,
        "limitations": limitations,
    }))
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn public_failure(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_input",
        "input",
        reason.into(),
        false,
        "Provide valid NIBArchive bytes or decoded archive facts and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

#[derive(Default)]
pub struct NibArchiveAnalyzer;

impl ArtifactAnalyzer for NibArchiveAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = nib::MAX_INPUT_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, snapshot)
    }
}

/// Owns one stable-read lifecycle for NIB archive inspection.
pub struct NibArchiveInspection<F: FileAccess> {
    inner: ArtifactInspection<F, NibArchiveAnalyzer>,
}

impl<F: FileAccess> NibArchiveInspection<F> {
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
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect(path, cancellation, completion)
    }
}

fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
    let report =
        nib::decode_nib_archive(&snapshot.bytes).map_err(|error| decode_failure(path, error))?;
    let limitations = report.limitations.clone();
    let subject = Subject::new(path, snapshot.sha256, NativeFormat::Nib, None)
        .map_err(|error| execution_failure(path, error.to_string()))?;
    let evidence = ArtifactEvidence::new(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: report,
            limitations,
            locations: vec![Location::ArtifactPath {
                path: path.to_owned(),
            }],
        },
    )
    .map_err(|error| execution_failure(path, error.to_string()))?;

    match json_output::admitted_length(&evidence, MAX_OUTPUT_BYTES) {
        Ok(_) => Ok(Arc::new(evidence)),
        Err(json_output::Error::Limit { maximum }) => Err(resource_failure(
            path,
            format!("serialized NIB archive Evidence exceeds {maximum} bytes"),
        )),
        Err(json_output::Error::Encoding(error)) => Err(execution_failure(path, error.to_string())),
    }
}

fn decode_failure(path: &str, error: NibArchiveError) -> Failure {
    match error {
        NibArchiveError::Malformed(reason) => Failure::new(
            "parse_failed",
            "analysis_output",
            "The selected file is not a valid supported NIBArchive.".into(),
            false,
            "Select a compiled NIB archive and retry.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("path", Detail::Text(path.into())),
                ("reason", Detail::Text(reason)),
            ]),
        ),
        NibArchiveError::Limit { message, .. } => resource_failure(path, message),
    }
}

fn execution_failure(path: &str, reason: String) -> Failure {
    Failure::new(
        "execution_failed",
        "provider_execution",
        "NIB archive inspection could not complete.".into(),
        true,
        "Check the selected local file and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

fn resource_failure(path: &str, reason: String) -> Failure {
    Failure::new(
        "resource_limit",
        "resource_limit",
        "NIB archive inspection exceeded a supported resource bound.".into(),
        false,
        "Select a smaller archive or request a narrower projection.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(reason)),
            (
                "maximum_input_bytes",
                Detail::Count(nib::MAX_INPUT_BYTES as u64),
            ),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_preserves_nib_identity_and_decoded_object_facts() {
        let bytes = minimal_nib_archive();
        let evidence = build_evidence(
            "/tmp/Main.nib",
            Snapshot {
                bytes,
                sha256: "a".repeat(64),
            },
        )
        .expect("valid NIB archive should produce Evidence");
        let value = serde_json::to_value(evidence.as_ref()).expect("Evidence serializes");

        assert_eq!(value["subject"]["format"], "nib");
        assert_eq!(value["subject"]["local_path"], "/tmp/Main.nib");
        assert_eq!(
            value["normalized_result"]["objects"][0]["class_name"],
            "Outlet"
        );
        assert_eq!(
            value["normalized_result"]["objects"][0]["values"]["title"]["$nib_data_base64"],
            "YWJj"
        );
        assert_eq!(value["operation"], OPERATION);
    }

    fn minimal_nib_archive() -> Vec<u8> {
        let mut bytes = vec![0u8; 50];
        bytes[..10].copy_from_slice(b"NIBArchive");
        put_u32(&mut bytes, 10, 1);
        put_u32(&mut bytes, 14, 7);
        put_u32(&mut bytes, 18, 1);
        put_u32(&mut bytes, 22, 50);
        put_u32(&mut bytes, 26, 1);
        put_u32(&mut bytes, 30, 53);
        put_u32(&mut bytes, 34, 1);
        put_u32(&mut bytes, 38, 59);
        put_u32(&mut bytes, 42, 1);
        put_u32(&mut bytes, 46, 65);
        bytes.extend_from_slice(&[0x80, 0x80, 0x81]);
        bytes.extend_from_slice(&[0x85, b't', b'i', b't', b'l', b'e']);
        bytes.extend_from_slice(&[0x80, 8, 0x83, b'a', b'b', b'c']);
        bytes.extend_from_slice(&[0x86, 0x80, b'O', b'u', b't', b'l', b'e', b't']);
        bytes
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
