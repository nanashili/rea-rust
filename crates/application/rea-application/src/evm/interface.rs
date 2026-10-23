//! Application projection for offline EVM interface candidates.
//!
//! The runtime adapter owns file admission and Evidence wrapping. This module
//! owns the stable normalized result and its operation-specific limits.

use rea_core::cancellation::Cancellation;
use rea_core::evidence::{
    ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
};
use rea_core::failure::{Detail, Failure, InputIssue};
use rea_host::fs::stable_file::Snapshot;
use rea_host::fs::stable_file::{self, FileAccess};
pub use rea_rust_analysis::evm::Encoding as EvmEncoding;
use rea_rust_analysis::evm::{self, Encoding};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const OPERATION: &str = "inspect_evm_interface";
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Build an input failure owned by this operation, preserving the caller's
/// field identity instead of attributing CLI input errors to another command.
pub fn invalid_input(field: &'static str, reason: &'static str, message: String) -> Failure {
    let details = BTreeMap::from([
        ("operation", Detail::Text(OPERATION.into())),
        (
            "issues",
            Detail::Issues(vec![InputIssue {
                path: vec![field.into()],
                reason,
                message,
                expected: None,
            }]),
        ),
    ]);

    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and try again.".into(),
        true,
        "Correct the listed arguments and retry.".into(),
        details,
    )
}

const PROVIDER: Provider = Provider {
    id: PROVIDER_ID,
    name: "REA EVM offline interface inspector",
    version: Some(PROVIDER_VERSION),
};

pub fn inspect_evidence<F: FileAccess>(
    access: Arc<F>,
    path: &str,
    encoding: Encoding,
    cancellation: &Cancellation,
) -> Result<ArtifactEvidence, Failure> {
    validate_path(path)?;

    let snapshot = stable_file::read(
        access,
        std::path::Path::new(path),
        evm::MAX_INPUT_BYTES,
        cancellation,
    )
    .map_err(|_| execution(path, "Unable to read a stable local EVM carrier".into()))?;
    let report = inspect_snapshot(path, snapshot, encoding)?;
    let limitations = report.limitations.clone();
    let subject = Subject::new(
        path,
        report.artifact.sha256.clone(),
        NativeFormat::Evm,
        None,
    )
    .map_err(|error| execution(path, error.to_string()))?;
    ArtifactEvidence::new(
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
    .map_err(|error| execution(path, error.to_string()))
}

const PROVIDER_ID: &str = "evmole-interface";
const PROVIDER_VERSION: &str = "evmole@0.9.3";

/// Decode a caller-provided revert payload while preserving unsupported custom
/// selectors as opaque bytes. This is a pure projection and performs no call.
pub fn decode_revert_payload(payload: &[u8]) -> Result<rea_rust_analysis::evm::Revert, Failure> {
    rea_rust_analysis::evm::decode_revert(payload).map_err(|error| failure("<payload>", error))
}

pub const REVERT_OPERATION: &str = "inspect_evm_revert";

const REVERT_PROVIDER: Provider = Provider {
    id: "evm-revert-decoder",
    name: "REA EVM offline revert decoder",
    version: Some("rea-evm-revert-v1"),
};

pub fn inspect_revert_evidence<F: FileAccess>(
    access: Arc<F>,
    path: &str,
    encoding: Encoding,
    cancellation: &Cancellation,
) -> Result<ArtifactEvidence, Failure> {
    let snapshot = stable_file::read(
        access,
        std::path::Path::new(path),
        evm::MAX_INPUT_BYTES,
        cancellation,
    )
    .map_err(|_| {
        execution(
            path,
            "Unable to read a stable local EVM revert carrier".into(),
        )
    })?;
    let report = inspect_revert_snapshot(path, snapshot, encoding)?;
    let limitations = report.limitations.clone();
    let subject = Subject::new(
        path,
        report.artifact.sha256.clone(),
        NativeFormat::Evm,
        None,
    )
    .map_err(|error| execution(path, error.to_string()))?;
    ArtifactEvidence::new(
        subject,
        REVERT_PROVIDER,
        Observation {
            operation: REVERT_OPERATION,
            result: report,
            limitations,
            locations: vec![Location::ArtifactPath {
                path: path.to_owned(),
            }],
        },
    )
    .map_err(|error| execution(path, error.to_string()))
}

#[derive(Debug, Serialize)]
pub struct RevertArtifact {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
    pub encoding: &'static str,
}

#[derive(Debug, Serialize)]
pub struct RevertPayload {
    pub sha256: String,
    pub bytes: usize,
    pub hex: String,
    pub selector: Option<String>,
    pub data_hex: String,
}

#[derive(Debug, Serialize)]
pub struct RevertReport {
    pub artifact: RevertArtifact,
    pub payload: RevertPayload,
    pub result: rea_rust_analysis::evm::Revert,
    pub evidence_kind: &'static str,
    pub runtime_execution: &'static str,
    pub diagnostics: Diagnostics,
    pub limitations: Vec<String>,
}

pub fn inspect_revert_snapshot(
    path: &str,
    snapshot: Snapshot,
    encoding: Encoding,
) -> Result<RevertReport, Failure> {
    let payload =
        evm::decode_carrier(&snapshot.bytes, encoding).map_err(|error| failure(path, error))?;
    let payload_hex = hex(&payload);
    let payload_sha256 = sha256(&payload);
    let selector = (payload.len() >= 4).then(|| format!("0x{}", &payload_hex[..8]));
    let data_hex = if payload.len() >= 4 {
        payload_hex[8..].to_owned()
    } else {
        payload_hex.clone()
    };
    let result = evm::decode_revert(&payload).map_err(|error| failure(path, error))?;
    let encoding_name = match encoding {
        Encoding::Raw => "raw",
        Encoding::Hex => "hex",
    };
    Ok(RevertReport {
        artifact: RevertArtifact {
            path: path.to_owned(),
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.len(),
            encoding: encoding_name,
        },
        payload: RevertPayload {
            sha256: payload_sha256,
            bytes: payload.len(),
            hex: payload_hex,
            selector,
            data_hex,
        },
        result,
        evidence_kind: "inferred",
        runtime_execution: "not-performed",
        diagnostics: Diagnostics {
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
        },
        limitations: vec![
            "Only the caller-selected local carrier is inspected; no target execution, chain lookup, RPC access or network request is performed.".into(),
            "Standard Error(string) and Panic(uint256) payloads are decoded. Custom and unsupported selectors remain explicitly opaque.".into(),
            format!("Input is bounded to {} bytes.", evm::MAX_INPUT_BYTES),
        ],
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[derive(Debug, Serialize)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
    pub encoding: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Bytecode {
    pub sha256: String,
    pub bytes: usize,
    pub hex: String,
    pub digest_algorithm: &'static str,
    pub kind: &'static str,
    pub deployment_authenticity: &'static str,
    pub hardfork: &'static str,
    pub metadata: evm::Metadata,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub artifact: Artifact,
    pub bytecode: Bytecode,
    pub evidence_kind: &'static str,
    pub functions: Vec<evm::Function>,
    pub discovery_completeness: &'static str,
    pub runtime_execution: &'static str,
    pub diagnostics: Diagnostics,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Diagnostics {
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

/// Analyze an already admitted stable snapshot using the caller's encoding.
pub fn inspect_snapshot(
    path: &str,
    snapshot: Snapshot,
    encoding: Encoding,
) -> Result<Report, Failure> {
    validate_path(path)?;

    let parsed = evm::inspect(&snapshot.bytes, encoding).map_err(|error| failure(path, error))?;
    let encoding_name = match encoding {
        Encoding::Raw => "raw",
        Encoding::Hex => "hex",
    };
    let limitations = vec![
        format!(
            "Provider {PROVIDER_ID} ({PROVIDER_VERSION}) recovers only bytecode-relative dispatch candidates; selectors, argument text and mutability are inferences."
        ),
        "Bytecode kind, hardfork and deployed-contract authenticity are unknown. No target execution, chain lookup, RPC access or network request is performed.".into(),
        "Only common PUSH4/EQ dispatch patterns are recognized. Empty results do not prove the absence of callable dispatch, and selector signatures are not resolved.".into(),
        "The selected carrier and decoded bytecode have distinct SHA-256 identities; SHA-256 is not the Ethereum Keccak code hash.".into(),
        format!("Input is bounded to {} bytes and complete output is bounded to {} bytes.", evm::MAX_INPUT_BYTES, MAX_OUTPUT_BYTES),
    ];
    let report = Report {
        artifact: Artifact {
            path: path.to_owned(),
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.len(),
            encoding: encoding_name,
        },
        bytecode: Bytecode {
            sha256: parsed.sha256,
            bytes: parsed.bytes,
            hex: parsed.hex,
            digest_algorithm: "sha256",
            kind: "unknown",
            deployment_authenticity: "unknown",
            hardfork: "unknown",
            metadata: parsed.metadata,
        },
        evidence_kind: "inferred",
        functions: parsed.functions,
        discovery_completeness: "unknown",
        runtime_execution: "not-performed",
        diagnostics: Diagnostics {
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
        },
        limitations,
    };
    let length = serde_json::to_vec(&report)
        .map_err(|error| execution(path, error.to_string()))?
        .len();
    if length > MAX_OUTPUT_BYTES {
        return Err(resource(path, length));
    }
    Ok(report)
}

fn validate_path(path: &str) -> Result<(), Failure> {
    if path.is_empty() {
        return Err(invalid_input(
            "path",
            "invalid_value",
            "EVM input requires a non-empty path.".into(),
        ));
    }
    if path.contains('\0') {
        return Err(invalid_input(
            "path",
            "invalid_format",
            "Local filesystem paths cannot contain NUL bytes.".into(),
        ));
    }
    if !std::path::Path::new(path).is_absolute() {
        return Err(invalid_input(
            "path",
            "invalid_format",
            "Expected an absolute filesystem path on this host.".into(),
        ));
    }
    Ok(())
}

fn failure(path: &str, error: evm::Error) -> Failure {
    match error {
        evm::Error::InputLimit => resource(path, evm::MAX_INPUT_BYTES + 1),
        evm::Error::UnsupportedContainer => Failure::new(
            "unsupported_target",
            "unsupported",
            "Container marker EF00 is outside the verified flat-bytecode interface profile.".into(),
            false,
            "Select flat EVM bytecode without the EF00 container marker, then retry.".into(),
            details(),
        ),
        evm::Error::InvalidHex(reason) => {
            let mut details = details();
            details.insert(
                "issues",
                Detail::Issues(vec![rea_core::failure::InputIssue {
                    path: vec!["encoding".into()],
                    reason: "invalid_format",
                    message: reason.into(),
                    expected: Some("raw or even-length hexadecimal bytes"),
                }]),
            );
            Failure::new("invalid_input", "invalid_input", "Analysis input is invalid. Check the arguments and retry.".into(), false, "Select encoding raw for bytes or hex for an even-length hexadecimal carrier, then retry.".into(), details)
        }
    }
}

fn resource(path: &str, observed: usize) -> Failure {
    let mut details = details();
    details.insert("resource", Detail::Text("capacity".into()));
    details.insert("path", Detail::Text(path.into()));
    details.insert("observed_bytes", Detail::Count(observed as u64));
    details.insert(
        "maximum_input_bytes",
        Detail::Count(evm::MAX_INPUT_BYTES as u64),
    );
    details.insert(
        "maximum_output_bytes",
        Detail::Count(MAX_OUTPUT_BYTES as u64),
    );
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        "EVM interface inspection exceeds its bounded representation capacity.".into(),
        false,
        "Select a smaller local carrier and retry within the reported limits.".into(),
        details,
    )
}

fn execution(path: &str, reason: String) -> Failure {
    let mut details = details();
    details.insert("path", Detail::Text(path.into()));
    details.insert("reason", Detail::Text(reason));
    Failure::new(
        "execution_failure",
        "execution_failure",
        "Analysis could not complete. Review the reported details and retry.".into(),
        false,
        "Review the local artifact and retry.".into(),
        details,
    )
}

fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([
        ("operation", Detail::Text(OPERATION.into())),
        ("provider_id", Detail::Text(PROVIDER_ID.into())),
        ("provider_version", Detail::Text(PROVIDER_VERSION.into())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_raw_snapshot_with_stable_identity_and_unknowns() {
        let report = inspect_snapshot(
            "/tmp/bytecode.bin",
            Snapshot {
                bytes: vec![0x63, 0x12, 0x34, 0x56, 0x78, 0x14],
                sha256: "a".repeat(64),
            },
            Encoding::Raw,
        )
        .unwrap();
        assert_eq!(report.artifact.encoding, "raw");
        assert_eq!(report.bytecode.hex, "631234567814");
        assert_eq!(report.functions[0].selector, "0x12345678");
        assert_eq!(report.runtime_execution, "not-performed");

        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(
            serialized["functions"][0],
            serde_json::json!({
                "selector": "0x12345678",
                "bytecode_offset": 0,
                "dispatch": "abi",
                "inferred_arguments": null,
                "inferred_state_mutability": null,
            })
        );
    }

    #[test]
    fn preserves_terminal_metadata_alongside_dispatch_candidates() {
        let mut bytes = vec![0x63, 0x12, 0x34, 0x56, 0x78];
        let metadata = [0xa1, 0x64, b's', b'o', b'l', b'c', 0x43, 0x00, 0x08, 0x1e];
        bytes.extend(metadata);
        bytes.extend(u16::try_from(metadata.len()).unwrap().to_be_bytes());

        let report = inspect_snapshot(
            "/tmp/bytecode-with-metadata.bin",
            Snapshot {
                bytes,
                sha256: "c".repeat(64),
            },
            Encoding::Raw,
        )
        .unwrap();

        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].selector, "0x12345678");
        assert_eq!(report.bytecode.metadata.status, "decoded");
        assert_eq!(report.bytecode.metadata.bytecode_offset, Some(5));
        assert_eq!(report.bytecode.metadata.cbor_bytes, Some(10));
        assert_eq!(
            report
                .bytecode
                .metadata
                .compiler_version
                .as_ref()
                .map(|version| version.value.as_str()),
            Some("0.8.30")
        );

        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(
            serialized["bytecode"]["metadata"]["compiler_version"]["representation"],
            "release-bytes"
        );
        assert_eq!(
            serialized["bytecode"]["metadata"]["entries"][0]["value"]["kind"],
            "bytes"
        );
    }

    #[test]
    fn projects_revert_with_exact_selector_and_data_provenance() {
        let report = inspect_revert_snapshot(
            "/tmp/revert.bin",
            Snapshot {
                bytes: vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02],
                sha256: "a".repeat(64),
            },
            Encoding::Raw,
        )
        .unwrap();

        assert_eq!(report.artifact.encoding, "raw");
        assert_eq!(report.payload.hex, "deadbeef0102");
        assert_eq!(report.payload.selector.as_deref(), Some("0xdeadbeef"));
        assert_eq!(report.payload.data_hex, "0102");
        assert_eq!(
            report.result,
            rea_rust_analysis::evm::Revert::Custom {
                selector: "0xdeadbeef".into(),
                data_hex: "0102".into(),
            }
        );
    }

    #[test]
    fn projects_short_revert_as_explicit_unknown() {
        let report = inspect_revert_snapshot(
            "/tmp/revert.bin",
            Snapshot {
                bytes: vec![0x01, 0x02],
                sha256: "b".repeat(64),
            },
            Encoding::Raw,
        )
        .unwrap();

        assert_eq!(report.payload.selector, None);
        assert_eq!(report.payload.data_hex, "0102");
        assert_eq!(
            report.result,
            rea_rust_analysis::evm::Revert::Unknown {
                data_hex: "0102".into(),
            }
        );
    }
}
