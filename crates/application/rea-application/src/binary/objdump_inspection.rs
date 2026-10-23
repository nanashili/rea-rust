//! Validation and projection for captured GNU objdump observations.
//!
//! The process adapter owns execution, output limits, decoding, and artifact
//! hashing.  This module deliberately consumes those captured facts only: it
//! never starts objdump, reads the selected path, or interprets objdump's text
//! as a stable normalized format.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_with_objdump";

/// Caller-selected operation.  `architectures` has no artifact subject.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjdumpOperation {
    FileHeaders,
    SectionHeaders,
    Symbols,
    Relocations,
    Dwarf,
    Disassemble,
    DisassembleAll,
    Architectures,
}

/// The request metadata retained alongside a captured command result.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ObjdumpRequest {
    pub operation: ObjdumpOperation,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub follow_debug_links: bool,
    #[serde(default)]
    pub symbol: Option<String>,
}

/// Output and lifecycle facts captured by the process boundary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CapturedObjdumpOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i64>,
    pub signal: Option<String>,
    pub output_truncated: bool,
    pub completion_status: CompletionStatus,
    #[serde(default)]
    pub artifact_sha256_after: Option<String>,
    #[serde(default)]
    pub artifact_changed: Option<bool>,
    #[serde(default)]
    pub artifact_sha256_before: Option<String>,
    #[serde(default)]
    pub provider_executable: Option<String>,
    #[serde(default)]
    pub command_arguments: Option<Vec<String>>,
    #[serde(default)]
    pub stdout_invalid_utf8: bool,
    #[serde(default)]
    pub stderr_invalid_utf8: bool,
    #[serde(default)]
    pub output_budget_bytes: Option<u64>,
}

/// Whether the process boundary confirmed command completion.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CompletionStatus {
    Complete,
    Unknown,
}

/// A captured result plus the uncertainty that belongs to its producer.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ObjdumpObservation {
    pub request: ObjdumpRequest,
    pub result: CapturedObjdumpOutput,
    pub limitations: Vec<String>,
}

/// Validate request metadata before it is associated with captured output.
pub fn validate_request(request: &ObjdumpRequest) -> Result<(), Failure> {
    match request.operation {
        ObjdumpOperation::Architectures => {
            if request.path.is_some() || request.symbol.is_some() || request.follow_debug_links {
                return Err(invalid("architectures does not accept artifact options"));
            }
        }
        ObjdumpOperation::Disassemble => {
            require_path(request)?;
            if request.symbol.as_deref().is_some_and(|symbol| {
                symbol.is_empty() || symbol.chars().any(|character| character == '\0')
            }) {
                return Err(invalid("symbol must be a non-empty NUL-free string"));
            }
        }
        _ => {
            require_path(request)?;
            if request.symbol.is_some() {
                return Err(invalid("symbol is only valid for disassemble"));
            }
        }
    }
    Ok(())
}

/// Parse an adapter-shaped request and captured output without touching the target.
///
/// The input shape is `{ "request": ..., "capture": ... }`; the returned
/// value is the stable result projection used by Evidence adapters.
pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("objdump inspection input must be an object"))?;
    let request: ObjdumpRequest = serde_json::from_value(
        object
            .get("request")
            .cloned()
            .ok_or_else(|| invalid("objdump request is required"))?,
    )
    .map_err(|_| invalid("invalid objdump request"))?;
    validate_request(&request)?;

    let capture: CapturedObjdumpOutput = serde_json::from_value(
        object
            .get("capture")
            .cloned()
            .ok_or_else(|| invalid("captured objdump output is required"))?,
    )
    .map_err(|_| invalid("invalid captured objdump output"))?;
    let observation = project(request, capture)?;
    serde_json::to_value(observation).map_err(|_| invalid("objdump result is not serializable"))
}

fn project(
    request: ObjdumpRequest,
    output: CapturedObjdumpOutput,
) -> Result<ObjdumpObservation, Failure> {
    let mut limitations = vec![if request.operation == ObjdumpOperation::Architectures {
        "The objdump version is not reported; architecture output lists BFD targets advertised by the installed tool and is independent of any artifact.".to_owned()
    } else {
        "The executable version and supported formats are reported as unknown because no reliable version probe was performed.".to_owned()
    }];
    limitations.push("A non-zero process exit is preserved as an observed command result.".into());

    if request.symbol.is_some() {
        limitations.push("Disassembly is scoped to the caller-selected symbol using GNU objdump matching and symbol-boundary semantics; an empty match does not establish artifact-wide absence.".into());
    }
    if request.follow_debug_links {
        limitations.push("DWARF output may include local debug-link files whose identities are not bound to Evidence.".into());
    }
    if output.output_truncated {
        limitations.push("The provider command ended before completion could be confirmed; captured output is partial.".into());
    }
    if output.stdout_invalid_utf8 || output.stderr_invalid_utf8 {
        let streams = match (output.stdout_invalid_utf8, output.stderr_invalid_utf8) {
            (true, true) => "stdout and stderr",
            (true, false) => "stdout",
            (false, true) => "stderr",
            (false, false) => unreachable!(),
        };
        limitations.push(format!(
            "Captured {streams} bytes contain invalid or incomplete UTF-8; replacement characters in the text capture do not preserve the original bytes."
        ));
    }
    if let Some(signal) = output.signal.as_deref() {
        limitations.push(format!("The provider process terminated by signal {signal}; captured output may be partial and command completion is unknown."));
    }
    if output.completion_status == CompletionStatus::Unknown {
        limitations.push(
            "Command completion is unknown; retained stdout and stderr are partial observations."
                .into(),
        );
    }
    if request.operation != ObjdumpOperation::Architectures {
        limitations.push("When both are available, pre-run and post-run digests detect artifact changes across the provider call but cannot prove the exact bytes consumed during the call.".into());
    }
    if output.artifact_changed == Some(true) {
        limitations.push("The provider command may have changed the artifact while analysis was running; pre-run and post-run digests are both reported.".into());
    }

    Ok(ObjdumpObservation {
        request,
        result: output,
        limitations,
    })
}

fn require_path(request: &ObjdumpRequest) -> Result<(), Failure> {
    if request.path.as_deref().is_none_or(str::is_empty) {
        return Err(invalid(
            "artifact objdump operations require a non-empty path",
        ));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide caller-selected objdump metadata and bounded captured output.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
