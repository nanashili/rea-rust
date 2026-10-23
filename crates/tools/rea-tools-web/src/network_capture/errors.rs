//! Capture decoder boundary failures and their typed projections.
//!
//! Compatibility owners: `src/browser/history/CaptureFormatError.ts`,
//! `src/browser/history/HistoricalCaptureDecoder.ts` (reply failure mapping),
//! `src/browser/history/CaptureFailures.ts` and
//! `src/browser/history/MitmproxyCaptureAdapter.ts`.
use super::limits::{CAPTURE_DEPTH, CAPTURE_INPUT_BYTES};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Value, json};

const OPERATION: &str = "inspect_web_network_capture";

/// Expected malformed, unsupported or oversized producer data at a decoder boundary.
///
/// Compatibility owner: `CaptureFormatError`. `reason` selects the reply
/// mapping back in the decoder (`format`, `unsupported`, `input-limit`,
/// `expanded-limit`, `limit`).
#[derive(Clone, Debug)]
pub struct CaptureFormatError {
    pub reason: &'static str,
    pub message: String,
    pub pointer: String,
}

impl CaptureFormatError {
    pub fn new(
        reason: &'static str,
        message: impl Into<String>,
        pointer: impl Into<String>,
    ) -> Self {
        Self {
            reason,
            message: message.into(),
            pointer: pointer.into(),
        }
    }
}

/// Map a `CaptureFormatError` to its typed analysis failure, matching the
/// `HistoricalCaptureDecoder` reply handling exactly.
pub fn from_capture_error(format: &str, error: CaptureFormatError) -> AnalysisError {
    match error.reason {
        "format" => AnalysisError::input(
            OPERATION,
            vec![InputIssue {
                path: vec![json!("capture_path"), json!(error.pointer)],
                reason: "invalid_format",
                message: Some(error.message),
                expected: None,
                minimum: None,
                maximum: None,
            }],
        ),
        "unsupported" => AnalysisError::capability_unavailable(format, OPERATION, error.message),
        "input-limit" => AnalysisError::input(
            OPERATION,
            vec![InputIssue {
                path: vec![json!("capture_path"), json!(error.pointer)],
                reason: "out_of_range",
                message: Some(error.message),
                expected: Some(json!({ "maximum_capture_nesting": CAPTURE_DEPTH })),
                minimum: None,
                maximum: None,
            }],
        ),
        "expanded-limit" => AnalysisError::input(
            OPERATION,
            vec![InputIssue {
                path: vec![json!("capture_path"), json!(error.pointer)],
                reason: "out_of_range",
                message: Some(error.message),
                expected: Some(json!({ "maximum_expanded_capture_bytes": CAPTURE_INPUT_BYTES })),
                minimum: None,
                maximum: None,
            }],
        ),
        "resource-limit" | "limit" => memory_failure(format, &error.message),
        "decoder" => {
            let mut diagnostics = serde_json::Map::new();
            diagnostics.insert("phase".into(), json!("decoder"));
            diagnostics.insert("failure_kind".into(), json!("decoder"));
            diagnostics.insert("reason".into(), json!(error.message));
            diagnostics.insert("pointer".into(), json!(error.pointer));
            AnalysisError::provider_adapter(format, OPERATION).with_diagnostics(diagnostics)
        }
        _ => AnalysisError::output(OPERATION, error.message),
    }
}

/// `captureMemoryFailure`: a resource-constraint failure with the actual limits.
fn memory_failure(format: &str, reason: &str) -> AnalysisError {
    let limits = json!({
        "boundary": "historical-capture-decoder",
        "format": format,
        "maximum_input_bytes": CAPTURE_INPUT_BYTES,
        "maximum_reply_bytes": super::limits::CAPTURE_OUTPUT_BYTES,
    });
    AnalysisError::resource_constraint(
        OPERATION,
        "memory",
        format!("{reason}. No complete capture result is available."),
        Some(limits),
    )
}

/// `AnalysisInputError` for an unreadable capture path.
pub fn not_found(path: &str, code: &str) -> AnalysisError {
    AnalysisError::input(
        OPERATION,
        vec![InputIssue {
            path: vec![json!("capture_path")],
            reason: "invalid_value",
            message: Some(format!(
                "Selected capture could not be read ({code}): {path}."
            )),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    )
}

/// `AnalysisAccessDeniedError` for a permission failure reading the capture.
pub fn access_denied(path: &str, code: &str) -> AnalysisError {
    AnalysisError::access_denied(OPERATION, path, code)
}

/// `AnalysisInputError` for an oversized capture file.
pub fn over_input_limit(message: &str) -> AnalysisError {
    AnalysisError::input(
        OPERATION,
        vec![InputIssue {
            path: vec![json!("capture_path")],
            reason: "out_of_range",
            message: Some(format!(
                "{message}. Select a capture within the {CAPTURE_INPUT_BYTES}-byte input budget."
            )),
            expected: Some(json!({ "maximum_capture_bytes": CAPTURE_INPUT_BYTES })),
            minimum: None,
            maximum: None,
        }],
    )
}

/// `MitmproxyCaptureAdapter.command` unavailability on this host.
///
/// macOS is never Linux, so native mitmproxy decoding is always unavailable;
/// the reason text matches the oracle exactly.
pub fn mitmproxy_unavailable() -> AnalysisError {
    const REQUIREMENT: &str = "Native capture decoding requires Linux and an absolute REA_MITMDUMP_COMMAND path to caller-supplied mitmdump 12.2.3; HAR needs no external engine.";
    AnalysisError::capability_unavailable("mitmproxy", OPERATION, REQUIREMENT)
        .with_user_message(REQUIREMENT)
}

/// `AnalysisInputError` issues for the service-level refinements.
pub fn input_issue(path: &str, reason: &'static str, message: &str) -> AnalysisError {
    AnalysisError::input(
        OPERATION,
        vec![InputIssue {
            path: vec![Value::String(path.to_owned())],
            reason,
            message: Some(message.to_owned()),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    )
}
