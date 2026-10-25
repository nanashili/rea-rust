//! Deterministic, local-only web capture and screenshot comparison tools.
//!
//! Compatibility owners: `src/server/registerBrowserTools.ts`
//! (`compare_web_captures`, `compare_web_screenshots`),
//! `src/application/BrowserObservationService.ts`,
//! `src/application/BrowserEvidence.ts`, `src/browser/CdpBrowserProvider.ts`,
//! `src/browser/PngVisualDiff.ts`, `src/domain/browserCaptureComparison.ts`,
//! `src/domain/webCaptureDiff.ts` and `src/domain/browserScenarioDiff.ts`.
//!
//! Both tools accept only inline, self-verifying inputs (no Evidence-id
//! resolution): passive `before`/`after` captures, inline `before_scenario`/
//! `after_scenario` recordings, or inline PNG artifacts. The comparison is a
//! pure function; no browser, network transport, or filesystem access occurs.
mod captures;
pub(crate) mod digest;
mod network;
mod scenario;
mod screenshot;

use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Value, json};

const COMPARE_CAPTURES: &str = "compare_web_captures";
const COMPARE_SCREENSHOTS: &str = "compare_web_screenshots";

/// `CDP_BROWSER_PROVIDER_IDENTITY`.
fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-cdp-browser",
        "REA Chrome DevTools Protocol observation provider",
        Some("2".to_owned()),
    )
}

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(COMPARE_CAPTURES, |context, input| {
        compare_captures(context, &input).into()
    });
    registry.handle(COMPARE_SCREENSHOTS, |context, input| {
        compare_screenshots(context, &input).into()
    });
}

fn compare_captures(_context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let (result, parameters, limitations) = captures::compare(input)?;
    build_evidence(
        "rea.web-capture-diff",
        COMPARE_CAPTURES,
        parameters,
        result,
        limitations,
    )
}

fn compare_screenshots(
    _context: &ToolContext<'_>,
    input: &Value,
) -> Result<Evidence, AnalysisError> {
    validate_screenshot_artifacts(input)?;
    let result = screenshot::compare(input)?;
    let parameters = screenshot_parameters(input);
    let limitations = string_array(&result, "limitations");
    build_evidence(
        "rea.web-screenshot-diff",
        COMPARE_SCREENSHOTS,
        parameters,
        result,
        limitations,
    )
}

/// `createBrowserEvidence` for a request-scoped comparison: null subject, no
/// environment, `observed` confidence and `external-service` authority.
fn build_evidence(
    predicate: &str,
    operation: &str,
    parameters: Value,
    result: Value,
    limitations: Vec<String>,
) -> Result<Evidence, AnalysisError> {
    let observation = Observation::new(operation, parameters, result)
        .predicate(predicate)
        .confidence("observed")
        .authority("external-service")
        .limitations(limitations);
    Evidence::create(None, &provider(), observation)
        .map_err(|error| AnalysisError::output(String::new(), error.to_string()))
}

/// `browserParameters` for the screenshot comparison branch.
fn screenshot_parameters(input: &Value) -> Value {
    let sha = |field: &str| -> Value {
        input
            .get(field)
            .and_then(|artifact| artifact.get("sha256"))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let threshold = input
        .get("channel_threshold")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    json!({
        "before_artifact_sha256": sha("before"),
        "after_artifact_sha256": sha("after"),
        "channel_threshold": threshold,
    })
}

/// `webScreenshotArtifactSchema` digest/size refinement, reproduced as input
/// validation because the frozen JSON Schema cannot express it.
fn validate_screenshot_artifacts(input: &Value) -> Result<(), AnalysisError> {
    let mut issues = Vec::new();
    for field in ["before", "after"] {
        let Some(artifact) = input.get(field).and_then(Value::as_object) else {
            continue;
        };
        let encoded = artifact
            .get("data_base64")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match decode_canonical_base64(encoded) {
            None => issues.push(custom_issue(field, "Invalid canonical base64")),
            Some(bytes) => {
                let declared_bytes = artifact.get("bytes").and_then(Value::as_u64);
                let declared_sha = artifact.get("sha256").and_then(Value::as_str);
                let actual_sha = sha256_hex(&bytes);
                if declared_bytes != Some(bytes.len() as u64)
                    || declared_sha != Some(actual_sha.as_str())
                {
                    issues.push(custom_issue(
                        field,
                        "Screenshot artifact digest or size mismatch",
                    ));
                }
            }
        }
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(AnalysisError::input(COMPARE_SCREENSHOTS, issues))
    }
}

fn custom_issue(field: &str, message: &str) -> rea_core::analysis_error::InputIssue {
    rea_core::analysis_error::InputIssue {
        path: vec![Value::String(field.to_owned())],
        reason: "invalid_value",
        message: Some(message.to_owned()),
        expected: None,
        minimum: None,
        maximum: None,
    }
}

fn decode_canonical_base64(value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    if value.is_empty() || value.len() % 4 != 0 {
        return None;
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded = engine.decode(value).ok()?;
    if engine.encode(&decoded) == value {
        Some(decoded)
    } else {
        None
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble"));
    }
    out
}

/// Extract a `limitations` string array from a normalized result object.
fn string_array(result: &Value, key: &str) -> Vec<String> {
    result
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The `_ = ToolOutput` keeps the import live if a branch is cfg'd out.
#[allow(dead_code)]
fn _assert_output(output: ToolOutput) -> ToolOutput {
    output
}
