//! Read-only property-list Evidence workflow.
use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use base64::Engine;
use rea_core::{
    cancellation::Cancellation,
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::plist;
use serde_json::{Value, json};
use sha2::Digest;
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_plist";

/// Validate the public, caller-supplied property-list boundary. The runtime
/// adapter may provide either inline bytes or an already retained Evidence
/// record; both paths remain read-only and retain the caller's source path.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("property-list input must be an object"))?;

    if let Some(evidence) = object.get("evidence") {
        if object.len() != 1 || !evidence.is_object() {
            return Err(invalid_input(
                "Evidence input must contain only a non-empty evidence object",
            ));
        }
        return Ok(());
    }

    let path = object
        .get("path")
        .and_then(Value::as_str)
        .or_else(|| object.get("source_path").and_then(Value::as_str))
        .ok_or_else(|| invalid_input("path is required"))?;
    if path.is_empty() || path.bytes().any(|byte| byte == 0) {
        return Err(invalid_input(
            "path must be a non-empty string without NUL bytes",
        ));
    }
    let bytes = object.get("bytes_base64");
    if bytes.is_none() {
        return Err(invalid_input("bytes_base64 is required"));
    }
    if let Some(encoded) = bytes {
        let encoded = encoded
            .as_str()
            .ok_or_else(|| invalid_input("bytes_base64 must be a string"))?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid_input("bytes_base64 is malformed"))?;
        if decoded.len() > plist::MAX_INPUT_BYTES {
            return Err(invalid_input(
                "property-list bytes exceed the admitted size",
            ));
        }
    }
    Ok(())
}

/// Decode inline bytes or project the normalized result from retained Evidence.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .or_else(|| input.get("source_path").and_then(Value::as_str))
        .unwrap_or_default();
    if let Some(evidence) = input.get("evidence") {
        if evidence.get("operation").and_then(Value::as_str) != Some(OPERATION) {
            return Err(invalid_input(
                "retained Evidence operation must be inspect_plist",
            ));
        }
        let result = evidence
            .get("normalized_result")
            .or_else(|| evidence.get("result"))
            .ok_or_else(|| invalid_input("retained Evidence has no normalized result"))?;
        return Ok(result.clone());
    }
    let encoded = input
        .get("bytes_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("bytes_base64 is required"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid_input("bytes_base64 is malformed"))?;
    let report = plist::read(&bytes, path.to_owned()).map_err(|error| {
        Failure::new(
            "parse_failed",
            "analysis_output",
            error.to_string().into(),
            false,
            "Supply valid property-list bytes and retry.".into(),
            BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
        )
    })?;
    let format = match report.format {
        plist::Format::Xml => "xml",
        plist::Format::Binary => "binary",
        plist::Format::OpenStep => "unknown",
    };
    let mut limitations = report.limitations;
    if matches!(report.format, plist::Format::OpenStep) {
        limitations.push("OpenStep property-list syntax was decoded, but the public format classification remains unknown.".into());
    }
    limitations.sort();
    limitations.dedup();
    Ok(json!({
        "format": format,
        "value": report.value,
        "bundle": report.bundle,
        "source_path": report.source_path,
        "provenance": [],
        "limitations": limitations,
        "source_sha256": format!("{:x}", sha2::Sha256::digest(&bytes)),
        "source_bytes": bytes.len(),
    }))
}

/// Retain a provider result after validating the same caller-selected input.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid_input("property-list result must be an object"));
    }
    Ok(result)
}
const PROVIDER: Provider = Provider {
    id: "rust-plist-reader",
    name: "REA Rust property-list reader",
    version: Some("1"),
};
const EXECUTION_MESSAGE: &str = "Analysis could not complete. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";

#[derive(Default)]
pub struct PlistAnalyzer;
impl ArtifactAnalyzer for PlistAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = plist::MAX_INPUT_BYTES;
    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, snapshot)
    }
}

pub struct PlistInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, PlistAnalyzer>,
}
impl<F: rea_host::fs::stable_file::FileAccess> PlistInspection<F> {
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
    let report = plist::read(&snapshot.bytes, path.to_owned())
        .map_err(|error| parse_failure(error, path))?;
    let subject = Subject::new(path, snapshot.sha256, NativeFormat::Plist, None)
        .map_err(|error| execution(path, error.to_string()))?;
    let limitations = report.limitations.clone();
    let mut result =
        serde_json::to_value(report).map_err(|error| execution(path, error.to_string()))?;
    result
        .as_object_mut()
        .expect("property-list reports serialize as JSON objects")
        .insert("provenance".into(), Value::Array(Vec::new()));
    let evidence = ArtifactEvidence::new(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result,
            limitations,
            locations: vec![Location::ArtifactPath {
                path: path.to_owned(),
            }],
        },
    )
    .map_err(|error| execution(path, error.to_string()))?;
    if let Err(error) = json_output::admitted_length(&evidence, plist::MAX_INPUT_BYTES) {
        return Err(match error {
            json_output::Error::Limit { maximum } => resource(path, maximum),
            json_output::Error::Encoding(error) => execution(path, error.to_string()),
        });
    }
    Ok(Arc::new(evidence))
}

fn parse_failure(error: plist::Error, path: &str) -> Failure {
    let mut details = BTreeMap::new();
    details.insert("path", Detail::Text(path.to_owned()));
    details.insert("reason", Detail::Text(error.to_string()));
    Failure::new(
        "parse_failed",
        "analysis_output",
        EXECUTION_MESSAGE.into(),
        false,
        "Inspect the property list with a compatible decoder and retry.".into(),
        details,
    )
}
fn execution(path: &str, reason: String) -> Failure {
    let mut details = BTreeMap::new();
    details.insert("path", Detail::Text(path.to_owned()));
    details.insert("reason", Detail::Text(reason));
    Failure::new(
        "execution_failed",
        "provider_execution",
        EXECUTION_MESSAGE.into(),
        true,
        "Retry after checking the selected input and local environment.".into(),
        details,
    )
}
fn resource(path: &str, maximum: usize) -> Failure {
    let mut details = BTreeMap::new();
    details.insert("path", Detail::Text(path.to_owned()));
    details.insert("maximum_bytes", Detail::Count(maximum as u64));
    Failure::new(
        "resource_limit",
        "resource_limit",
        "Property-list output exceeds the admitted output budget.".into(),
        true,
        "Select a smaller property list or increase the admitted limit.".into(),
        details,
    )
}

fn invalid_input(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        true,
        "Correct the property-list input and retry.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_host::fs::stable_file::Snapshot;

    #[test]
    fn evidence_retains_lossless_projection_and_source_identity() {
        let xml = br#"<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>org.example.App</string><key>CFBundleExecutable</key><string>App</string><key>CFBundleName</key><string>Example</string><key>CFBundleVersion</key><string>42</string><key>CFBundleShortVersionString</key><string>4.2</string><key>Payload</key><array><integer>9007199254740992</integer><real>-0</real><real>nan</real><data>AA==</data><date>bad-date</date></array><key>__proto__</key><string>omit</string></dict></plist>"#;
        let evidence = build_evidence(
            "/tmp/Info.plist",
            Snapshot {
                bytes: xml.to_vec(),
                sha256: "a".repeat(64),
            },
        )
        .unwrap();
        let value = serde_json::to_value(&*evidence).unwrap();
        let result = &value["normalized_result"];
        assert_eq!(result["bundle"]["identifier"], "org.example.App");
        assert_eq!(result["bundle"]["short_version"], "4.2");
        assert_eq!(result["value"]["Payload"][0]["decimal"], "9007199254740992");
        assert_eq!(result["value"]["Payload"][1]["value"], "-0");
        assert_eq!(result["value"]["Payload"][2]["value"], "nan");
        assert_eq!(result["value"]["Payload"][3]["base64"], "AA==");
        assert!(result["value"]["__proto__"].is_null());
        assert_eq!(value["subject"]["local_path"], "/tmp/Info.plist");
        assert_eq!(value["subject"]["format"], "plist");
    }
}
