//! Evidence composition for controlled browser scenario captures.
//!
//! The scenario provider owns browser and step observations. This boundary
//! adds the stable provider identity, caller-selected parameters, and
//! controlled-replay provenance without reinterpreting those observations.

use rea_core::{
    canonical_json,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

const PROVIDER_ID: &str = "rea-playwright-browser-scenario";
const PROVIDER_NAME: &str = "REA Playwright browser scenario capture provider";
const PROVIDER_VERSION: &str = "1";
const PREDICATE_TYPE: &str = "rea.browser-scenario-capture";

/// Compose authenticated Evidence for a retained browser scenario capture.
pub fn capture(input: &Value, result: &Value) -> Result<Value, Failure> {
    super::scenario_capture::validate_input(input)?;
    let retained = super::scenario_capture::retain_result(input, result.clone())?;
    let parameters = scenario_parameters(input)?;
    let environment = browser_environment(&retained);
    let limitations = capture_limitations(&retained)?;

    let mut unsigned = Map::new();
    unsigned.insert("subject".into(), Value::Null);
    unsigned.insert(
        "provider".into(),
        json!({
            "id": PROVIDER_ID,
            "name": PROVIDER_NAME,
            "version": PROVIDER_VERSION,
        }),
    );
    unsigned.insert("analysis_profile".into(), Value::Null);
    unsigned.insert("predicate_type".into(), json!(PREDICATE_TYPE));
    unsigned.insert(
        "operation".into(),
        json!(super::scenario_capture::OPERATION),
    );
    unsigned.insert("parameters".into(), parameters);
    unsigned.insert("raw_result".into(), Value::Null);
    unsigned.insert("normalized_result".into(), retained);
    unsigned.insert("confidence".into(), json!("observed"));
    unsigned.insert("authority".into(), json!("controlled-replay"));
    unsigned.insert("environment".into(), environment);
    unsigned.insert("limitations".into(), json!(limitations));
    unsigned.insert("relationship_coverage".into(), Value::Null);
    unsigned.insert("locations".into(), json!([]));
    unsigned.insert("evidence_links".into(), json!([]));

    authenticate(unsigned)
}

fn scenario_parameters(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| evidence_failure("browser scenario input must be an object"))?;
    let mut parameters = object.clone();
    let digest = canonical_json::digest(input)
        .map_err(|error| evidence_failure(&format!("unable to digest scenario: {error}")))?;
    parameters.insert("scenario_sha256".into(), json!(digest));
    Ok(Value::Object(parameters))
}

fn browser_environment(result: &Value) -> Value {
    let browser = result.get("browser").and_then(Value::as_object);
    let product = browser
        .and_then(|value| value.get("product"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let version = browser
        .and_then(|value| value.get("version"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let isolation = if browser
        .and_then(|value| value.get("process_ownership"))
        .and_then(Value::as_str)
        == Some("provider-owned")
    {
        "process"
    } else {
        "none"
    };

    json!({
        "id": format!("{product}@{version}"),
        "platform": "unknown",
        "architecture": "unknown",
        "isolation": isolation,
    })
}

fn capture_limitations(result: &Value) -> Result<Vec<String>, Failure> {
    let limitations = result
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(|| evidence_failure("browser scenario capture omitted limitations"))?;
    let mut output = Vec::with_capacity(limitations.len() + 2);
    output.push("Artifact identity is unavailable for this observation.".into());
    for limitation in limitations {
        let text = limitation
            .as_str()
            .ok_or_else(|| evidence_failure("browser scenario limitation must be text"))?;
        output.push(text.to_owned());
    }
    output.push("Browser host platform and architecture were not observed.".into());
    Ok(output)
}

fn authenticate(unsigned: Map<String, Value>) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(&Value::Object(unsigned))
        .map_err(|error| evidence_failure(&error.to_string()))?;
    let evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| evidence_failure(&error.to_string()))?;
    serde_json::from_str(evidence.raw().get()).map_err(|error| evidence_failure(&error.to_string()))
}

fn evidence_failure(reason: &str) -> Failure {
    Failure::new(
        "evidence_integrity_mismatch",
        "integrity_mismatch",
        format!("Unable to authenticate browser scenario Evidence: {reason}"),
        false,
        "Retry the browser scenario while preserving the selected browser and scenario inputs."
            .into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(super::scenario_capture::OPERATION.into()),
        )]),
    )
}
