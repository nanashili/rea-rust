//! Evidence composition for live Electron CDP observations.
//!
//! The provider result remains the normalized observation. This module adds
//! the stable provider identity, exact request parameters, and Evidence
//! provenance shared by the CLI and MCP adapters.

use crate::{
    electron,
    electron::observation::{self as electron_observation, PageInspection},
};
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

const PROVIDER_ID: &str = "rea-cdp-electron";
const PROVIDER_NAME: &str = "REA Electron file-page CDP observation provider";
const PROVIDER_VERSION: &str = "1";
const TARGET_LIST_PREDICATE: &str = "rea.electron-target-list";
const PAGE_INSPECTION_PREDICATE: &str = "rea.electron-page-inspection";

/// Compose the authenticated Evidence envelope for one target-list result.
pub fn target_list(input: &Value, result: &Value) -> Result<Value, Failure> {
    let endpoint = electron_observation::validate_target_list_input(input)?;
    if !result.is_object() {
        return Err(evidence_failure(
            electron_observation::OPERATION,
            "Electron target-list result must be an object.".into(),
        ));
    }
    let observation_limitations = result
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            evidence_failure(
                electron_observation::OPERATION,
                "Electron target-list result omitted its limitations array.".into(),
            )
        })?
        .iter()
        .map(|limitation| {
            limitation.as_str().map(str::to_owned).ok_or_else(|| {
                evidence_failure(
                    electron_observation::OPERATION,
                    "Electron target-list limitation must be text.".into(),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let parameters = json!({"cdp_endpoint": endpoint});

    create_evidence(
        electron_observation::OPERATION,
        TARGET_LIST_PREDICATE,
        parameters,
        result.clone(),
        Value::Null,
        observation_limitations,
    )
}

/// Compose the authenticated Evidence envelope for one page inspection.
pub fn page_inspection(input: &Value, result: &PageInspection) -> Result<Value, Failure> {
    let request = electron::page_inspection::validate_input(input)?;
    let parameters = json!({
        "cdp_endpoint": request.cdp_endpoint,
        "target_id": request.target_id,
        "observation_ms": request.observation_ms,
        "include_script_sources": request.include_script_sources,
    });
    let normalized_result = serde_json::to_value(result).map_err(|error| {
        evidence_failure(electron::page_inspection::OPERATION, error.to_string())
    })?;
    let environment = json!({
        "id": format!("{}@{}", result.browser.product, result.browser.revision),
        "platform": "unknown",
        "architecture": "unknown",
        "isolation": "none",
    });
    let mut limitations = result.limitations.clone();
    limitations.push("Browser host platform and architecture were not observed.".into());

    create_evidence(
        electron::page_inspection::OPERATION,
        PAGE_INSPECTION_PREDICATE,
        parameters,
        normalized_result,
        environment,
        limitations,
    )
}

fn create_evidence(
    operation: &'static str,
    predicate_type: &'static str,
    parameters: Value,
    normalized_result: Value,
    environment: Value,
    observation_limitations: Vec<String>,
) -> Result<Value, Failure> {
    let mut limitations = vec!["Artifact identity is unavailable for this observation.".to_owned()];
    limitations.extend(observation_limitations);

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
    unsigned.insert("predicate_type".into(), json!(predicate_type));
    unsigned.insert("operation".into(), json!(operation));
    unsigned.insert("parameters".into(), parameters);
    unsigned.insert("raw_result".into(), Value::Null);
    unsigned.insert("normalized_result".into(), normalized_result);
    unsigned.insert("confidence".into(), json!("observed"));
    unsigned.insert("authority".into(), json!("external-service"));
    unsigned.insert("environment".into(), environment);
    unsigned.insert("limitations".into(), json!(limitations));
    unsigned.insert("relationship_coverage".into(), Value::Null);
    unsigned.insert("locations".into(), json!([]));
    unsigned.insert("evidence_links".into(), json!([]));

    let raw = serde_json::value::to_raw_value(&Value::Object(unsigned))
        .map_err(|error| evidence_failure(operation, error.to_string()))?;
    let evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| evidence_failure(operation, error.to_string()))?;
    serde_json::from_str(evidence.raw().get())
        .map_err(|error| evidence_failure(operation, error.to_string()))
}

fn evidence_failure(operation: &'static str, reason: String) -> Failure {
    Failure::new(
        "evidence_integrity_mismatch",
        "integrity_mismatch",
        format!("Unable to authenticate Electron observation Evidence: {reason}"),
        false,
        "Retry the passive observation while preserving the selected endpoint and target.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}
