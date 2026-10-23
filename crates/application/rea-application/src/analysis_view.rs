//! Provider-neutral dispatch for views over complete retained Evidence.
//!
//! Source-specific projectors own admission and selection. This module owns
//! the shared route, view digest, and derived Evidence boundary.

use crate::{
    android, artifacts, artifacts::desktop_application_view, binary, binary::macho_view,
    environment, evm, flutter::dart_aot_view, il2cpp, interface_builder, javascript, managed,
    native, pcap, wasm, web,
};
use rea_core::{
    canonical_json,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";

/// Project a retained view and seal it as Evidence linked to its parent.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(&error.to_string()))?;

    let projection = dispatch_projector(&record, parent, view)?;
    let mut result = extract_view_result(projection, &record)?;
    seal_view_result(&mut result)?;

    create_view_evidence(parent, view, &record, result)
}

enum Projection {
    Evidence(Box<serde_json::value::RawValue>),
    Result(Value),
}

fn dispatch_projector(
    record: &EvidenceRecord,
    parent: &Value,
    view: &Value,
) -> Result<Projection, Failure> {
    let view_kind = view.get("kind").and_then(Value::as_str);

    if record.operation_matches("inspect_pcap_capture") {
        return evidence_projection(pcap::capture_view::project(parent, view));
    }

    if view_kind == Some("api-surface") {
        return evidence_projection(web::network_api_surface_view::project(parent, view));
    }
    if view_kind == Some("environment-manifest") {
        return evidence_projection(environment::manifest_view::project(parent, view));
    }

    if record.operation_matches("inspect_binary_layout") {
        return evidence_projection(binary::layout_view::project(parent, view));
    }
    if record.operation_matches("inspect_desktop_application") {
        return evidence_projection(desktop_application_view::project(parent, view));
    }
    if record.operation_matches("analyze_javascript_application") {
        return javascript::application_view::project(parent, view).map(Projection::Result);
    }
    if record.operation_matches("analyze_function") {
        return evidence_projection(native::function_view::project(parent, view));
    }
    if record.operation_matches("inspect_artifact")
        || record.operation_matches("inventory_artifact")
    {
        return evidence_projection(artifacts::inventory_view::project(parent, view));
    }
    if record.operation_matches("inspect_wasm_artifact") {
        return evidence_projection(wasm::artifact_view::project(parent, view));
    }
    if record.operation_matches("inspect_macho") {
        return evidence_projection(macho_view::project(parent, view));
    }
    if record.operation_matches("decode_interface_builder") {
        return interface_builder::view::project_record(record, parent, view)
            .map(Projection::Evidence);
    }
    if record.operation_matches("inspect_evm_interface") {
        return evidence_projection(evm::view::project(parent, view));
    }
    if record.operation_matches("inspect_managed_artifact") {
        return evidence_projection(managed::artifact_view::project(parent, view));
    }
    if record.operation_matches("inspect_managed_members") {
        return evidence_projection(managed::member_view::project(parent, view));
    }
    if record.operation_matches("inspect_web_network_capture") {
        return evidence_projection(web::network_capture_view::project(parent, view));
    }
    if record.operation_matches("inspect_android_package") {
        return evidence_projection(android::package_view::project(parent, view));
    }
    if record.operation_matches("inspect_dart_aot") {
        return evidence_projection(dart_aot_view::project(parent, view));
    }
    if record.operation_matches("inspect_il2cpp_metadata") {
        return evidence_projection(il2cpp::metadata_view::project(parent, view));
    }
    if record.operation_matches("capture_browser_scenario") {
        return evidence_projection(environment::manifest_view::project(parent, view));
    }

    Err(invalid(
        "No native retained analysis view is available for this Evidence operation.",
    ))
}

fn evidence_projection(
    result: Result<Box<serde_json::value::RawValue>, Failure>,
) -> Result<Projection, Failure> {
    result.map(Projection::Evidence)
}

fn extract_view_result(projection: Projection, parent: &EvidenceRecord) -> Result<Value, Failure> {
    match projection {
        Projection::Result(result) => Ok(result),
        Projection::Evidence(raw) => {
            let record =
                EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;
            if !record.operation_matches(OPERATION) {
                return Err(invalid(
                    "View projector returned Evidence for another operation.",
                ));
            }

            let envelope: Value =
                serde_json::from_str(raw.get()).map_err(|error| invalid(&error.to_string()))?;
            if envelope["parameters"]["parent_evidence_id"].as_str() != Some(parent.evidence_id()) {
                return Err(invalid(
                    "View projector returned Evidence for another parent.",
                ));
            }

            serde_json::from_str(record.normalized_result().get())
                .map_err(|error| invalid(&error.to_string()))
        }
    }
}

fn seal_view_result(result: &mut Value) -> Result<(), Failure> {
    result
        .as_object_mut()
        .ok_or_else(|| invalid("View projector must return an object."))?
        .remove("view_digest");

    let view_digest =
        canonical_json::digest(result).map_err(|error| invalid(&error.to_string()))?;
    result
        .as_object_mut()
        .expect("object existence was checked above")
        .insert("view_digest".into(), json!(view_digest));
    Ok(())
}

fn create_view_evidence(
    parent: &Value,
    view: &Value,
    record: &EvidenceRecord,
    result: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let limitations = result
        .get("limitations")
        .cloned()
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let confidence = projection_confidence(view, &result);
    let locations = projection_locations(view, &result);
    let relationship_coverage = if view.get("kind").and_then(Value::as_str) == Some("native") {
        parent
            .get("relationship_coverage")
            .cloned()
            .filter(|value| !value.is_null())
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };

    let evidence = json!({
        "subject": parent.get("subject").cloned().unwrap_or(Value::Null),
        "provider": {
            "id": "rea-analysis-view",
            "name": "REA analysis view projection",
            "version": "1"
        },
        "analysis_profile": null,
        "predicate_type": "rea.analysis-view",
        "operation": OPERATION,
        "parameters": {
            "parent_evidence_id": record.evidence_id(),
            "view": view
        },
        "raw_result": null,
        "normalized_result": result,
        "confidence": confidence,
        "authority": parent.get("authority").cloned().unwrap_or(json!("analyst-inference")),
        "environment": null,
        "limitations": limitations,
        "relationship_coverage": relationship_coverage,
        "locations": locations,
        "evidence_links": [record.evidence_id()]
    });
    let raw =
        serde_json::value::to_raw_value(&evidence).map_err(|error| invalid(&error.to_string()))?;
    let sealed =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    serde_json::value::RawValue::from_string(sealed.raw().get().to_owned())
        .map_err(|error| invalid(&error.to_string()))
}

fn projection_confidence(view: &Value, result: &Value) -> &'static str {
    let uses_templates = matches!(
        view.get("kind").and_then(Value::as_str),
        Some("api-surface" | "environment-manifest")
    ) && result
        .get("templated_groups")
        .and_then(Value::as_u64)
        .is_some_and(|count| count > 0);

    if uses_templates {
        "inferred"
    } else {
        "derived"
    }
}

fn projection_locations(view: &Value, result: &Value) -> Vec<Value> {
    let mut locations = Vec::new();
    if let Some(path) = result
        .get("artifact")
        .and_then(|artifact| artifact.get("path"))
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    {
        locations.push(json!({"kind":"artifact-path", "path":path}));
    }

    if view.get("kind").and_then(Value::as_str) == Some("native") {
        if let Some(address) = result
            .get("procedure_address")
            .and_then(Value::as_str)
            .filter(|address| !address.is_empty())
        {
            locations.push(json!({"kind":"address", "address":address}));
        }
    }

    locations
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Select compatible retained Evidence and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
