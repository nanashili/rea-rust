//! Contract boundary for deterministic JavaScript capture comparisons.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "compare_web_captures";

const LIMITATIONS: [&str; 4] = [
    "A changed status proves an observed difference; unknown means absence could not be established from capture completeness.",
    "Network comparison covers activity observed after each CDP attachment; WebSocket connection identities are not stable across captures.",
    "Accessibility is comparable only when its tree and selected text capture are complete.",
    "Storage usage, quota, key inventories, and redacted values are compared only when their retained evidence is complete.",
];

const NORMALIZABLE_SCENARIO_ARTIFACTS: [&str; 7] = [
    "action_state",
    "dom",
    "accessibility",
    "url",
    "history",
    "storage",
    "events",
];

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web capture comparison input must be an object"))?;
    if object.contains_key("before_scenario") || object.contains_key("after_scenario") {
        return validate_scenario_input(object);
    }
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "before" | "after"))
    {
        return Err(invalid(
            "web capture comparison accepts exactly before and after snapshots",
        ));
    }
    for field in ["before", "after"] {
        let snapshot = object
            .get(field)
            .and_then(Value::as_object)
            .ok_or_else(|| invalid(&format!("{field} capture snapshot must be an object")))?;
        if snapshot
            .keys()
            .any(|key| !matches!(key.as_str(), "inspection" | "webmcp"))
        {
            return Err(invalid(&format!(
                "{field} snapshot accepts only inspection and webmcp"
            )));
        }
        snapshot
            .get("inspection")
            .filter(|value| value.is_object())
            .ok_or_else(|| invalid(&format!("{field}.inspection must be an object")))?;
        if let Some(webmcp) = snapshot.get("webmcp") {
            if !webmcp.is_null() && !webmcp.is_object() {
                return Err(invalid(&format!(
                    "{field}.webmcp must be an object or null"
                )));
            }
        }
    }
    Ok(())
}

fn validate_scenario_input(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "before_scenario" | "after_scenario" | "normalization"
        )
    }) {
        return Err(invalid(
            "scenario comparison accepts before_scenario, after_scenario, and normalization",
        ));
    }
    for field in ["before_scenario", "after_scenario"] {
        let capture = object
            .get(field)
            .and_then(Value::as_object)
            .ok_or_else(|| invalid(&format!("{field} must be an object")))?;
        if !capture.get("steps").is_some_and(Value::is_array) {
            return Err(invalid(&format!("{field}.steps must be an array")));
        }
        if !capture.get("browser").is_some_and(Value::is_object)
            || !capture.get("scenario").is_some_and(Value::is_object)
        {
            return Err(invalid(&format!(
                "{field} must include browser and scenario identity"
            )));
        }
    }
    if let Some(normalization) = object.get("normalization") {
        let normalization_object = normalization
            .as_object()
            .ok_or_else(|| invalid("normalization must be an object"))?;
        if normalization_object.keys().any(|key| key != "rules") {
            return Err(invalid("normalization accepts only rules"));
        }
        if let Some(rules) = normalization_object.get("rules") {
            let rules = rules
                .as_array()
                .ok_or_else(|| invalid("normalization.rules must be an array"))?;
            let mut rule_ids = BTreeSet::new();
            for rule in rules {
                let rule_object = rule
                    .as_object()
                    .ok_or_else(|| invalid("each normalization rule must be an object"))?;
                if rule_object.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "rule_id" | "artifacts" | "match" | "replacement"
                    )
                }) {
                    return Err(invalid("normalization rules contain an unknown field"));
                }
                let rule_id = rule_object
                    .get("rule_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| invalid("normalization rule_id must be non-empty"))?;
                if !rule_ids.insert(rule_id.to_owned()) {
                    return Err(invalid("normalization rule IDs must be unique"));
                }
                let artifacts = rule_object
                    .get("artifacts")
                    .and_then(Value::as_array)
                    .filter(|values| !values.is_empty())
                    .ok_or_else(|| invalid("normalization artifacts must be non-empty"))?;
                let mut artifact_names = BTreeSet::new();
                for artifact in artifacts {
                    let name = artifact
                        .as_str()
                        .filter(|name| NORMALIZABLE_SCENARIO_ARTIFACTS.contains(name))
                        .ok_or_else(|| invalid("normalization artifact is not normalizable"))?;
                    if !artifact_names.insert(name) {
                        return Err(invalid("normalization rule artifact kinds must be unique"));
                    }
                }
                if artifacts.is_empty() {
                    return Err(invalid("normalization artifacts must be non-empty"));
                }
                for field in ["match", "replacement"] {
                    if !rule_object
                        .get(field)
                        .and_then(Value::as_str)
                        .is_some_and(|value| field == "replacement" || !value.is_empty())
                    {
                        return Err(invalid(&format!("normalization {field} must be a string")));
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web capture comparison result must be an object"));
    }
    Ok(result)
}

/// Compare two normalized captures using stable identities and explicit
/// completeness.  Missing sections never become false equality.
pub fn compare(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if input.get("before_scenario").is_some() {
        return compare_scenarios(input);
    }
    let before = input["before"]["inspection"]
        .as_object()
        .ok_or_else(|| invalid("before.inspection must be an object"))?;
    let after = input["after"]["inspection"]
        .as_object()
        .ok_or_else(|| invalid("after.inspection must be an object"))?;
    let before_mcp = input["before"].get("webmcp");
    let after_mcp = input["after"].get("webmcp");

    let dimensions = serde_json::json!({
        "dom_structure": compare_dom(before, after),
        "scripts": compare_collection(before, after, "scripts", "script_key", "Script inventory was incomplete in at least one observation."),
        "resources": compare_collection(before, after, "resources", "resource_key", "Resource inventory was incomplete in at least one observation."),
        "network": compare_network(before, after),
        "metadata": compare_value_dimension(before, after, "metadata", "Safe metadata capture was incomplete in at least one observation."),
        "webmcp": compare_webmcp(before_mcp, after_mcp),
        "accessibility": compare_value_dimension(before, after, "accessibility", "Accessibility tree or text capture was incomplete in at least one observation."),
        "storage": compare_value_dimension(before, after, "storage", "Storage fingerprints, inventories, usage, or quota were unavailable or truncated in at least one observation.")
    });
    let overall_status = dimension_statuses(&dimensions);
    Ok(serde_json::json!({
        "overall_status": overall_status,
        "before_target": target_identity(before),
        "after_target": target_identity(after),
        "dimensions": dimensions,
        "limitations": LIMITATIONS,
    }))
}

const BUILT_IN_SCENARIO_RULES: [&str; 9] = [
    "ignore_step_elapsed_ms",
    "ignore_event_sequence",
    "ignore_event_step_index",
    "compare_screenshot_content_digest",
    "compare_normalized_text_content",
    "ignore_capture_local_network_transaction_ids",
    "attribute_network_transactions_to_request_step",
    "compare_network_transactions_as_unordered_collection",
    "preserve_redirect_transaction_ancestry",
];

fn compare_scenarios(input: &Value) -> Result<Value, Failure> {
    let before = input["before_scenario"]
        .as_object()
        .ok_or_else(|| invalid("before_scenario must be an object"))?;
    let after = input["after_scenario"]
        .as_object()
        .ok_or_else(|| invalid("after_scenario must be an object"))?;
    let rules = committed_rules(input.get("normalization"));
    let before_steps = unique_steps(before.get("steps"));
    let after_steps = unique_steps(after.get("steps"));
    let before_ids = step_ids(before.get("steps"));
    let after_ids = step_ids(after.get("steps"));
    let duplicates_before = duplicate_ids(&before_ids);
    let duplicates_after = duplicate_ids(&after_ids);
    let mut failures = alignment_failures(
        &before_ids,
        &after_ids,
        &duplicates_before,
        &duplicates_after,
    );
    if scenario_context(before) != scenario_context(after) {
        failures.push(serde_json::json!({
            "code": "capture_context_mismatch",
            "step_id": null,
            "reason": "Browser product/version or scenario origin scope differs between captures."
        }));
    }

    let ordered_ids: Vec<String> = before_ids
        .iter()
        .filter(|id| !duplicates_before.contains(*id) && after_steps.contains_key(*id))
        .filter(|id| !duplicates_after.contains(*id))
        .cloned()
        .collect();
    let mut steps = Vec::new();
    let mut total_artifact_diffs = 0usize;
    for step_id in ordered_ids {
        let before_step = &before_steps[&step_id];
        let after_step = &after_steps[&step_id];
        if before_step["action"] != after_step["action"] {
            failures.push(serde_json::json!({
                "code": "action_mismatch",
                "step_id": step_id,
                "reason": format!("Aligned step action changed from {} to {}.", before_step["action"], after_step["action"])
            }));
        }
        let artifacts = compare_scenario_artifacts(before, before_step, after, after_step, &rules);
        total_artifact_diffs += artifacts.len();
        let status = if artifacts.iter().any(|diff| diff["status"] == "changed") {
            "changed"
        } else if artifacts.iter().any(|diff| diff["status"] == "unknown") {
            "unknown"
        } else {
            "unchanged"
        };
        steps.push(serde_json::json!({
            "step_id": step_id,
            "before_step_index": before_step["step_index"],
            "after_step_index": after_step["step_index"],
            "before_action": before_step["action"],
            "after_action": after_step["action"],
            "status": status,
            "artifact_diffs": artifacts
        }));
    }
    let alignment_status = if failures.is_empty() {
        "aligned"
    } else if steps.is_empty() {
        "failed"
    } else {
        "partial"
    };
    let equality_eligible = scenario_equality_eligible(before)
        && scenario_equality_eligible(after)
        && alignment_status == "aligned";
    let overall_status = if steps.iter().any(|step| step["status"] == "changed") {
        "changed"
    } else if steps.iter().any(|step| step["status"] == "unknown") || !equality_eligible {
        "unknown"
    } else {
        "unchanged"
    };
    let before_only = before_ids
        .iter()
        .filter(|id| !after_steps.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let after_only = after_ids
        .iter()
        .filter(|id| !before_steps.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let normalization = normalization_result(&rules);
    Ok(serde_json::json!({
        "comparison_kind": "browser_scenario",
        "overall_status": overall_status,
        "normalization": normalization,
        "alignment": {
            "status": alignment_status,
            "aligned_steps": steps.len(),
            "before_only": before_only,
            "after_only": after_only,
            "failures": failures
        },
        "steps": steps,
        "artifact_diffs": {"total": total_artifact_diffs},
        "limitations": [
            "Steps align only by exact unique step_id; missing, duplicate, or action-mismatched steps prevent an unchanged claim.",
            "Only declared literal normalization rules are applied to durable captured fields.",
            "Missing or truncated evidence, incompatible capture context, or alignment failure prevents an unchanged claim."
        ]
    }))
}

fn step_ids(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(|steps| steps.iter())
        .filter_map(|step| {
            step.get("step_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

fn duplicate_ids(ids: &[String]) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for id in ids {
        if !seen.insert(id.clone()) {
            duplicates.insert(id.clone());
        }
    }
    duplicates
}

fn unique_steps(value: Option<&Value>) -> BTreeMap<String, Value> {
    let ids = step_ids(value);
    let duplicates = duplicate_ids(&ids);
    value
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(|steps| steps.iter())
        .filter_map(|step| {
            let id = step.get("step_id").and_then(Value::as_str)?.to_owned();
            if duplicates.contains(&id) {
                None
            } else {
                Some((id, step.clone()))
            }
        })
        .collect()
}

fn alignment_failures(
    before_ids: &[String],
    after_ids: &[String],
    before_duplicates: &BTreeSet<String>,
    after_duplicates: &BTreeSet<String>,
) -> Vec<Value> {
    let mut failures = Vec::new();
    for id in before_duplicates {
        failures.push(serde_json::json!({
            "code": "duplicate_before_step_id",
            "step_id": id,
            "reason": format!("before capture contains duplicate step_id {id}.")
        }));
    }
    for id in after_duplicates {
        failures.push(serde_json::json!({
            "code": "duplicate_after_step_id",
            "step_id": id,
            "reason": format!("after capture contains duplicate step_id {id}.")
        }));
    }
    for id in before_ids.iter().filter(|id| !after_ids.contains(id)) {
        failures.push(serde_json::json!({
            "code": "missing_after_step",
            "step_id": id,
            "reason": format!("Step {id} is missing from the after capture.")
        }));
    }
    for id in after_ids.iter().filter(|id| !before_ids.contains(id)) {
        failures.push(serde_json::json!({
            "code": "missing_before_step",
            "step_id": id,
            "reason": format!("Step {id} is missing from the before capture.")
        }));
    }
    failures
}

fn scenario_context(capture: &serde_json::Map<String, Value>) -> Value {
    serde_json::json!({
        "product": capture["browser"]["product"],
        "version": capture["browser"]["version"],
        "origin": capture["scenario"]["start_origin"]
    })
}

fn scenario_equality_eligible(capture: &serde_json::Map<String, Value>) -> bool {
    capture
        .get("completeness")
        .and_then(|value| value.get("equality_eligible"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn committed_rules(normalization: Option<&Value>) -> Vec<Value> {
    let mut rules = normalization
        .and_then(|value| value.get("rules"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    rules.sort_by(|left, right| {
        left.get("rule_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(
                right
                    .get("rule_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
    });
    rules
}

fn normalization_result(rules: &[Value]) -> Value {
    let commitment = serde_json::json!({
        "built_in_rules": BUILT_IN_SCENARIO_RULES,
        "rules": rules
    });
    serde_json::json!({
        "built_in_rules": BUILT_IN_SCENARIO_RULES,
        "rules": rules,
        "sha256": canonical(&commitment)
    })
}

fn compare_scenario_artifacts(
    before_capture: &serde_json::Map<String, Value>,
    before: &Value,
    after_capture: &serde_json::Map<String, Value>,
    after: &Value,
    rules: &[Value],
) -> Vec<Value> {
    let artifacts = [
        "action_state",
        "screenshot",
        "dom",
        "accessibility",
        "url",
        "history",
        "storage",
    ];
    let mut differences = artifacts
        .iter()
        .filter_map(|artifact| compare_scenario_artifact(before, after, artifact, rules))
        .collect::<Vec<_>>();
    if let Some(events) =
        compare_scenario_events(before_capture, before, after_capture, after, rules)
    {
        differences.push(events);
    }
    differences
}

fn compare_scenario_artifact(
    before: &Value,
    after: &Value,
    artifact: &str,
    rules: &[Value],
) -> Option<Value> {
    let (before_state, before_value) = scenario_artifact_state(before, artifact);
    let (after_state, after_value) = scenario_artifact_state(after, artifact);
    if before_state == "not_requested" && after_state == "not_requested" {
        return None;
    }
    let before_digest = before_value.map(|value| normalized_digest(value, artifact, rules));
    let after_digest = after_value.map(|value| normalized_digest(value, artifact, rules));
    if before_state == "captured" && after_state == "captured" && before_digest == after_digest {
        return None;
    }
    let status = if before_state == "captured" && after_state == "captured" {
        "changed"
    } else {
        "unknown"
    };
    Some(serde_json::json!({
        "artifact": artifact,
        "status": status,
        "before_state": before_state,
        "after_state": after_state,
        "before_sha256": before_digest,
        "after_sha256": after_digest,
        "reason": if status == "unknown" { Some("Artifact evidence was missing, truncated, or not requested on one side.") } else { None }
    }))
}

fn compare_scenario_events(
    before_capture: &serde_json::Map<String, Value>,
    before_step: &Value,
    after_capture: &serde_json::Map<String, Value>,
    after_step: &Value,
    rules: &[Value],
) -> Option<Value> {
    let before_state = scenario_event_state(before_capture, before_step);
    let after_state = scenario_event_state(after_capture, after_step);
    let before_events = scenario_events_for_step(before_capture, before_step, rules);
    let after_events = scenario_events_for_step(after_capture, after_step, rules);
    let before_digest = (before_state == "captured").then(|| canonical(&before_events));
    let after_digest = (after_state == "captured").then(|| canonical(&after_events));

    if before_state == "captured"
        && after_state == "captured"
        && before_digest == after_digest
        && scenario_event_coverage_reason(before_capture, after_capture).is_none()
    {
        return None;
    }

    let coverage_reason = scenario_event_coverage_reason(before_capture, after_capture);
    let comparable =
        before_state == "captured" && after_state == "captured" && coverage_reason.is_none();
    let status = if comparable { "changed" } else { "unknown" };
    Some(serde_json::json!({
        "artifact": "events",
        "status": status,
        "before_state": before_state,
        "after_state": after_state,
        "before_sha256": before_digest,
        "after_sha256": after_digest,
        "reason": if status == "unknown" {
            coverage_reason.or_else(|| Some(format!(
                "Artifact coverage is not comparable ({} before, {} after).",
                before_state, after_state
            )))
        } else {
            None
        }
    }))
}

fn scenario_event_state(capture: &serde_json::Map<String, Value>, step: &Value) -> &'static str {
    let capture_completeness = capture.get("completeness");
    let step_completeness = step.get("completeness");
    let listed = |field: &str, section: &str| {
        [capture_completeness, step_completeness]
            .iter()
            .any(|value| {
                value
                    .and_then(|value| value.get(field))
                    .and_then(Value::as_array)
                    .is_some_and(|sections| {
                        sections.iter().any(|item| item.as_str() == Some(section))
                    })
            })
    };
    let dropped = capture
        .get("events")
        .and_then(|events| events.get("dropped"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if dropped > 0
        || ["events", "frames", "workers", "popups", "websockets"]
            .iter()
            .any(|section| listed("truncated_sections", section))
    {
        "truncated"
    } else if ["events", "frames", "workers", "popups", "websockets"]
        .iter()
        .any(|section| listed("missing_sections", section))
    {
        "missing"
    } else {
        "captured"
    }
}

fn scenario_events_for_step(
    capture: &serde_json::Map<String, Value>,
    step: &Value,
    rules: &[Value],
) -> Value {
    let step_index = step.get("step_index").and_then(Value::as_u64);
    let mut ordinary = Vec::new();
    let mut transactions: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let items = capture
        .get("events")
        .and_then(|events| events.get("items"))
        .and_then(Value::as_array);
    let request_steps = items
        .into_iter()
        .flat_map(|items| items.iter())
        .filter_map(|item| {
            if item.get("kind").and_then(Value::as_str) != Some("request") {
                return None;
            }
            Some((
                item.get("transaction_id")?.as_str()?.to_owned(),
                item.get("step_index")?.as_u64()?,
            ))
        })
        .collect::<BTreeMap<_, _>>();
    if let Some(items) = items {
        for item in items {
            let Some(object) = item.as_object() else {
                continue;
            };
            let transaction_id = object
                .get("transaction_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let item_step = transaction_id
                .as_ref()
                .and_then(|id| request_steps.get(id).copied())
                .or_else(|| object.get("step_index").and_then(Value::as_u64));
            if item_step != step_index {
                continue;
            }
            let mut projected = object.clone();
            projected.remove("sequence");
            projected.remove("step_index");
            if let Some(transaction_id) = transaction_id {
                projected.remove("transaction_id");
                transactions
                    .entry(transaction_id)
                    .or_default()
                    .push(Value::Object(projected));
            } else {
                ordinary.push(normalize_scenario_value(
                    &Value::Object(projected),
                    "events",
                    rules,
                ));
            }
        }
    }
    ordinary.sort_by_key(canonical);
    let network_transactions = transactions
        .into_values()
        .map(|mut events| {
            events.sort_by_key(canonical);
            canonical(&normalize_scenario_value(
                &Value::Array(events),
                "events",
                rules,
            ))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "events": ordinary,
        "network_transactions": network_transactions
    })
}

fn scenario_event_coverage_reason(
    before: &serde_json::Map<String, Value>,
    after: &serde_json::Map<String, Value>,
) -> Option<String> {
    let before_families = scenario_string_set(before, &["scenario", "event_families"]);
    let after_families = scenario_string_set(after, &["scenario", "event_families"]);
    if before_families != after_families {
        return Some(format!(
            "Event family selections differ ({} before, {} after); capture both sides with matching event families before comparing event evidence.",
            family_list(&before_families),
            family_list(&after_families)
        ));
    }
    let before_content = scenario_object(before, &["scenario", "network_content"]);
    let after_content = scenario_object(after, &["scenario", "network_content"]);
    for field in ["request_body", "response_body", "header_values"] {
        if before_content.get(field) != after_content.get(field) {
            return Some("Network content selections differ; capture both sides with matching content selection before comparing network evidence.".into());
        }
    }
    None
}

fn scenario_string_set(object: &serde_json::Map<String, Value>, path: &[&str]) -> BTreeSet<String> {
    let value = scenario_value(object, path);
    value
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn scenario_object(
    object: &serde_json::Map<String, Value>,
    path: &[&str],
) -> serde_json::Map<String, Value> {
    scenario_value(object, path)
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

fn scenario_value(object: &serde_json::Map<String, Value>, path: &[&str]) -> Option<Value> {
    let mut current = Value::Object(object.clone());
    for key in path {
        current = current.get(*key)?.clone();
    }
    Some(current)
}

fn family_list(families: &BTreeSet<String>) -> String {
    if families.is_empty() {
        "none".into()
    } else {
        families.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn scenario_artifact_state<'a>(step: &'a Value, artifact: &str) -> (String, Option<&'a Value>) {
    if artifact == "action_state" {
        return ("captured".into(), Some(step));
    }
    let state = step.get("artifacts").and_then(|value| value.get(artifact));
    let state_name = state
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("missing");
    let value = state.and_then(|value| value.get("value"));
    (state_name.to_owned(), value)
}

fn normalized_digest(value: &Value, artifact: &str, rules: &[Value]) -> String {
    let projected = match artifact {
        "action_state" => serde_json::json!({
            "action": value["action"],
            "status": value["status"],
            "before_url": value["before_url"],
            "after_url": value["after_url"],
            "error": value["error"]
        }),
        "screenshot" => serde_json::json!({
            "sha256": value["sha256"],
            "bytes": value["bytes"],
            "media_type": value["media_type"]
        }),
        "dom" | "accessibility" => value["text"].clone(),
        _ => value.clone(),
    };
    let normalized = if artifact == "screenshot" {
        projected
    } else {
        normalize_scenario_value(&projected, artifact, rules)
    };
    canonical(&normalized)
}

fn normalize_scenario_value(value: &Value, artifact: &str, rules: &[Value]) -> Value {
    match value {
        Value::String(text) => rules
            .iter()
            .filter(|rule| rule_applies(rule, artifact))
            .fold(Value::String(text.clone()), |current, rule| {
                let source = current.as_str().unwrap_or_default();
                let matcher = rule
                    .get("match")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let replacement = rule
                    .get("replacement")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                Value::String(source.replace(matcher, replacement))
            }),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| normalize_scenario_value(value, artifact, rules))
                .collect(),
        ),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        normalize_scenario_value(value, artifact, rules),
                    )
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn rule_applies(rule: &Value, artifact: &str) -> bool {
    rule.get("artifacts")
        .and_then(Value::as_array)
        .map(|artifacts| {
            artifacts
                .iter()
                .any(|value| value.as_str() == Some(artifact))
        })
        .unwrap_or(false)
}

fn compare_dom(
    before: &serde_json::Map<String, Value>,
    after: &serde_json::Map<String, Value>,
) -> Value {
    let nodes_equal = canonical_optional(before.get("dom")) == canonical_optional(after.get("dom"));
    let frames_equal =
        canonical_optional(before.get("frames")) == canonical_optional(after.get("frames"));
    let complete = section_complete(before, "dom")
        && section_complete(after, "dom")
        && section_complete(before, "frames")
        && section_complete(after, "frames");
    let differs = !nodes_equal || !frames_equal;

    if differs && complete {
        changed_dimension(vec![change("document", "modified")])
    } else if differs {
        unknown_dimension(
            "DOM or frame capture was incomplete, or frame ancestry was unresolved in at least one observation.",
        )
    } else if complete {
        unchanged_dimension()
    } else {
        unknown_dimension(
            "DOM or frame capture was incomplete, or frame ancestry was unresolved in at least one observation.",
        )
    }
}

fn compare_collection(
    before: &serde_json::Map<String, Value>,
    after: &serde_json::Map<String, Value>,
    path: &str,
    identity_field: &str,
    reason: &str,
) -> Value {
    let before_values = value_at_path(before, path);
    let after_values = value_at_path(after, path);
    let before_map = keyed_values(before_values, identity_field);
    let after_map = keyed_values(after_values, identity_field);
    let changes = compare_keyed(&before_map, &after_map);
    let section = path.split('.').next().unwrap_or(path);
    let complete = section_complete(before, section) && section_complete(after, section);
    dimension_from_changes(changes, complete, reason)
}

fn compare_network(
    before: &serde_json::Map<String, Value>,
    after: &serde_json::Map<String, Value>,
) -> Value {
    let before_requests = network_requests(before);
    let after_requests = network_requests(after);
    let ambiguous = ambiguous_request_identities(&before_requests, &after_requests);
    let before_http =
        network_request_map(&before_requests, &ambiguous, body_shapes_selected(before));
    let after_http = network_request_map(&after_requests, &ambiguous, body_shapes_selected(after));
    let mut changes = compare_keyed(&before_http, &after_http);

    let before_sockets = websocket_map(before, web_socket_shapes_selected(before));
    let after_sockets = websocket_map(after, web_socket_shapes_selected(after));
    changes.extend(compare_keyed(&before_sockets, &after_sockets));
    changes.sort_by(|left, right| {
        left["identity"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["identity"].as_str().unwrap_or_default())
    });

    let complete = network_complete(before, after, &before_requests, &after_requests, &ambiguous);
    dimension_from_changes(
        changes,
        complete,
        "Network capture or selected HTTP/WebSocket payload coverage was limited, unavailable, incomplete, or included dropped events.",
    )
}

fn network_requests<'a>(inspection: &'a serde_json::Map<String, Value>) -> Vec<&'a Value> {
    inspection
        .get("network")
        .and_then(|value| value.get("requests"))
        .and_then(Value::as_array)
        .map(|values| values.iter().collect())
        .unwrap_or_default()
}

fn request_identity(request: &Value) -> String {
    let object = request.as_object();
    format!(
        "net_{}",
        canonical(&serde_json::json!({
            "method": object.and_then(|value| value.get("method")),
            "url": object.and_then(|value| value.get("url")),
            "resource_type": object.and_then(|value| value.get("resource_type"))
        }))
    )
}

fn request_match_key(request: &Value) -> String {
    let object = request.as_object();
    canonical(&serde_json::json!({
        "method": object.and_then(|value| value.get("method")),
        "url": object.and_then(|value| value.get("url"))
    }))
}

fn ambiguous_request_identities(before: &[&Value], after: &[&Value]) -> BTreeSet<String> {
    let mut groups: BTreeMap<String, bool> = BTreeMap::new();
    for request in before.iter().chain(after.iter()) {
        let Some(object) = request.as_object() else {
            continue;
        };
        let key = request_match_key(request);
        let unknown = object.get("resource_type").is_none_or(Value::is_null);
        let previously_unknown = groups.get(&key).copied().unwrap_or(false);
        groups.insert(key, previously_unknown || unknown);
    }

    before
        .iter()
        .chain(after.iter())
        .filter(|request| {
            groups
                .get(&request_match_key(request))
                .copied()
                .unwrap_or(false)
        })
        .map(|request| request_identity(request))
        .collect()
}

fn network_request_map(
    requests: &[&Value],
    ambiguous: &BTreeSet<String>,
    include_shapes: bool,
) -> BTreeMap<String, String> {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for request in requests {
        let identity = request_identity(request);
        if ambiguous.contains(&identity) {
            continue;
        }
        let Some(object) = request.as_object() else {
            continue;
        };
        let projection = serde_json::json!({
            "method": object.get("method"),
            "url": object.get("url"),
            "resource_type": object.get("resource_type"),
            "status": object.get("status"),
            "mime_type": object.get("mime_type"),
            "encoded_data_length": object.get("encoded_data_length"),
            "redirects": object.get("redirects").map(canonical),
            "request_shape": include_shapes.then(|| object.get("body_shapes").and_then(|value| value.get("request"))),
            "response_shape": include_shapes.then(|| object.get("body_shapes").and_then(|value| value.get("response")))
        });
        grouped
            .entry(identity)
            .or_default()
            .push(canonical(&projection));
    }
    grouped
        .into_iter()
        .map(|(identity, mut values)| {
            values.sort();
            (identity, canonical(&serde_json::json!(values)))
        })
        .collect()
}

fn websocket_map(
    inspection: &serde_json::Map<String, Value>,
    include_shapes: bool,
) -> BTreeMap<String, String> {
    let Some(connections) = inspection
        .get("network")
        .and_then(|value| value.get("websocket_connections"))
        .and_then(Value::as_array)
    else {
        return BTreeMap::new();
    };
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for connection in connections {
        let Some(object) = connection.as_object() else {
            continue;
        };
        let url = object.get("url").cloned().unwrap_or(Value::Null);
        let events = object
            .get("events")
            .and_then(Value::as_array)
            .map(|events| {
                events
                    .iter()
                    .map(|event| {
                        let event_object = event.as_object();
                        serde_json::json!({
                            "direction": event_object.and_then(|value| value.get("direction")),
                            "opcode": event_object.and_then(|value| value.get("opcode")),
                            "payload_bytes": event_object.and_then(|value| value.get("payload_bytes")),
                            "payload_shape": include_shapes.then(|| event_object.and_then(|value| value.get("payload_shape")))
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let stream = canonical(&serde_json::json!({"url": url, "events": events}));
        let group_key = canonical(&url);
        grouped.entry(group_key).or_default().push(stream);
    }
    grouped
        .into_iter()
        .map(|(url, mut streams)| {
            streams.sort();
            (
                format!("ws_{}", url),
                canonical(&serde_json::json!(streams)),
            )
        })
        .collect()
}

fn body_shapes_selected(inspection: &serde_json::Map<String, Value>) -> bool {
    !section_excluded(inspection, "json_body_shapes", "not_approved")
}

fn web_socket_shapes_selected(inspection: &serde_json::Map<String, Value>) -> bool {
    !section_excluded(inspection, "websocket_shapes", "not_approved")
}

fn section_excluded(
    inspection: &serde_json::Map<String, Value>,
    section: &str,
    reason: &str,
) -> bool {
    inspection
        .get("completeness")
        .and_then(|value| value.get("excluded"))
        .and_then(Value::as_array)
        .map(|values| {
            values.iter().any(|value| {
                value.get("section").and_then(Value::as_str) == Some(section)
                    && value.get("reason").and_then(Value::as_str) == Some(reason)
            })
        })
        .unwrap_or(false)
}

fn network_complete(
    before: &serde_json::Map<String, Value>,
    after: &serde_json::Map<String, Value>,
    before_requests: &[&Value],
    after_requests: &[&Value],
    ambiguous: &BTreeSet<String>,
) -> bool {
    let request_sections_complete = [before, after].iter().all(|inspection| {
        section_complete(inspection, "network_requests")
            && inspection
                .get("completeness")
                .and_then(|value| value.get("dropped_events"))
                .and_then(|value| value.get("network_requests"))
                .and_then(Value::as_u64)
                .unwrap_or(0)
                == 0
    });
    let no_unknown_types = before_requests
        .iter()
        .chain(after_requests.iter())
        .all(|request| {
            request
                .get("resource_type")
                .is_some_and(|value| !value.is_null())
        });
    let websocket_complete = [before, after].iter().all(|inspection| {
        section_complete(inspection, "websocket_connections")
            && section_complete(inspection, "websocket_frames")
    });
    let body_shapes_complete = [before, after].iter().all(|inspection| {
        !body_shapes_selected(inspection)
            || (section_complete(inspection, "json_body_shapes")
                && network_requests(inspection).iter().all(|request| {
                    request
                        .get("body_shapes")
                        .and_then(|value| value.get("status"))
                        .and_then(Value::as_str)
                        == Some("included")
                }))
    });
    let websocket_shapes_complete = [before, after].iter().all(|inspection| {
        !web_socket_shapes_selected(inspection)
            || (section_complete(inspection, "websocket_shapes")
                && inspection
                    .get("network")
                    .and_then(|value| value.get("websocket_connections"))
                    .and_then(Value::as_array)
                    .is_some_and(|connections| {
                        connections.iter().all(|connection| {
                            connection
                                .get("events")
                                .and_then(Value::as_array)
                                .is_some_and(|events| {
                                    events.iter().all(|event| {
                                        event
                                            .get("payload_shape")
                                            .is_some_and(|value| !value.is_null())
                                    })
                                })
                        })
                    }))
    });
    let websocket_payload_bytes_complete = [before, after].iter().all(|inspection| {
        inspection
            .get("network")
            .and_then(|value| value.get("websocket_connections"))
            .and_then(Value::as_array)
            .is_some_and(|connections| {
                connections.iter().all(|connection| {
                    connection
                        .get("events")
                        .and_then(Value::as_array)
                        .is_some_and(|events| {
                            events.iter().all(|event| {
                                event
                                    .get("payload_bytes")
                                    .is_some_and(|value| !value.is_null())
                            })
                        })
                })
            })
    });
    request_sections_complete
        && websocket_complete
        && body_shapes_complete
        && websocket_shapes_complete
        && websocket_payload_bytes_complete
        && no_unknown_types
        && ambiguous.is_empty()
}

fn compare_value_dimension(
    before: &serde_json::Map<String, Value>,
    after: &serde_json::Map<String, Value>,
    field: &str,
    reason: &str,
) -> Value {
    let complete = section_complete(before, field) && section_complete(after, field);
    let equal = canonical_optional(before.get(field)) == canonical_optional(after.get(field));
    if !equal && complete {
        changed_dimension(vec![change(field, "modified")])
    } else if !equal {
        unknown_dimension(reason)
    } else if complete {
        unchanged_dimension()
    } else {
        unknown_dimension(reason)
    }
}

fn compare_webmcp(before: Option<&Value>, after: Option<&Value>) -> Value {
    // A pair of explicit nulls (or omitted sections) means WebMCP discovery
    // was not selected on either side. There is no observed surface to
    // compare, but this must not make an independently observed change in
    // another dimension look uncertain.
    if [before, after]
        .iter()
        .all(|value| value.is_none_or(|value| value.is_null()))
    {
        return unchanged_dimension();
    }

    let before_map = before
        .and_then(|value| value.get("tools"))
        .and_then(|value| value.get("items"));
    let after_map = after
        .and_then(|value| value.get("tools"))
        .and_then(|value| value.get("items"));
    let changes = compare_keyed(
        &keyed_values(before_map, "tool_key"),
        &keyed_values(after_map, "tool_key"),
    );
    let complete = [before, after].iter().all(|value| {
        value
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            == Some("available")
    });
    dimension_from_changes(
        changes,
        complete,
        "WebMCP discovery was unavailable or incomplete in at least one capture.",
    )
}

fn keyed_values(value: Option<&Value>, identity_field: &str) -> BTreeMap<String, String> {
    let values = match value {
        Some(Value::Array(values)) => values,
        Some(Value::Object(object)) => object
            .get("items")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice),
        _ => &[],
    };
    values
        .iter()
        .filter_map(|value| {
            let object = value.as_object()?;
            let identity = if identity_field == "network_identity" {
                format!(
                    "{}:{}:{}",
                    object.get("method").and_then(Value::as_str).unwrap_or(""),
                    object.get("url").and_then(Value::as_str).unwrap_or(""),
                    object
                        .get("resource_type")
                        .map(canonical)
                        .unwrap_or_default()
                )
            } else {
                object.get(identity_field).map(canonical)?
            };
            Some((identity, canonical(value)))
        })
        .collect()
}

fn compare_keyed(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<Value> {
    let mut identities = BTreeSet::new();
    identities.extend(before.keys().cloned());
    identities.extend(after.keys().cloned());
    identities
        .into_iter()
        .filter_map(
            |identity| match (before.get(&identity), after.get(&identity)) {
                (None, Some(_)) => Some(change(&identity, "added")),
                (Some(_), None) => Some(change(&identity, "removed")),
                (Some(before), Some(after)) if before != after => {
                    Some(change(&identity, "modified"))
                }
                _ => None,
            },
        )
        .collect()
}

fn dimension_from_changes(changes: Vec<Value>, complete: bool, reason: &str) -> Value {
    if !changes.is_empty() && complete {
        changed_dimension(changes)
    } else if !changes.is_empty() {
        unknown_dimension(reason)
    } else if complete {
        unchanged_dimension()
    } else {
        unknown_dimension(reason)
    }
}

fn changed_dimension(changes: Vec<Value>) -> Value {
    serde_json::json!({"status": "changed", "total_changes": changes.len(), "changes": changes, "reason": null})
}

fn unchanged_dimension() -> Value {
    serde_json::json!({"status": "unchanged", "total_changes": 0, "changes": [], "reason": null})
}

fn unknown_dimension(reason: &str) -> Value {
    serde_json::json!({"status": "unknown", "total_changes": 0, "changes": [], "reason": reason})
}

fn change(identity: &str, kind: &str) -> Value {
    serde_json::json!({"identity": identity, "change": kind})
}

fn dimension_statuses(dimensions: &Value) -> &'static str {
    let statuses: Vec<&Value> = dimensions
        .as_object()
        .into_iter()
        .flat_map(|object| object.values())
        .collect();
    if statuses.iter().any(|value| value["status"] == "changed") {
        "changed"
    } else if statuses.iter().any(|value| value["status"] == "unknown") {
        "unknown"
    } else {
        "unchanged"
    }
}

fn target_identity(inspection: &serde_json::Map<String, Value>) -> Value {
    serde_json::json!({
        "target_id": inspection["target"]["target_id"],
        "url": inspection["target"]["url"]
    })
}

fn value_at_path<'a>(object: &'a serde_json::Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut keys = path.split('.');
    let first_key = keys.next()?;
    let mut current = object.get(first_key)?;

    for key in keys {
        current = current.get(key)?;
    }

    Some(current)
}

fn section_complete(object: &serde_json::Map<String, Value>, section: &str) -> bool {
    if !section_evidence_is_present(object, section) {
        return false;
    }

    let complete = |field: &str| {
        object
            .get("completeness")
            .and_then(|value| value.get(field))
            .and_then(Value::as_array)
            .map(|values| !values.iter().any(|value| value.as_str() == Some(section)))
            .unwrap_or(true)
    };
    complete("policy_filtered_sections")
        && complete("attach_limited_sections")
        && complete("truncated_sections")
        && complete("unavailable_sections")
}

fn section_evidence_is_present(inspection: &serde_json::Map<String, Value>, section: &str) -> bool {
    match section {
        "dom" => inspection.get("dom").is_some_and(Value::is_object),
        "frames" => inspection.get("frames").is_some_and(Value::is_array),
        "scripts" => inspection.get("scripts").is_some_and(Value::is_object),
        "resources" => inspection.get("resources").is_some_and(Value::is_array),
        "network_requests" => inspection
            .get("network")
            .and_then(|network| network.get("requests"))
            .is_some_and(Value::is_array),
        "websocket_connections" => inspection
            .get("network")
            .and_then(|network| network.get("websocket_connections"))
            .is_some_and(Value::is_array),
        "websocket_frames" => inspection
            .get("network")
            .and_then(|network| network.get("websocket_connections"))
            .and_then(Value::as_array)
            .is_some_and(|connections| {
                connections
                    .iter()
                    .all(|connection| connection.get("events").is_some_and(Value::is_array))
            }),
        "metadata" | "accessibility" | "storage" => {
            inspection.get(section).is_some_and(Value::is_object)
        }
        _ => false,
    }
}

fn canonical(value: &Value) -> String {
    let mut output = String::new();
    write_canonical(value, &mut output);
    let mut hasher = Sha256::new();
    hasher.update(output.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn canonical_optional(value: Option<&Value>) -> String {
    value
        .map(canonical)
        .unwrap_or_else(|| canonical(&Value::Null))
}

fn write_canonical(value: &Value, output: &mut String) {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            output.push_str(&serde_json::to_string(value).expect("JSON scalar serialization"));
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical(value, output);
            }
            output.push(']');
        }
        Value::Object(object) => {
            output.push('{');
            for (index, (key, value)) in
                object.iter().collect::<BTreeMap<_, _>>().iter().enumerate()
            {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).expect("JSON key serialization"));
                output.push(':');
                write_canonical(value, output);
            }
            output.push('}');
        }
    }
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide complete before and after browser capture snapshots for deterministic comparison."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "before": {"inspection": {"target": {"target_id": "before"}}},
            "after": {"inspection": {"target": {"target_id": "after"}}}
        })
    }

    fn comparable_input() -> Value {
        let inspection = |target_id: &str, script_hash: &str| {
            serde_json::json!({
                "target": {"target_id": target_id, "url": "https://example.test/"},
                "dom": {"nodes": [], "total_nodes": 0},
                "frames": [],
                "scripts": {"items": [{"script_key": "scr_key", "cdp_hash": script_hash}], "total": 1},
                "resources": [],
                "network": {"requests": [], "websocket_connections": []},
                "metadata": {"responses": [], "dom_urls": [], "agent_hints": []},
                "accessibility": {"nodes": [], "total_nodes": 0},
                "storage": {"local_storage_keys": [], "session_storage_keys": [], "indexed_db_names": [], "cache_names": [], "content_fingerprints": [], "fingerprints_complete": true, "usage_bytes": 0, "quota_bytes": 1},
                "completeness": {"policy_filtered_sections": [], "attach_limited_sections": [], "truncated_sections": [], "unavailable_sections": []}
            })
        };
        serde_json::json!({
            "before": {"inspection": inspection("before", "hash-a"), "webmcp": null},
            "after": {"inspection": inspection("after", "hash-b"), "webmcp": null}
        })
    }

    #[test]
    fn accepts_capture_snapshots() {
        validate_input(&input()).expect("valid capture comparison input");
        assert!(retain_result(&input(), serde_json::json!({"overall_status": "unknown"})).is_ok());
    }

    #[test]
    fn missing_observation_sections_remain_unknown() {
        let result = compare(&input()).expect("partial capture comparison");

        assert_eq!(result["dimensions"]["dom_structure"]["status"], "unknown");
        assert_eq!(result["dimensions"]["scripts"]["status"], "unknown");
        assert_eq!(result["overall_status"], "unknown");
    }

    #[test]
    fn rejects_missing_after_snapshot() {
        let invalid_input = serde_json::json!({
            "before": {"inspection": {}}
        });
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_snapshot_without_inspection() {
        let mut invalid_input = input();
        invalid_input["after"] = serde_json::json!({"webmcp": null});
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_caller_supplied_result_fields() {
        let mut invalid_input = input();
        invalid_input["result"] = serde_json::json!({"overall_status": "unchanged"});
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn compares_script_identity_and_summarizes_overall_change() {
        let result = compare(&comparable_input()).expect("comparison result");
        assert_eq!(result["overall_status"], "changed");
        assert_eq!(result["dimensions"]["scripts"]["status"], "changed");
        assert_eq!(result["dimensions"]["scripts"]["total_changes"], 1);
        assert_eq!(result["dimensions"]["dom_structure"]["status"], "unchanged");
    }

    #[test]
    fn unselected_webmcp_does_not_mask_an_observed_script_change() {
        let mut input = comparable_input();
        input["before"]
            .as_object_mut()
            .expect("before snapshot")
            .remove("webmcp");
        input["after"]
            .as_object_mut()
            .expect("after snapshot")
            .remove("webmcp");

        let result = compare(&input).expect("comparison result");

        assert_eq!(result["dimensions"]["webmcp"]["status"], "unchanged");
        assert_eq!(result["overall_status"], "changed");
    }

    #[test]
    fn public_compare_returns_computed_passive_result() {
        let result = compare(&comparable_input()).expect("computed passive comparison");
        assert!(result.get("dimensions").is_some());
        assert!(result.get("limitations").is_some());
        assert!(result.get("result").is_none());
    }

    #[test]
    fn incomplete_equal_capture_is_unknown() {
        let mut input = comparable_input();
        input["before"]["inspection"]["completeness"]["truncated_sections"] =
            serde_json::json!(["scripts"]);
        let result = compare(&input).expect("comparison result");
        assert_eq!(result["dimensions"]["scripts"]["status"], "unknown");
        assert_eq!(result["overall_status"], "unknown");
    }

    #[test]
    fn incomplete_script_change_is_unknown() {
        let mut input = comparable_input();
        input["before"]["inspection"]["completeness"]["truncated_sections"] =
            serde_json::json!(["scripts"]);

        let result = compare(&input).expect("comparison result");

        assert_eq!(result["dimensions"]["scripts"]["status"], "unknown");
        assert_eq!(result["dimensions"]["scripts"]["total_changes"], 0);
        assert_eq!(result["overall_status"], "unknown");
    }

    #[test]
    fn compares_http_request_metadata_and_body_shapes() {
        let mut input = comparable_input();
        for side in ["before", "after"] {
            input[side]["inspection"]["network"]["requests"] = serde_json::json!([{
                "method": "POST",
                "url": "https://example.test/api",
                "resource_type": "fetch",
                "status": 200,
                "mime_type": "application/json",
                "encoded_data_length": 10,
                "body_shapes": {"request": {"kind": "object"}, "response": {"kind": "object"}}
            }]);
        }
        input["after"]["inspection"]["network"]["requests"][0]["status"] = serde_json::json!(201);
        let result = compare(&input).expect("comparison result");
        assert_eq!(result["dimensions"]["network"]["status"], "changed");
    }

    #[test]
    fn unknown_resource_type_prevents_network_equality_claim() {
        let mut input = comparable_input();
        for side in ["before", "after"] {
            input[side]["inspection"]["network"]["requests"] = serde_json::json!([{
                "method": "GET",
                "url": "https://example.test/api",
                "resource_type": null,
                "status": 200
            }]);
        }
        let result = compare(&input).expect("comparison result");
        assert_eq!(result["dimensions"]["network"]["status"], "unknown");
    }

    #[test]
    fn compares_websocket_connection_streams_as_a_group() {
        let mut input = comparable_input();
        for side in ["before", "after"] {
            input[side]["inspection"]["network"]["websocket_connections"] = serde_json::json!([{
                "url": "wss://example.test/socket",
                "events": [{"direction": "sent", "opcode": 1, "payload_bytes": 3, "payload_shape": {"kind": "text"}}]
            }]);
        }
        input["after"]["inspection"]["network"]["websocket_connections"][0]["events"][0]["payload_bytes"] =
            serde_json::json!(4);
        let result = compare(&input).expect("comparison result");
        assert_eq!(result["dimensions"]["network"]["status"], "changed");
    }

    fn scenario_input(after_url: &str) -> Value {
        let step = serde_json::json!({
            "step_index": 0,
            "step_id": "open",
            "action": "scenario_start",
            "status": "completed",
            "before_url": "https://example.test/",
            "after_url": after_url,
            "error": null,
            "artifacts": {
                "screenshot": {"state": "not_requested"},
                "dom": {"state": "captured", "value": {"text": "hello"}},
                "accessibility": {"state": "not_requested"},
                "url": {"state": "captured", "value": {"url": after_url}},
                "history": {"state": "not_requested"},
                "storage": {"state": "not_requested"}
            },
            "completeness": {"missing_sections": [], "truncated_sections": []}
        });
        serde_json::json!({
            "browser": {"product": "Chromium", "version": "1"},
            "scenario": {"start_origin": "https://example.test"},
            "completeness": {"equality_eligible": true},
            "steps": [step]
        })
    }

    #[test]
    fn compares_aligned_scenarios_and_reports_artifact_change() {
        let before_scenario = scenario_input("https://example.test/");
        let mut after_scenario = scenario_input("https://example.test/");
        after_scenario["steps"][0]["artifacts"]["dom"]["value"]["text"] =
            serde_json::json!("changed");
        let input = serde_json::json!({
            "before_scenario": before_scenario,
            "after_scenario": after_scenario,
            "normalization": {"rules": []}
        });
        let result = compare(&input).expect("scenario comparison result");
        assert_eq!(result["comparison_kind"], "browser_scenario");
        assert_eq!(result["alignment"]["status"], "aligned");
        assert_eq!(result["overall_status"], "changed");
        assert_eq!(result["artifact_diffs"]["total"], 1);
    }

    #[test]
    fn scenario_literal_normalization_preserves_unchanged_claim() {
        let before_scenario = scenario_input("https://example.test/");
        let mut after_scenario = scenario_input("https://example.test/");
        after_scenario["steps"][0]["artifacts"]["url"]["value"]["url"] =
            serde_json::json!("https://example.test/id-2");
        let mut before_scenario = before_scenario;
        before_scenario["steps"][0]["artifacts"]["url"]["value"]["url"] =
            serde_json::json!("https://example.test/id-1");
        let input = serde_json::json!({
            "before_scenario": before_scenario,
            "after_scenario": after_scenario,
            "normalization": {"rules": [{
                "rule_id": "ids",
                "artifacts": ["url"],
                "match": "id-2",
                "replacement": "id-1"
            }]}
        });
        let result = compare(&input).expect("scenario comparison result");
        assert_eq!(result["overall_status"], "unchanged");
        assert_eq!(result["normalization"]["rules"][0]["rule_id"], "ids");
    }

    #[test]
    fn scenario_missing_step_prevents_unchanged_claim() {
        let mut input = serde_json::json!({
            "before_scenario": scenario_input("https://example.test/"),
            "after_scenario": scenario_input("https://example.test/"),
            "normalization": {"rules": []}
        });
        input["after_scenario"]["steps"] = serde_json::json!([]);
        let result = compare(&input).expect("scenario comparison result");
        assert_eq!(result["alignment"]["status"], "failed");
        assert_eq!(result["overall_status"], "unknown");
    }

    #[test]
    fn rejects_duplicate_normalization_rule_ids() {
        let capture = scenario_input("https://example.test/");
        let rule = serde_json::json!({
            "rule_id": "same",
            "artifacts": ["url"],
            "match": "a",
            "replacement": "b"
        });
        let input = serde_json::json!({
            "before_scenario": capture,
            "after_scenario": scenario_input("https://example.test/"),
            "normalization": {"rules": [rule.clone(), rule]}
        });
        assert!(validate_input(&input).is_err());
    }

    #[test]
    fn rejects_duplicate_or_non_normalizable_rule_artifacts() {
        let capture = scenario_input("https://example.test/");
        for artifacts in [
            serde_json::json!(["url", "url"]),
            serde_json::json!(["screenshot"]),
        ] {
            let input = serde_json::json!({
                "before_scenario": capture,
                "after_scenario": scenario_input("https://example.test/"),
                "normalization": {"rules": [{
                    "rule_id": "rule",
                    "artifacts": artifacts,
                    "match": "a",
                    "replacement": "b"
                }]}
            });
            assert!(validate_input(&input).is_err());
        }
    }

    #[test]
    fn projects_only_stable_screenshot_and_text_fields() {
        let mut before = scenario_input("https://example.test/");
        let mut after = scenario_input("https://example.test/");
        for capture in [&mut before, &mut after] {
            capture["steps"][0]["artifacts"]["screenshot"] = serde_json::json!({
                "state": "captured",
                "value": {"sha256": "same", "bytes": 10, "media_type": "image/png", "captured_at": "volatile"}
            });
            capture["steps"][0]["artifacts"]["dom"]["value"] = serde_json::json!({
                "text": "hello",
                "captured_at": "volatile"
            });
        }
        after["steps"][0]["artifacts"]["screenshot"]["value"]["captured_at"] =
            serde_json::json!("different");
        after["steps"][0]["artifacts"]["dom"]["value"]["captured_at"] =
            serde_json::json!("different");
        let result = compare(&serde_json::json!({
            "before_scenario": before,
            "after_scenario": after,
            "normalization": {"rules": []}
        }))
        .expect("scenario comparison result");
        assert_eq!(result["overall_status"], "unchanged");
        assert_eq!(result["artifact_diffs"]["total"], 0);
    }

    #[test]
    fn event_family_selection_mismatch_is_unknown() {
        let mut before = scenario_input("https://example.test/");
        let mut after = scenario_input("https://example.test/");
        before["scenario"]["event_families"] = serde_json::json!(["network"]);
        after["scenario"]["event_families"] = serde_json::json!(["console"]);
        let result = compare(&serde_json::json!({
            "before_scenario": before,
            "after_scenario": after,
            "normalization": {"rules": []}
        }))
        .expect("scenario comparison result");
        assert_eq!(result["overall_status"], "unknown");
        assert_eq!(
            result["steps"][0]["artifact_diffs"][0]["artifact"],
            "events"
        );
        assert_eq!(result["steps"][0]["artifact_diffs"][0]["status"], "unknown");
    }

    #[test]
    fn dropped_events_are_truncated_evidence() {
        let mut before = scenario_input("https://example.test/");
        let after = scenario_input("https://example.test/");
        before["events"] = serde_json::json!({"dropped": 1, "items": []});
        let result = compare(&serde_json::json!({
            "before_scenario": before,
            "after_scenario": after,
            "normalization": {"rules": []}
        }))
        .expect("scenario comparison result");
        assert_eq!(result["overall_status"], "unknown");
        assert_eq!(
            result["steps"][0]["artifact_diffs"][0]["before_state"],
            "truncated"
        );
    }

    #[test]
    fn compares_step_events_after_volatile_fields_are_removed() {
        let mut before = scenario_input("https://example.test/");
        let mut after = scenario_input("https://example.test/");
        before["events"] = serde_json::json!({
            "dropped": 0,
            "items": [{"sequence": 1, "step_index": 0, "kind": "console", "text": "before"}]
        });
        after["events"] = serde_json::json!({
            "dropped": 0,
            "items": [{"sequence": 99, "step_index": 0, "kind": "console", "text": "after"}]
        });
        let result = compare(&serde_json::json!({
            "before_scenario": before,
            "after_scenario": after,
            "normalization": {"rules": []}
        }))
        .expect("scenario comparison result");
        assert_eq!(result["overall_status"], "changed");
        assert_eq!(
            result["steps"][0]["artifact_diffs"][0]["artifact"],
            "events"
        );
        assert_eq!(result["steps"][0]["artifact_diffs"][0]["status"], "changed");
    }

    #[test]
    fn attributes_transaction_events_to_the_request_step() {
        let mut before = scenario_input("https://example.test/");
        let mut after = scenario_input("https://example.test/");
        before["events"] = serde_json::json!({
            "dropped": 0,
            "items": [
                {"sequence": 1, "step_index": 0, "kind": "request", "transaction_id": "local-before", "url": "https://example.test/api"},
                {"sequence": 2, "step_index": 1, "kind": "response", "transaction_id": "local-before", "status": 200}
            ]
        });
        after["events"] = serde_json::json!({
            "dropped": 0,
            "items": [
                {"sequence": 9, "step_index": 0, "kind": "request", "transaction_id": "local-after", "url": "https://example.test/api"},
                {"sequence": 10, "step_index": 7, "kind": "response", "transaction_id": "local-after", "status": 200}
            ]
        });
        let result = compare(&serde_json::json!({
            "before_scenario": before,
            "after_scenario": after,
            "normalization": {"rules": []}
        }))
        .expect("scenario comparison result");
        assert_eq!(result["overall_status"], "unchanged");
        assert_eq!(result["artifact_diffs"]["total"], 0);
    }
}
