//! Comparison of two completed native browser-scenario captures.
//!
//! Capture owns launch, CDP attachment and cleanup. This module consumes only
//! its redacted JSON result and performs deterministic step/artifact comparison.
use super::digest::digest_canonical_value;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const ARTIFACTS: [&str; 8] = [
    "action_state",
    "screenshot",
    "dom",
    "accessibility",
    "url",
    "history",
    "storage",
    "events",
];
const BUILT_IN_RULES: [&str; 9] = [
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

pub(super) fn compare(input: &Value) -> Result<(Value, Value, Vec<String>), AnalysisError> {
    let before = capture(input, "before_scenario")?;
    let after = capture(input, "after_scenario")?;
    let rules = normalization_rules(input);
    let commitment = json!({
        "built_in_rules": BUILT_IN_RULES,
        "rules": rules.clone(),
    });
    let normalization = json!({
        "built_in_rules": BUILT_IN_RULES,
        "rules": rules,
        "sha256": digest_canonical_value(&commitment),
    });
    let alignment = align_steps(before, after);
    let mut steps = Vec::new();
    let mut total = 0usize;
    let mut action_failures = Vec::new();
    for id in &alignment.ordered {
        let left = alignment.before[id];
        let right = alignment.after[id];
        let before_action = string(left, "action");
        let after_action = string(right, "action");
        let mut failures = Vec::new();
        if before_action != after_action {
            let reason =
                format!("Aligned step action changed from {before_action} to {after_action}.");
            failures.push(reason.clone());
            action_failures.push(json!({
                "code": "action_mismatch",
                "step_id": id,
                "reason": reason,
            }));
        }
        let mut diffs = Vec::new();
        for artifact in ARTIFACTS {
            let left_state = evidence_state(before, left, artifact);
            let right_state = evidence_state(after, right, artifact);
            let (left_state, right_state) =
                if artifact == "events" && !event_coverage_matches(before, after) {
                    ("unknown".to_owned(), "unknown".to_owned())
                } else {
                    (left_state, right_state)
                };
            let left_value = artifact_value(before, left, artifact, &rules);
            let right_value = artifact_value(after, right, artifact, &rules);
            if let Some(diff) = compare_artifact(
                left_value,
                right_value,
                left_state,
                right_state,
                artifact,
                &rules,
            ) {
                total += 1;
                diffs.push(diff);
            }
        }
        let status = if diffs.iter().any(|diff| diff["status"] == "changed") {
            "changed"
        } else if diffs.iter().any(|diff| diff["status"] == "unknown") {
            "unknown"
        } else if !failures.is_empty() {
            "unknown"
        } else {
            "unchanged"
        };
        steps.push(json!({
            "step_id": id,
            "before_step_index": number(left, "step_index"),
            "after_step_index": number(right, "step_index"),
            "before_action": before_action,
            "after_action": after_action,
            "status": status,
            "artifact_diffs": diffs,
        }));
    }
    let mut failures = alignment.failures;
    failures.extend(action_failures);
    if !same_context(before, after) {
        failures.push(json!({
            "code": "capture_context_mismatch",
            "step_id": Value::Null,
            "reason": "Browser product/version or scenario origin scope differs between captures.",
        }));
    }
    let alignment_status = if failures.is_empty() {
        "aligned"
    } else if steps.is_empty() {
        "failed"
    } else {
        "partial"
    };
    let overall_status = if steps.iter().any(|step| step["status"] == "changed") {
        "changed"
    } else if alignment_status != "aligned"
        || steps.iter().any(|step| step["status"] == "unknown")
        || !equality_eligible(before)
        || !equality_eligible(after)
    {
        "unknown"
    } else {
        "unchanged"
    };
    let result = json!({
        "comparison_kind": "browser_scenario",
        "overall_status": overall_status,
        "normalization": normalization.clone(),
        "alignment": {
            "status": alignment_status,
            "aligned_steps": steps.len(),
            "before_only": alignment.before_only,
            "after_only": alignment.after_only,
            "failures": failures,
        },
        "steps": steps,
        "artifact_diffs": { "total": total },
        "limitations": [
            "Steps align only by exact, unique step_id; missing, duplicate, or action-mismatched steps are reported and prevent an unchanged claim.",
            "Only declared literal normalization rules are applied, in canonical rule_id order, to already-redacted durable capture fields.",
            "Elapsed time, event sequence/index values and capture-local transaction IDs are excluded as volatile; network transactions are compared as an unordered collection in the step that sent their request; screenshot bytes are compared by content digest.",
            "A changed status proves an observed normalized difference. Missing or truncated evidence, incompatible capture context, or alignment failure prevents an unchanged claim.",
        ],
    });
    let parameters = json!({
        "comparison_kind": "browser_scenario",
        "before_browser": before.get("browser").cloned().unwrap_or(Value::Null),
        "after_browser": after.get("browser").cloned().unwrap_or(Value::Null),
        "before_start_origin": before.pointer("/scenario/start_origin").cloned().unwrap_or(Value::Null),
        "after_start_origin": after.pointer("/scenario/start_origin").cloned().unwrap_or(Value::Null),
        "normalization_sha256": normalization["sha256"].clone(),
    });
    let limitations = result["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    Ok((result, parameters, limitations))
}

fn capture<'a>(input: &'a Value, field: &str) -> Result<&'a Value, AnalysisError> {
    input
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            AnalysisError::input(
                "compare_web_captures",
                vec![InputIssue {
                    path: vec![Value::String(field.to_owned())],
                    reason: "invalid_value",
                    message: Some(
                        "Expected a completed browser scenario capture object.".to_owned(),
                    ),
                    expected: Some(Value::String("object".to_owned())),
                    minimum: None,
                    maximum: None,
                }],
            )
        })
}

struct Alignment<'a> {
    before: BTreeMap<String, &'a Value>,
    after: BTreeMap<String, &'a Value>,
    ordered: Vec<String>,
    before_only: Vec<String>,
    after_only: Vec<String>,
    failures: Vec<Value>,
}

fn align_steps<'a>(before: &'a Value, after: &'a Value) -> Alignment<'a> {
    let left = steps(before);
    let right = steps(after);
    let (before, before_duplicates) = unique_steps(&left);
    let (after, after_duplicates) = unique_steps(&right);
    let before_only = before
        .keys()
        .filter(|id| !after.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let after_only = after
        .keys()
        .filter(|id| !before.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    for id in before_duplicates {
        failures.push(json!({ "code": "duplicate_before_step_id", "step_id": id, "reason": format!("before capture contains duplicate step_id {id}.") }));
    }
    for id in after_duplicates {
        failures.push(json!({ "code": "duplicate_after_step_id", "step_id": id, "reason": format!("after capture contains duplicate step_id {id}.") }));
    }
    for id in &after_only {
        failures.push(json!({ "code": "missing_before_step", "step_id": id, "reason": format!("Step {id} is missing from the before capture.") }));
    }
    for id in &before_only {
        failures.push(json!({ "code": "missing_after_step", "step_id": id, "reason": format!("Step {id} is missing from the after capture.") }));
    }
    let ordered = left
        .iter()
        .map(|step| string(step, "step_id"))
        .filter(|id| before.contains_key(id) && after.contains_key(id))
        .collect();
    Alignment {
        before,
        after,
        ordered,
        before_only,
        after_only,
        failures,
    }
}

fn steps(capture: &Value) -> Vec<&Value> {
    capture["steps"]
        .as_array()
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn unique_steps<'a>(steps: &[&'a Value]) -> (BTreeMap<String, &'a Value>, BTreeSet<String>) {
    let mut map = BTreeMap::new();
    let mut duplicates = BTreeSet::new();
    for step in steps {
        let id = string(step, "step_id");
        if map.insert(id.clone(), *step).is_some() {
            duplicates.insert(id);
        }
    }
    for id in &duplicates {
        map.remove(id);
    }
    (map, duplicates)
}

fn compare_artifact(
    left_value: Value,
    right_value: Value,
    left_state: String,
    right_state: String,
    artifact: &str,
    rules: &[Value],
) -> Option<Value> {
    if left_state == "not_requested" && right_state == "not_requested" {
        return None;
    }
    let left_normalized = normalize(left_value, artifact, rules);
    let right_normalized = normalize(right_value, artifact, rules);
    if left_state == "captured" && right_state == "captured" && left_normalized == right_normalized
    {
        return None;
    }
    Some(json!({
        "artifact": artifact,
        "status": if left_state == "captured" && right_state == "captured" { "changed" } else { "unknown" },
        "before_state": if left_state.is_empty() { "missing".to_owned() } else { left_state.clone() },
        "after_state": if right_state.is_empty() { "missing".to_owned() } else { right_state.clone() },
        "before_sha256": if left_state == "captured" { Value::String(digest_canonical_value(&left_normalized)) } else { Value::Null },
        "after_sha256": if right_state == "captured" { Value::String(digest_canonical_value(&right_normalized)) } else { Value::Null },
            "reason": if left_state == "captured" && right_state == "captured" { Value::Null } else { Value::String(format!("Artifact coverage is not comparable ({} before, {} after).", if left_state.is_empty() { "missing" } else { &left_state }, if right_state.is_empty() { "missing" } else { &right_state })) },
    }))
}

fn artifact_value(capture: &Value, step: &Value, artifact: &str, rules: &[Value]) -> Value {
    match artifact {
        "action_state" => json!({
            "action": string(step, "action"),
            "status": string(step, "status"),
            "before_url": step.get("before_url").cloned().unwrap_or(Value::Null),
            "after_url": step.get("after_url").cloned().unwrap_or(Value::Null),
            "error": step.get("error").cloned().unwrap_or(Value::Null),
        }),
        "events" => scenario_events_for_step(capture, number(step, "step_index"), rules),
        _ => step
            .get("artifacts")
            .and_then(|value| value.get(artifact))
            .and_then(|value| value.get("value"))
            .cloned()
            .unwrap_or(Value::Null),
    }
}

fn evidence_state(capture: &Value, step: &Value, artifact: &str) -> String {
    let original = match artifact {
        "action_state" | "events" => "captured".to_owned(),
        _ => step
            .get("artifacts")
            .and_then(|value| value.get(artifact))
            .map(|value| string(value, "state"))
            .filter(|state| !state.is_empty())
            .unwrap_or_else(|| "missing".to_owned()),
    };
    let section = match artifact {
        "action_state" => "action",
        "events" => "events",
        other => other,
    };
    let completeness = step.get("completeness");
    if artifact == "events"
        && capture
            .get("completeness")
            .and_then(|value| value.get("truncated_sections"))
            .and_then(Value::as_array)
            .is_some_and(|items| {
                ["events", "frames", "workers", "popups", "websockets"]
                    .iter()
                    .any(|section| items.iter().any(|item| item.as_str() == Some(section)))
            })
    {
        return "truncated".to_owned();
    }
    if artifact == "events"
        && capture
            .get("completeness")
            .and_then(|value| value.get("missing_sections"))
            .and_then(Value::as_array)
            .is_some_and(|items| {
                ["events", "frames", "workers", "popups", "websockets"]
                    .iter()
                    .any(|section| items.iter().any(|item| item.as_str() == Some(section)))
            })
    {
        return "missing".to_owned();
    }
    if completeness
        .and_then(|value| value.get("truncated_sections"))
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(section)))
        || (artifact == "events"
            && capture
                .get("events")
                .and_then(|value| value.get("dropped"))
                .and_then(Value::as_u64)
                .is_some_and(|dropped| dropped > 0))
    {
        return "truncated".to_owned();
    }
    if completeness
        .and_then(|value| value.get("missing_sections"))
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(section)))
    {
        return "missing".to_owned();
    }
    original
}

struct NetworkNode {
    events: Vec<Value>,
    predecessor: Option<String>,
    predecessor_state: Option<String>,
    predecessor_conflict: bool,
    step_index: u64,
}

fn scenario_events_for_step(capture: &Value, step_index: u64, rules: &[Value]) -> Value {
    let mut events = Vec::new();
    let Some(items) = capture
        .get("events")
        .and_then(|value| value.get("items"))
        .and_then(Value::as_array)
    else {
        return json!({ "events": events, "network_transactions": [] });
    };
    for event in items {
        if number(event, "step_index") != step_index {
            continue;
        }
        if event.get("transaction_id").is_none() {
            let mut ordinary = event.clone();
            if let Value::Object(map) = &mut ordinary {
                map.remove("sequence");
                map.remove("step_index");
            }
            events.push(ordinary);
        }
    }
    let mut network_transactions = network_fingerprints(items, rules)
        .into_iter()
        .filter(|(node_step, _)| *node_step == step_index)
        .map(|(_, fingerprint)| fingerprint)
        .collect::<Vec<_>>();
    network_transactions.sort();
    events = events
        .into_iter()
        .map(|event| normalize_event(event, rules))
        .collect();
    let ordinary_events_sha256 = digest_canonical_value(&Value::Array(events));
    json!({ "ordinary_events_sha256": ordinary_events_sha256, "network_transactions": network_transactions })
}

fn network_fingerprints(items: &[Value], rules: &[Value]) -> Vec<(u64, String)> {
    let source_steps = items
        .iter()
        .filter_map(|event| Some((number(event, "sequence"), number(event, "step_index"))))
        .collect::<BTreeMap<_, _>>();
    let requests = items
        .iter()
        .filter_map(|event| {
            (string(event, "kind") == "request").then(|| (string(event, "transaction_id"), event))
        })
        .collect::<BTreeMap<_, _>>();
    let mut order = Vec::new();
    let mut nodes = BTreeMap::<String, NetworkNode>::new();

    for event in items {
        let id = string(event, "transaction_id");
        if id.is_empty() {
            continue;
        }
        let request = requests.get(&id).copied();
        let kind = string(event, "kind");
        let receipt_step = if kind == "network-content" {
            source_steps
                .get(&number(event, "source_event_sequence"))
                .copied()
        } else {
            Some(number(event, "step_index"))
        };
        let request_step = request
            .map(|item| number(item, "step_index"))
            .or(receipt_step)
            .unwrap_or_default();
        let predecessor = request
            .map(|item| string_or_null(item, "redirected_from_transaction_id"))
            .or_else(|| Some(string_or_null(event, "redirected_from_transaction_id")))
            .flatten();
        let predecessor_state = request
            .map(|item| string_or_null(item, "redirected_from_transaction_state"))
            .or_else(|| Some(string_or_null(event, "redirected_from_transaction_state")))
            .flatten();
        let mut evidence = event.clone();
        if let Value::Object(map) = &mut evidence {
            map.remove("sequence");
            map.remove("step_index");
            map.remove("transaction_id");
            map.remove("redirected_from_transaction_id");
            map.remove("redirected_from_transaction_state");
            if kind == "network-content" {
                map.remove("source_event_sequence");
            }
        }
        let existing = nodes.get_mut(&id);
        if let Some(node) = existing {
            node.events.push(evidence);
            if kind != "network-content" {
                let parent = string_or_null(event, "redirected_from_transaction_id");
                if parent.is_some()
                    && node.predecessor != parent
                    && (node.predecessor.is_some()
                        || node.predecessor_state.as_deref() == Some("root"))
                {
                    node.predecessor_conflict = true;
                } else if parent.is_some() && node.predecessor.is_none() {
                    node.predecessor = parent;
                    node.predecessor_state =
                        string_or_null(event, "redirected_from_transaction_state");
                } else if parent.is_none()
                    && string(event, "redirected_from_transaction_state") == "root"
                    && node.predecessor.is_some()
                {
                    node.predecessor_conflict = true;
                }
            }
        } else {
            order.push(id.clone());
            nodes.insert(
                id,
                NetworkNode {
                    events: vec![evidence],
                    predecessor,
                    predecessor_state,
                    predecessor_conflict: false,
                    step_index: request_step,
                },
            );
        }
    }

    let mut fingerprints = BTreeMap::<String, String>::new();
    for id in &order {
        fingerprint_node(id, &nodes, rules, &mut fingerprints, &mut BTreeSet::new());
    }
    order
        .into_iter()
        .filter_map(|id| {
            nodes.get(&id).and_then(|node| {
                fingerprints
                    .get(&id)
                    .map(|hash| (node.step_index, hash.clone()))
            })
        })
        .collect()
}

fn fingerprint_node(
    id: &str,
    nodes: &BTreeMap<String, NetworkNode>,
    rules: &[Value],
    fingerprints: &mut BTreeMap<String, String>,
    path: &mut BTreeSet<String>,
) {
    if fingerprints.contains_key(id) {
        return;
    }
    if !path.insert(id.to_owned()) {
        fingerprints.insert(
            id.to_owned(),
            digest_canonical_value(&json!({"events": [], "redirected_from": {"state": "cycle"}})),
        );
        return;
    }
    let Some(node) = nodes.get(id) else {
        path.remove(id);
        return;
    };
    let mut own = node
        .events
        .iter()
        .map(|event| digest_canonical_value(&normalize_event(event.clone(), rules)))
        .collect::<Vec<_>>();
    own.sort();
    let parent = if node.predecessor_conflict {
        json!({"state": "missing"})
    } else if let Some(parent_id) = &node.predecessor {
        if nodes.contains_key(parent_id) {
            fingerprint_node(parent_id, nodes, rules, fingerprints, path);
            fingerprints
                .get(parent_id)
                .cloned()
                .map(Value::String)
                .unwrap_or_else(|| json!({"state":"missing"}))
        } else {
            json!({"state": "missing"})
        }
    } else if node.predecessor_state.as_deref() == Some("root") {
        Value::Null
    } else {
        json!({"state": "missing"})
    };
    fingerprints.insert(
        id.to_owned(),
        digest_canonical_value(&json!({"events": own, "redirected_from": parent})),
    );
    path.remove(id);
}

fn normalize_event(mut value: Value, rules: &[Value]) -> Value {
    for rule in rules {
        if rule["artifacts"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some("events")))
        {
            replace_strings(
                &mut value,
                rule["match"].as_str().unwrap_or_default(),
                rule["replacement"].as_str().unwrap_or_default(),
            );
        }
    }
    value
}

fn string_or_null(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn event_coverage_matches(before: &Value, after: &Value) -> bool {
    let selection_matches = [
        "/scenario/network_content/request_body",
        "/scenario/network_content/response_body",
        "/scenario/network_content/header_values",
    ]
    .iter()
    .all(|path| before.pointer(path) == after.pointer(path));
    let mut before_families = before
        .pointer("/scenario/event_families")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut after_families = after
        .pointer("/scenario/event_families")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    before_families.sort_by_key(|value| value.as_str().unwrap_or_default().to_owned());
    after_families.sort_by_key(|value| value.as_str().unwrap_or_default().to_owned());
    selection_matches && before_families == after_families
}

fn normalize(mut value: Value, artifact: &str, rules: &[Value]) -> Value {
    value = match artifact {
        "screenshot" => project_fields(value, &["sha256", "bytes", "media_type"]),
        "dom" | "accessibility" => project_field(value, "text"),
        "action_state" => {
            if let Value::Object(map) = &mut value {
                map.remove("elapsed_ms");
            }
            value
        }
        "events" => value,
        _ => value,
    };
    for rule in rules {
        if rule["artifacts"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(artifact)))
        {
            replace_strings(
                &mut value,
                rule["match"].as_str().unwrap_or_default(),
                rule["replacement"].as_str().unwrap_or_default(),
            );
        }
    }
    value
}

fn project_field(value: Value, field: &str) -> Value {
    value.get(field).cloned().unwrap_or_else(|| value.clone())
}

fn project_fields(value: Value, fields: &[&str]) -> Value {
    let Value::Object(map) = value else {
        return value;
    };
    let mut projected = serde_json::Map::new();
    for field in fields {
        if let Some(value) = map.get(*field) {
            projected.insert((*field).to_owned(), value.clone());
        }
    }
    Value::Object(projected)
}

fn replace_strings(value: &mut Value, needle: &str, replacement: &str) {
    match value {
        Value::String(text) => *text = text.replace(needle, replacement),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| replace_strings(item, needle, replacement)),
        Value::Object(map) => map
            .values_mut()
            .for_each(|item| replace_strings(item, needle, replacement)),
        _ => {}
    }
}

fn normalization_rules(input: &Value) -> Vec<Value> {
    let mut rules = input
        .pointer("/normalization/rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for rule in &mut rules {
        if let Some(artifacts) = rule.get_mut("artifacts").and_then(Value::as_array_mut) {
            artifacts.sort_by_key(|artifact| artifact.as_str().unwrap_or_default().to_owned());
        }
    }
    rules.sort_by(|left, right| string(left, "rule_id").cmp(&string(right, "rule_id")));
    rules
}

fn same_context(before: &Value, after: &Value) -> bool {
    [
        "/browser/product",
        "/browser/version",
        "/scenario/start_origin",
    ]
    .iter()
    .all(|path| before.pointer(path) == after.pointer(path))
}
fn equality_eligible(capture: &Value) -> bool {
    capture
        .pointer("/completeness/equality_eligible")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
fn number(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}
