//! Deterministic comparison of two retained `analyze_function` Evidence records.
//!
//! The adapter supplies complete, authenticated Evidence.  This module only
//! projects the retained dossier into comparable facts; it never executes a
//! target or resolves a function by fuzzy matching.

use rea_core::{
    canonical_json,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "compare_functions";

/// Compare two caller-selected function dossiers.
pub fn compare(input: &Value) -> Result<Value, Failure> {
    let left = Side::parse(
        input
            .get("left")
            .ok_or_else(|| invalid("left Evidence is required"))?,
        "left",
    )?;
    let right = Side::parse(
        input
            .get("right")
            .ok_or_else(|| invalid("right Evidence is required"))?,
        "right",
    )?;
    if left.evidence_id == right.evidence_id {
        return Err(invalid("left and right Evidence must be distinct"));
    }

    let links = vec![json!(left.evidence_id), json!(right.evidence_id)];
    let providers_differ = canonical(&left.provider) != canonical(&right.provider);
    let dimensions = compare_dimensions(&left, &right, &links, providers_differ);
    let function_match = function_match(&left, &right);
    let changes: Vec<Value> = dimensions
        .iter()
        .filter(|dimension| dimension["status"] != "unchanged")
        .cloned()
        .collect();
    let status = overall_status(
        &dimensions,
        function_match["status"].as_str().unwrap_or("ambiguous"),
    );
    let summary = json!({
        "unchanged": dimensions.iter().filter(|item| item["status"] == "unchanged").count(),
        "changed": dimensions.iter().filter(|item| item["status"] == "changed").count(),
        "unknown": dimensions.iter().filter(|item| item["status"] == "unknown").count(),
    });
    let mut limitations = left
        .limitations
        .iter()
        .map(|value| format!("Left: {value}"))
        .collect::<Vec<_>>();
    limitations.extend(
        right
            .limitations
            .iter()
            .map(|value| format!("Right: {value}")),
    );
    if providers_differ {
        limitations.push(
            "Provider-specific pseudocode and assembly representations were not equated.".into(),
        );
    }
    limitations.sort();
    limitations.dedup();

    let semantic = json!({
        "status": status,
        "function_match": function_match,
        "left_subject_sha256": left.subject_digest,
        "right_subject_sha256": right.subject_digest,
        "summary": summary,
        "dimensions": dimensions,
        "changes": changes,
        "limitations": limitations,
    });
    Ok(semantic)
}

#[derive(Clone)]
struct Side {
    evidence_id: String,
    subject_digest: Value,
    provider: Value,
    dossier: Value,
    limitations: Vec<String>,
    relationship_coverage: Option<Value>,
}

impl Side {
    fn parse(value: &Value, label: &str) -> Result<Self, Failure> {
        if value.get("operation").and_then(Value::as_str) != Some("analyze_function") {
            return Err(invalid(&format!(
                "{label} Evidence operation must be analyze_function"
            )));
        }
        let evidence_id = value
            .get("evidence_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| invalid(&format!("{label} Evidence must include evidence_id")))?;
        let subject = value
            .get("subject")
            .filter(|item| !item.is_null())
            .ok_or_else(|| invalid("Function comparison requires artifact-bound Evidence"))?;
        let subject_digest = subject
            .pointer("/digest/sha256")
            .cloned()
            .or_else(|| subject.get("sha256").cloned())
            .ok_or_else(|| invalid("Function Evidence subject must include a SHA-256 digest"))?;
        let result = value
            .get("normalized_result")
            .or_else(|| value.get("result"))
            .ok_or_else(|| invalid("Function Evidence must include normalized_result"))?
            .clone();
        let dossier = result.get("dossier").unwrap_or(&result).clone();
        if dossier
            .get("procedure")
            .and_then(Value::as_object)
            .is_none()
        {
            return Err(invalid("Function Evidence dossier must include procedure"));
        }
        let mut limitations = strings(value.get("limitations"));
        limitations.extend(strings(dossier.get("limitations")));
        limitations.sort();
        limitations.dedup();
        Ok(Self {
            evidence_id: evidence_id.into(),
            subject_digest,
            provider: value.get("provider").cloned().unwrap_or(Value::Null),
            dossier,
            limitations,
            relationship_coverage: value
                .get("relationship_coverage")
                .cloned()
                .filter(|item| !item.is_null()),
        })
    }
}

fn compare_dimensions(
    left: &Side,
    right: &Side,
    links: &[Value],
    providers_differ: bool,
) -> Vec<Value> {
    let dimensions = vec![
        compare_identity(left, right, links, providers_differ),
        compare_text(
            "pseudocode",
            field_string(&left.dossier, "/pseudocode"),
            field_string(&right.dossier, "/pseudocode"),
            links,
            providers_differ,
        ),
        compare_text(
            "assembly",
            lines(&left.dossier, "assembly"),
            lines(&right.dossier, "assembly"),
            links,
            providers_differ,
        ),
        compare_comments(left, right, links),
        compare_calls(left, right, links, providers_differ),
        compare_projection(
            "references",
            references(&left.dossier, left.subject_digest == right.subject_digest),
            references(&right.dossier, left.subject_digest == right.subject_digest),
            links,
            providers_differ,
            "Reference endpoint identity is incomplete or ambiguous.",
        ),
        compare_strings_names(left, right, links, providers_differ),
        compare_cfg(left, right, links, providers_differ),
    ];

    dimensions
        .into_iter()
        .map(|dimension| apply_facet_limitations(dimension, left, right, links))
        .collect()
}

/// Empty undeclared facets are not evidence of observed absence. Apply this
/// admission rule uniformly after each owner has normalized its facts.
fn apply_facet_limitations(dimension: Value, left: &Side, right: &Side, links: &[Value]) -> Value {
    let Some(name) = dimension.get("dimension").and_then(Value::as_str) else {
        return dimension;
    };
    let mut limitations = facet_limitations(&left.dossier, name)
        .into_iter()
        .map(|reason| format!("Left: {reason}"))
        .collect::<Vec<_>>();
    limitations.extend(
        facet_limitations(&right.dossier, name)
            .into_iter()
            .map(|reason| format!("Right: {reason}")),
    );
    if limitations.is_empty() {
        return dimension;
    }

    let mut existing = dimension
        .get("limitations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    existing.extend(limitations);
    existing.sort();
    existing.dedup();
    unknown_with_values(name, links, existing, Value::Null, Value::Null)
}

fn facet_limitations(dossier: &Value, dimension: &str) -> Vec<String> {
    let fields: Vec<(&str, usize)> = match dimension {
        "identity" => Vec::new(),
        "pseudocode" => vec![("pseudocode", value_count(dossier, "pseudocode"))],
        "assembly" => vec![("assembly", array_count(dossier, "assembly"))],
        "comments" => vec![("comments", array_count(dossier, "comments"))],
        "calls" => vec![
            ("callers", array_count(dossier, "callers")),
            ("callees", array_count(dossier, "callees")),
        ],
        "references" => vec![(
            "references",
            array_count(dossier, "incoming_references")
                .saturating_add(array_count(dossier, "outgoing_references")),
        )],
        "strings_names" => vec![(
            "strings_names",
            array_count(dossier, "referenced_strings")
                .saturating_add(array_count(dossier, "referenced_names")),
        )],
        "cfg" => vec![("cfg", array_count(dossier, "basic_blocks"))],
        _ => Vec::new(),
    };

    fields
        .into_iter()
        .filter_map(|(field, count)| {
            let availability = dossier
                .get("facet_availability")
                .and_then(|value| value.get(field));
            if availability
                .and_then(|value| value.get("available"))
                .and_then(Value::as_bool)
                == Some(false)
            {
                return Some(format!(
                    "{field}: {}",
                    availability
                        .and_then(|value| value.get("reason"))
                        .and_then(Value::as_str)
                        .unwrap_or("provider marked this facet unavailable")
                ));
            }
            if availability.is_none() && count == 0 {
                return Some(format!(
                    "{field}: Provider did not declare coverage for this empty facet."
                ));
            }
            None
        })
        .collect()
}

fn array_count(dossier: &Value, field: &str) -> usize {
    dossier
        .get(field)
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn value_count(dossier: &Value, field: &str) -> usize {
    dossier
        .get(field)
        .and_then(Value::as_str)
        .map_or(0, |value| value.chars().count())
}

fn compare_identity(left: &Side, right: &Side, links: &[Value], providers_differ: bool) -> Value {
    let left_name = procedure_name(&left.dossier);
    let right_name = procedure_name(&right.dossier);
    if is_auto_name(&left_name) || is_auto_name(&right_name) {
        return unknown(
            "identity",
            links,
            "Address-derived function names are not stable cross-version identity.",
            null_count(),
        );
    }
    compare_projection(
        "identity",
        identity(&left.dossier),
        identity(&right.dossier),
        links,
        providers_differ,
        "",
    )
}

fn compare_comments(left: &Side, right: &Side, links: &[Value]) -> Value {
    let left_values = comments(&left.dossier);
    let right_values = comments(&right.dossier);
    if left_values.is_none() || right_values.is_none() {
        return unknown_with_counts(
            "comments",
            links,
            vec!["Comment locations could not be normalized relative to the function.".into()],
            left.dossier
                .get("comments")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            right
                .dossier
                .get("comments")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
        );
    }
    compare_projection(
        "comments",
        left_values.unwrap_or(Value::Null),
        right_values.unwrap_or(Value::Null),
        links,
        false,
        "",
    )
}

fn compare_text(
    name: &str,
    left: String,
    right: String,
    links: &[Value],
    providers_differ: bool,
) -> Value {
    let mut limits = vec!["Exact provider text is compared without address or generated-name normalization; layout-only differences do not establish a behavior change.".to_string()];
    if name == "assembly" {
        limits.push(
            "Assembly is opaque provider text; relocation normalization is unavailable.".into(),
        );
    }
    if providers_differ {
        limits.push("Exact text comparison requires one provider identity.".into());
        return unknown_with_counts(
            name,
            links,
            limits,
            left.chars().count(),
            right.chars().count(),
        );
    }
    let Some(delta) = line_delta(&left, &right) else {
        return unknown_with_counts(
            name,
            links,
            vec![
                limits,
                vec!["Bounded line diff exceeded its time or edit-distance limit.".into()],
            ]
            .into_iter()
            .flatten()
            .collect(),
            left.chars().count(),
            right.chars().count(),
        );
    };
    let changed = delta["hunks"].as_u64().unwrap_or(0) != 0;
    dimension(
        name,
        if changed { "changed" } else { "unchanged" },
        json!(left.chars().count()),
        json!(right.chars().count()),
        links,
        limits,
        digest_value(&left),
        digest_value(&right),
        delta,
        providers_differ,
    )
}

/// Compute a bounded line delta with the same observable fields as the
/// TypeScript diff. Large inputs remain unresolved instead of allocating an
/// unbounded edit matrix.
fn line_delta(left: &str, right: &str) -> Option<Value> {
    let left_lines = left.lines().collect::<Vec<_>>();
    let right_lines = right.lines().collect::<Vec<_>>();
    let cells = left_lines.len().checked_mul(right_lines.len())?;
    if cells > 1_000_000 {
        return None;
    }
    let width = right_lines.len() + 1;
    let mut table = vec![0usize; (left_lines.len() + 1) * width];
    for (left_index, left_line) in left_lines.iter().enumerate() {
        for (right_index, right_line) in right_lines.iter().enumerate() {
            let index = (left_index + 1) * width + right_index + 1;
            table[index] = if left_line == right_line {
                table[left_index * width + right_index] + 1
            } else {
                table[left_index * width + right_index + 1]
                    .max(table[(left_index + 1) * width + right_index])
            };
        }
    }
    let lcs = table[left_lines.len() * width + right_lines.len()];
    let mut left_index = left_lines.len();
    let mut right_index = right_lines.len();
    let mut hunks = 0usize;
    let mut in_hunk = false;
    while left_index > 0 || right_index > 0 {
        if left_index > 0
            && right_index > 0
            && left_lines[left_index - 1] == right_lines[right_index - 1]
        {
            in_hunk = false;
            left_index -= 1;
            right_index -= 1;
            continue;
        }
        if !in_hunk {
            hunks += 1;
            in_hunk = true;
        }
        let left_score = if left_index > 0 {
            table[(left_index - 1) * width + right_index]
        } else {
            0
        };
        let right_score = if right_index > 0 {
            table[left_index * width + right_index - 1]
        } else {
            0
        };
        if left_score >= right_score && left_index > 0 {
            left_index -= 1;
        } else if right_index > 0 {
            right_index -= 1;
        } else {
            break;
        }
    }
    Some(json!({
        "added_lines": right_lines.len() - lcs,
        "removed_lines": left_lines.len() - lcs,
        "hunks": hunks,
    }))
}

fn compare_calls(left: &Side, right: &Side, links: &[Value], providers_differ: bool) -> Value {
    let left_values = calls(&left.dossier);
    let right_values = calls(&right.dossier);
    let mut limits = coverage_limits(&left.dossier, &["callers", "callees"]);
    limits.extend(coverage_limits(&right.dossier, &["callers", "callees"]));
    limits.extend(relationship_limitations(
        left.relationship_coverage.as_ref(),
    ));
    limits.extend(relationship_limitations(
        right.relationship_coverage.as_ref(),
    ));
    limits.extend(unresolved_call_limitations(&left.dossier));
    limits.extend(unresolved_call_limitations(&right.dossier));
    if left_values
        .iter()
        .chain(right_values.iter())
        .any(|item| is_auto_name(item["name"].as_str().unwrap_or("")))
    {
        limits.push("Address-derived callee or caller names cannot be matched safely.".into());
    }
    let mut diagnostics = relationship_diagnostics(left.relationship_coverage.as_ref());
    diagnostics.extend(relationship_diagnostics(
        right.relationship_coverage.as_ref(),
    ));
    diagnostics.sort();
    diagnostics.dedup();
    if !limits.is_empty() {
        limits.extend(diagnostics);
        return unknown_with_counts(
            "calls",
            links,
            limits,
            left_values.len(),
            right_values.len(),
        );
    }
    let mut result = compare_projection(
        "calls",
        sorted(left_values),
        sorted(right_values),
        links,
        providers_differ,
        "",
    );
    if !diagnostics.is_empty() {
        result["limitations"] = json!(diagnostics);
    }
    result
}

fn relationship_diagnostics(coverage: Option<&Value>) -> Vec<String> {
    coverage
        .and_then(|value| value.get("diagnostics"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn relationship_limitations(coverage: Option<&Value>) -> Vec<String> {
    let Some(coverage) = coverage else {
        return vec!["Provider did not report relationship coverage.".into()];
    };
    match coverage.get("status").and_then(Value::as_str) {
        Some("complete") => Vec::new(),
        Some("partial") => coverage
            .get("limitations")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_else(|| vec!["Provider reported partial relationship coverage.".into()]),
        Some("unknown") => coverage
            .get("reason")
            .and_then(Value::as_str)
            .map(|reason| vec![reason.to_owned()])
            .unwrap_or_else(|| vec!["Provider reported unknown relationship coverage.".into()]),
        _ => vec!["Provider reported invalid relationship coverage.".into()],
    }
}

fn unresolved_call_limitations(dossier: &Value) -> Vec<String> {
    dossier
        .get("unresolved_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|call| {
            let address = call
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or("unknown address");
            let reason = call
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unknown reason");
            format!("Unresolved call at {address}: {reason}")
        })
        .collect()
}

fn compare_strings_names(
    left: &Side,
    right: &Side,
    links: &[Value],
    providers_differ: bool,
) -> Value {
    let left_values = strings_names(&left.dossier, true);
    let right_values = strings_names(&right.dossier, true);
    if left_values.is_none() || right_values.is_none() {
        let count = |dossier: &Value| {
            [
                "referenced_strings",
                "referenced_names",
                "swift_string_literals",
            ]
            .into_iter()
            .map(|key| {
                dossier
                    .get(key)
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len)
            })
            .sum()
        };
        return unknown_with_counts(
            "strings_names",
            links,
            vec!["Reference source locations could not be normalized to function offsets.".into()],
            count(&left.dossier),
            count(&right.dossier),
        );
    }
    let mut result = compare_projection(
        "strings_names",
        left_values.unwrap_or(Value::Null),
        right_values.unwrap_or(Value::Null),
        links,
        providers_differ,
        "",
    );
    if swift_partial(&left.dossier) || swift_partial(&right.dossier) {
        result = unknown(
            "strings_names",
            links,
            "Swift String literal coverage differs or is partial; referenced strings and names match, and complete coverage does not establish a differing literal.",
            null_count(),
        );
    }
    result
}

fn compare_cfg(left: &Side, right: &Side, links: &[Value], providers_differ: bool) -> Value {
    let Some(left_graph) = cfg(&left.dossier) else {
        return unknown(
            "cfg",
            links,
            "CFG addresses could not be normalized to local block indices.",
            null_count(),
        );
    };
    let Some(right_graph) = cfg(&right.dossier) else {
        return unknown(
            "cfg",
            links,
            "CFG addresses could not be normalized to local block indices.",
            null_count(),
        );
    };
    compare_projection("cfg", left_graph, right_graph, links, providers_differ, "")
}

fn compare_projection(
    name: &str,
    left: Value,
    right: Value,
    links: &[Value],
    providers_differ: bool,
    limitation: &str,
) -> Value {
    if !limitation.is_empty() {
        return unknown(name, links, limitation, null_count());
    }
    // Provider identity only makes exact provider text incomparable.  Comments,
    // calls, references, strings, and CFG facts remain comparable after their
    // owning projections normalize addresses and names.
    let status = if canonical(&left) == canonical(&right) {
        "unchanged"
    } else {
        "changed"
    };
    let left_count = left
        .as_array()
        .map_or(Value::Null, |items| json!(items.len()));
    let right_count = right
        .as_array()
        .map_or(Value::Null, |items| json!(items.len()));
    dimension(
        name,
        status,
        left_count,
        right_count,
        links,
        Vec::new(),
        digest_value(&left),
        digest_value(&right),
        Value::Null,
        providers_differ,
    )
}

fn dimension(
    name: &str,
    status: &str,
    left_count: Value,
    right_count: Value,
    links: &[Value],
    limitations: Vec<String>,
    left_digest: Value,
    right_digest: Value,
    text_delta: Value,
    providers_differ: bool,
) -> Value {
    json!({"dimension":name,"status":status,"left_digest":left_digest,"right_digest":right_digest,"left_count":left_count,"right_count":right_count,"text_delta":text_delta,"conclusion_kind":if status == "changed" && providers_differ {"contradiction"} else {"derived_relationship"},"evidence_links":links,"limitations":limitations})
}

fn unknown(name: &str, links: &[Value], limitation: &str, counts: (Value, Value)) -> Value {
    unknown_with_values(name, links, vec![limitation.into()], counts.0, counts.1)
}
fn unknown_with_counts(
    name: &str,
    links: &[Value],
    limitations: Vec<String>,
    left_count: usize,
    right_count: usize,
) -> Value {
    json!({"dimension":name,"status":"unknown","left_digest":null,"right_digest":null,"left_count":left_count,"right_count":right_count,"text_delta":null,"conclusion_kind":"unresolved_branch","evidence_links":links,"limitations":limitations})
}
fn unknown_with_values(
    name: &str,
    links: &[Value],
    limitations: Vec<String>,
    left_count: Value,
    right_count: Value,
) -> Value {
    json!({"dimension":name,"status":"unknown","left_digest":null,"right_digest":null,"left_count":left_count,"right_count":right_count,"text_delta":null,"conclusion_kind":"unresolved_branch","evidence_links":links,"limitations":limitations})
}
fn null_count() -> (Value, Value) {
    (Value::Null, Value::Null)
}

fn function_match(left: &Side, right: &Side) -> Value {
    let l = procedure_name(&left.dossier);
    let r = procedure_name(&right.dossier);
    let stable = !is_auto_name(&l) && !is_auto_name(&r);
    json!({"status":if stable && l == r {"matched"} else if stable {"mismatched"} else {"ambiguous"},"method":if stable && l == r {"symbol"} else {"explicit"},"left_name":l,"right_name":r})
}

fn overall_status(dimensions: &[Value], matching: &str) -> &'static str {
    if matching == "mismatched" {
        "changed"
    } else if matching == "ambiguous" {
        "unknown"
    } else if dimensions.iter().any(|item| item["status"] == "changed") {
        "changed"
    } else if dimensions.iter().any(|item| item["status"] == "unknown") {
        "unknown"
    } else {
        "unchanged"
    }
}
fn procedure_name(dossier: &Value) -> String {
    dossier
        .pointer("/procedure/name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .into()
}
fn identity(dossier: &Value) -> Value {
    let locals = dossier
        .pointer("/procedure/locals")
        .and_then(Value::as_array)
        .map(|items| {
            let mut descriptions = items
                .iter()
                .filter_map(|item| item.get("description").and_then(Value::as_str))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            descriptions.sort();
            descriptions
        })
        .unwrap_or_default();
    json!({"name":procedure_name(dossier),"signature":dossier.pointer("/procedure/signature").cloned().unwrap_or(Value::Null),"locals":locals})
}
fn field_string(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or("")
        .into()
}
fn lines(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}
fn calls(value: &Value) -> Vec<Value> {
    ["callers", "callees"].into_iter().flat_map(|key| value.get(key).and_then(Value::as_array).into_iter().flatten().map(move |item| json!({"direction":if key == "callers" {"in"} else {"out"},"name":item.get("name").cloned().unwrap_or(Value::Null)}))).collect()
}
fn comments(value: &Value) -> Option<Value> {
    let base = value.pointer("/procedure/address").and_then(Value::as_str);
    let values = value
        .get("comments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut rows = Vec::with_capacity(values.len());
    for item in values {
        let offset = relative_offset(item.get("address"), base)?;
        rows.push(json!({"offset": offset, "kind": item.get("kind"), "text": item.get("text")}));
    }
    Some(sorted(rows))
}
fn strings_names(value: &Value, swift: bool) -> Option<Value> {
    let base = value.pointer("/procedure/address").and_then(Value::as_str);
    let mut rows = Vec::new();
    for (key, kind) in [
        ("referenced_strings", "string"),
        ("referenced_names", "name"),
    ] {
        for item in value
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            rows.push(json!({"kind": kind, "source_offset": relative_offset(item.get("source_address"), base)?, "value": item.get("value")}));
        }
    }
    if swift {
        for item in value
            .get("swift_string_literals")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            rows.push(json!({"kind":"swift_string", "source_offset": relative_offset(item.get("source_address"), base)?, "value":item.get("value"), "representation":item.get("representation"), "registers":item.get("registers")}));
        }
    }
    Some(sorted(rows))
}
fn references(value: &Value, same_artifact: bool) -> Value {
    let mut rows = Vec::new();
    for (key, direction) in [
        ("incoming_references", "in"),
        ("outgoing_references", "out"),
    ] {
        rows.extend(value.get(key).and_then(Value::as_array).into_iter().flatten().map(|item| json!({"direction":direction,"source":endpoint(item.get("source_procedure"), item.get("source_address"), same_artifact),"target":endpoint(item.get("target_procedure"), item.get("target_address"), same_artifact),"kind":item.get("kind")})));
    }
    sorted(rows)
}
fn endpoint(procedure: Option<&Value>, address: Option<&Value>, same: bool) -> Value {
    if same {
        if let Some(address) = address
            .and_then(Value::as_str)
            .filter(|v| v.starts_with("0x"))
        {
            return json!({"kind":"address","address":address});
        }
    }
    if let Some(name) = procedure
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && !is_auto_name(v))
    {
        return json!({"kind":"name","name":name});
    }
    json!({"kind":"unknown","reported_address":address.cloned().unwrap_or(Value::Null),"reported_name":procedure.and_then(|p|p.get("name")).cloned().unwrap_or(Value::Null)})
}
fn cfg(value: &Value) -> Option<Value> {
    let blocks = value.get("basic_blocks")?.as_array()?;
    let mut rows = Vec::new();
    let mut starts = Vec::new();
    for block in blocks {
        let start = parse_hex(block.get("start")?.as_str()?)?;
        let end = parse_hex(block.get("end")?.as_str()?)?;
        if end <= start {
            return None;
        }
        starts.push(start);
        rows.push((start, end, block.get("successors")?.as_array()?.clone()));
    }
    starts.sort_unstable();
    starts.dedup();
    if starts.len() != rows.len() {
        return None;
    }
    rows.sort_by_key(|row| row.0);
    Some(json!(
        rows.into_iter()
            .map(|(start, end, successors)| {
                let mut indices = successors
                    .into_iter()
                    .filter_map(|s| {
                        parse_hex(s.as_str()?).and_then(|s| starts.binary_search(&s).ok())
                    })
                    .collect::<Vec<_>>();
                indices.sort_unstable();
                Some(json!({"size":(end-start).to_string(),"successors":indices}))
            })
            .collect::<Option<Vec<_>>>()?
    ))
}
fn parse_hex(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .and_then(|v| u64::from_str_radix(v, 16).ok())
}
fn coverage_limits(value: &Value, fields: &[&str]) -> Vec<String> {
    fields
        .iter()
        .filter_map(|field| {
            let declared = value.pointer(&format!("/facet_availability/{field}"));
            if declared.is_some_and(|item| item.get("available") == Some(&Value::Bool(false))) {
                Some(format!(
                    "{field}: {}",
                    declared?
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("provider marked this facet unavailable")
                ))
            } else if declared.is_none()
                && value
                    .get(*field)
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
            {
                Some(format!(
                    "{field}: Provider did not declare coverage for this empty facet."
                ))
            } else {
                None
            }
        })
        .collect()
}
fn swift_partial(value: &Value) -> bool {
    value
        .get("swift_string_literal_omissions")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
}
fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
fn sorted(values: Vec<Value>) -> Value {
    let mut rows = values;
    rows.sort_by_key(canonical);
    Value::Array(rows)
}
fn canonical(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}
fn digest_value<T: serde::Serialize>(value: &T) -> Value {
    canonical_json::digest(value).map_or(Value::Null, |digest| json!({"sha256":digest}))
}
fn is_auto_name(name: &str) -> bool {
    ["sub_", "fcn.", "fun_", "FUN_"]
        .iter()
        .find_map(|prefix| {
            name.get(..prefix.len())
                .filter(|head| head.eq_ignore_ascii_case(prefix))
                .map(|_| &name[prefix.len()..])
        })
        .is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}
fn relative_offset(value: Option<&Value>, base: Option<&str>) -> Option<Value> {
    let address = value.and_then(Value::as_str)?;
    let base = base?;
    let address = parse_hex(address)?;
    let base = parse_hex(base)?;
    (address >= base).then(|| Value::String((address - base).to_string()))
}
fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide two distinct complete analyze_function Evidence records and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
