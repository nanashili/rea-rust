//! Evidence-record and evidence-bundle projections over JSON values.
//!
//! Compatibility owners: `src/domain/evidence.ts`
//! (`rebindEvidenceSubjectTargetPath`, `rebindEvidenceToTargetPath`) and
//! `src/domain/evidenceBundle.ts` (`createEvidenceBundle`,
//! `evidenceBundleForTarget`). The session bundle produced by
//! `rea_mcp::Session::export_bundle()` already has the canonical bundle shape
//! (`artifacts`, `providers`, `environments`, `scenarios`, `captures`,
//! `unknowns`, `records`), which is the TS `EvidenceBundle` shape.
use super::canonical::compare_unicode_code_points;
use rea_analysis::BinaryTarget;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Rebind a matching artifact subject descriptor to the caller's selected path
/// (TS `rebindEvidenceSubjectTargetPath`). Operates on the display-subject
/// shape `{ path, sha256, format, architecture? }`.
pub(crate) fn rebind_evidence_subject_target_path(subject: &Value, target: &Value) -> Value {
    let matches = string_field(subject, "sha256") == string_field(target, "sha256")
        && string_field(subject, "format") == string_field(target, "format")
        && architecture_of(subject) == architecture_of(target);
    if !matches {
        return subject.clone();
    }
    let mut rebound = subject.clone();
    if let (Some(object), Some(path)) = (rebound.as_object_mut(), target.get("path")) {
        object.insert("path".into(), path.clone());
    }
    rebound
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// `architecture ?? null` for the display-subject shape.
fn architecture_of(value: &Value) -> Value {
    value.get("architecture").cloned().unwrap_or(Value::Null)
}

/// Rebind authenticated Evidence (full record shape) when it names this target
/// (TS `rebindEvidenceToTargetPath`). The subject uses the persistence shape
/// `{ name, digest: { sha256 }, local_path, format, architecture }`.
pub(crate) fn rebind_evidence_to_target_path(evidence: &Value, target: &BinaryTarget) -> Value {
    let Some(subject) = evidence.get("subject") else {
        return evidence.clone();
    };
    if subject.is_null() {
        return evidence.clone();
    }
    let subject_sha = subject
        .get("digest")
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str);
    let subject_format = subject.get("format").and_then(Value::as_str);
    let subject_arch = subject.get("architecture").cloned().unwrap_or(Value::Null);
    let subject_path = subject.get("local_path").and_then(Value::as_str);
    let target_arch = target
        .architecture
        .clone()
        .map_or(Value::Null, Value::String);
    let matches = subject_sha == Some(target.sha256.as_str())
        && subject_format == Some(target.format.as_str())
        && subject_arch == target_arch;
    if !matches || subject_path == Some(target.path.as_str()) {
        return evidence.clone();
    }
    let name = std::path::Path::new(&target.path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("artifact");
    let mut rebound_subject = subject.clone();
    if let Some(object) = rebound_subject.as_object_mut() {
        object.insert("name".into(), json!(name));
        object.insert("local_path".into(), json!(target.path));
    }
    let mut rebound = evidence.clone();
    if let Some(object) = rebound.as_object_mut() {
        object.insert("subject".into(), rebound_subject);
    }
    rebound
}

/// The residual-unknown IDs referenced by one unknown revision.
fn referenced_evidence_ids(unknown: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    for key in [
        "supporting_evidence_ids",
        "contradicting_evidence_ids",
        "mutation_evidence_ids",
    ] {
        collect_ids(unknown.get(key), &mut ids);
    }
    if let Some(resolution) = unknown.get("resolution").filter(|value| !value.is_null()) {
        collect_ids(resolution.get("evidence_ids"), &mut ids);
    }
    ids
}

fn collect_ids(value: Option<&Value>, out: &mut Vec<String>) {
    if let Some(array) = value.and_then(Value::as_array) {
        for item in array {
            if let Some(text) = item.as_str() {
                out.push(text.to_owned());
            }
        }
    }
}

fn record_subject_sha(record: &Value) -> Option<&str> {
    record
        .get("subject")
        .filter(|value| !value.is_null())
        .and_then(|subject| subject.get("digest"))
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str)
}

/// Project records into a deterministic bundle whose order has no semantics
/// (TS `createEvidenceBundle`). `records` and `unknowns` are owned JSON arrays.
pub(crate) fn create_evidence_bundle(records: Vec<Value>, unknowns: Vec<Value>) -> Value {
    let mut sorted_records = records;
    sorted_records.sort_by(|left, right| {
        compare_unicode_code_points(
            left.get("evidence_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            right
                .get("evidence_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )
    });

    let mut artifacts = Vec::new();
    let mut providers = Vec::new();
    let mut environments = Vec::new();
    let mut scenarios = Vec::new();
    let mut captures = Vec::new();
    for record in &sorted_records {
        if let Some(subject) = record.get("subject").filter(|value| !value.is_null()) {
            artifacts.push(json!({
                "digest": subject.get("digest").cloned().unwrap_or(Value::Null),
                "format": subject.get("format").cloned().unwrap_or(Value::Null),
                "architecture": subject.get("architecture").cloned().unwrap_or(Value::Null),
            }));
        }
        if let Some(provider) = record.get("provider") {
            providers.push(provider.clone());
        }
        if let Some(environment) = record.get("environment").filter(|value| !value.is_null()) {
            environments.push(environment.clone());
        }
        if record.get("authority").and_then(Value::as_str) == Some("controlled-replay") {
            scenarios.push(json!({
                "evidence_id": record.get("evidence_id").cloned().unwrap_or(Value::Null),
                "operation": record.get("operation").cloned().unwrap_or(Value::Null),
                "authority": record.get("authority").cloned().unwrap_or(Value::Null),
            }));
        }
        if record.get("predicate_type").and_then(Value::as_str) == Some("rea.process-capture") {
            captures.push(json!({
                "evidence_id": record.get("evidence_id").cloned().unwrap_or(Value::Null),
                "predicate_type": record.get("predicate_type").cloned().unwrap_or(Value::Null),
            }));
        }
    }

    let mut sorted_unknowns = unknowns;
    sorted_unknowns.sort_by(|left, right| {
        let id = compare_unicode_code_points(
            left.get("unknown_id").and_then(Value::as_str).unwrap_or(""),
            right
                .get("unknown_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        id.then_with(|| {
            let left_revision = left.get("revision").and_then(Value::as_i64).unwrap_or(0);
            let right_revision = right.get("revision").and_then(Value::as_i64).unwrap_or(0);
            left_revision.cmp(&right_revision)
        })
    });

    json!({
        "artifacts": unique_sorted(artifacts),
        "providers": unique_sorted(providers),
        "environments": unique_sorted(environments),
        "scenarios": scenarios,
        "captures": captures,
        "unknowns": sorted_unknowns,
        "records": sorted_records,
    })
}

/// TS `uniqueSorted`: dedupe by compact JSON, sort by code-point order.
fn unique_sorted(values: Vec<Value>) -> Vec<Value> {
    let mut unique: HashMap<String, Value> = HashMap::new();
    for value in values {
        unique.insert(value.to_string(), value);
    }
    let mut entries: Vec<(String, Value)> = unique.into_iter().collect();
    entries.sort_by(|(left, _), (right, _)| compare_unicode_code_points(left, right));
    entries.into_iter().map(|(_, value)| value).collect()
}

/// Retain records and eligible complete unknown histories for one target
/// (TS `evidenceBundleForTarget`). `bundle` is the canonical bundle JSON.
pub(crate) fn evidence_bundle_for_target(bundle: &Value, sha256: &str) -> Value {
    let records: Vec<Value> = bundle
        .get("records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let unknowns: Vec<Value> = bundle
        .get("unknowns")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut records_by_id: HashMap<String, &Value> = HashMap::new();
    for record in &records {
        if let Some(id) = record.get("evidence_id").and_then(Value::as_str) {
            records_by_id.insert(id.to_owned(), record);
        }
    }

    // Group unknown revisions by unknown_id preserving insertion order.
    let mut histories: Vec<(String, Vec<&Value>)> = Vec::new();
    let mut history_index: HashMap<String, usize> = HashMap::new();
    for unknown in &unknowns {
        let id = unknown
            .get("unknown_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        match history_index.get(&id) {
            Some(index) => histories[*index].1.push(unknown),
            None => {
                history_index.insert(id.clone(), histories.len());
                histories.push((id, vec![unknown]));
            }
        }
    }

    let mut retained: HashSet<String> = HashSet::new();
    let mut dependents: HashMap<String, HashSet<String>> = HashMap::new();
    // Ordered list of (id, related_ids) to mirror TS Map iteration order.
    let mut relationships: Vec<(String, HashSet<String>)> = Vec::new();

    for (id, history) in &histories {
        let eligible = history.iter().all(|unknown| {
            if unknown.get("scope_digest").and_then(Value::as_str) != Some(sha256) {
                return false;
            }
            let mutation_ids: HashSet<String> = unknown
                .get("mutation_evidence_ids")
                .and_then(Value::as_array)
                .map(|array| {
                    array
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            referenced_evidence_ids(unknown).iter().all(|evidence_id| {
                let record = records_by_id.get(evidence_id);
                let subject_matches =
                    record.is_some_and(|record| record_subject_sha(record) == Some(sha256));
                let mutation_matches = mutation_ids.contains(evidence_id)
                    && record.is_some_and(|record| {
                        record.get("predicate_type").and_then(Value::as_str)
                            == Some("rea.residual-unknown-mutation")
                    });
                subject_matches || mutation_matches
            })
        });
        if !eligible {
            continue;
        }
        retained.insert(id.clone());
        let mut related: HashSet<String> = HashSet::new();
        for unknown in history {
            if let Some(array) = unknown.get("relationships").and_then(Value::as_array) {
                for relationship in array {
                    if let Some(related_id) = relationship.get("unknown_id").and_then(Value::as_str)
                    {
                        related.insert(related_id.to_owned());
                    }
                }
            }
        }
        relationships.push((id.clone(), related.clone()));
        for related_id in &related {
            dependents
                .entry(related_id.clone())
                .or_default()
                .insert(id.clone());
        }
    }

    // Prune histories whose related IDs are not all retained, cascading.
    let mut pending: Vec<String> = Vec::new();
    for (id, related_ids) in &relationships {
        if related_ids
            .iter()
            .any(|related| !retained.contains(related))
        {
            pending.push(id.clone());
        }
    }
    let mut index = 0;
    while index < pending.len() {
        let id = pending[index].clone();
        index += 1;
        if !retained.remove(&id) {
            continue;
        }
        if let Some(references) = dependents.get(&id) {
            for dependent in references {
                pending.push(dependent.clone());
            }
        }
    }

    let retained_unknowns: Vec<Value> = unknowns
        .iter()
        .filter(|unknown| {
            unknown
                .get("unknown_id")
                .and_then(Value::as_str)
                .is_some_and(|id| retained.contains(id))
        })
        .cloned()
        .collect();

    let mut mutation_ids: BTreeSet<String> = BTreeSet::new();
    for unknown in &retained_unknowns {
        if let Some(array) = unknown
            .get("mutation_evidence_ids")
            .and_then(Value::as_array)
        {
            for value in array {
                if let Some(text) = value.as_str() {
                    mutation_ids.insert(text.to_owned());
                }
            }
        }
    }

    let filtered_records: Vec<Value> = records
        .iter()
        .filter(|record| {
            let subject_matches = record_subject_sha(record) == Some(sha256);
            let mutation_matches = record
                .get("evidence_id")
                .and_then(Value::as_str)
                .is_some_and(|id| mutation_ids.contains(id));
            subject_matches || mutation_matches
        })
        .cloned()
        .collect();

    create_evidence_bundle(filtered_records, retained_unknowns)
}
