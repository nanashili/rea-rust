//! Views over retained `inspect_il2cpp_metadata` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/il2cppMetadataView.ts`.
use crate::common::json;
use crate::common::schema::{self, Issue, IssueKind};
use crate::common::view::{
    OPERATION, Parent, complete_within_view, offset_limit, page_coverage, view_error, view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::collections::HashSet;

/// Header-ordered IL2CPP metadata section names (used by the ordering refine).
const SECTION_NAMES: [&str; 31] = [
    "stringLiterals",
    "stringLiteralData",
    "strings",
    "events",
    "properties",
    "methods",
    "parameterDefaultValues",
    "fieldDefaultValues",
    "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes",
    "parameters",
    "fields",
    "genericParameters",
    "genericParameterConstraints",
    "genericContainers",
    "nestedTypes",
    "interfaces",
    "vtableMethods",
    "interfaceOffsets",
    "typeDefinitions",
    "images",
    "assemblies",
    "fieldRefs",
    "referencedAssemblies",
    "attributeData",
    "attributeDataRanges",
    "unresolvedIndirectCallParameterTypes",
    "unresolvedIndirectCallParameterRanges",
    "windowsRuntimeTypeNames",
    "windowsRuntimeStrings",
    "exportedTypeDefinitions",
];

/// Counts recorded once for an immutable parent.
struct Checked {
    counts: Value,
}

/// `parseMetadataReport`: validate the owned report (schema + section refine)
/// and record its collection counts. Cached for immutable parents.
fn checked_report(parent: &Parent<'_>) -> Result<(std::sync::Arc<Value>, Value), AnalysisError> {
    let report = parent.parse_result("inspect_il2cpp_metadata")?;
    refine_sections(&report)?;
    let computed = parent.cached("inspect_il2cpp_metadata:counts", || {
        let types = json::array_at(&report, "types");
        let nested = types
            .iter()
            .filter(|ty| ty.get("declaring_type").and_then(Value::as_i64) != Some(-1))
            .count();
        Ok(Checked {
            counts: json!({
                "sections": json::array_at(&report, "sections").len(),
                "images": json::array_at(&report, "images").len(),
                "types": types.len(),
                "methods": json::array_at(&report, "methods").len(),
                "nested_types": nested,
            }),
        })
    })?;
    Ok((report, computed.counts.clone()))
}

/// Port of `il2cppMetadataSchema.superRefine`: sections must follow header order
/// and their ranges must stay inside the recorded artifact bytes.
fn refine_sections(report: &Value) -> Result<(), AnalysisError> {
    let sections = json::array_at(report, "sections");
    let bytes = report
        .get("artifact")
        .and_then(|artifact| artifact.get("bytes"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut issues: Vec<Issue> = Vec::new();
    for (index, section) in sections.iter().enumerate() {
        let name = section.get("name").and_then(Value::as_str);
        if name != SECTION_NAMES.get(index).copied() {
            issues.push(Issue {
                path: vec![json!("sections"), json!(index), json!("name")],
                kind: IssueKind::Custom {
                    message: "Sections must follow header order.".into(),
                },
                aborts: false,
            });
        }
        let offset = section.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let size = section.get("size").and_then(Value::as_u64).unwrap_or(0);
        if offset.saturating_add(size) > bytes {
            issues.push(Issue {
                path: vec![json!("sections"), json!(index)],
                kind: IssueKind::Custom {
                    message: "Section range is outside the selected artifact.".into(),
                },
                aborts: false,
            });
        }
    }
    if issues.is_empty() {
        return Ok(());
    }
    let issues = schema::prefix_issues(issues, &["source", "normalized_result"]);
    let input = json!({ "source": { "normalized_result": report } });
    Err(schema::input_error_from_issues(
        OPERATION,
        &issues,
        &input,
        Vec::new(),
    ))
}

/// `rowIndices`: all indices, or the requested indices deduplicated, sorted
/// ascending and bounded by the collection length.
fn row_indices(length: usize, indices: Option<&Value>) -> Vec<usize> {
    match indices {
        None => (0..length).collect(),
        Some(values) => {
            let mut set: BTreeSet<u64> = BTreeSet::new();
            if let Some(items) = values.as_array() {
                for value in items {
                    if let Some(index) = value.as_u64() {
                        set.insert(index);
                    }
                }
            }
            set.into_iter()
                .filter_map(|index| usize::try_from(index).ok())
                .filter(|index| *index < length)
                .collect()
        }
    }
}

/// `selectFields`: `{ index, ...row }` with optional field filtering; omitted
/// (absent) values are dropped; JSON nulls are retained.
fn select_fields(row: &Value, index: usize, fields: Option<&HashSet<String>>) -> Value {
    let mut item = Map::new();
    item.insert("index".into(), json!(index));
    if let Some(object) = row.as_object() {
        for (key, value) in object {
            if fields.is_none_or(|set| set.contains(key.as_str())) {
                item.insert(key.clone(), value.clone());
            }
        }
    }
    Value::Object(item)
}

/// Contiguous `[start, end)` type range of a selected image.
#[derive(Clone, Copy)]
struct Range {
    start: i64,
    end: i64,
}

/// Compile caller selections once (`selection`).
struct Selection {
    names: Option<HashSet<String>>,
    owners: Option<HashSet<i64>>,
    namespaces: Option<HashSet<String>>,
    image_ranges: Option<Vec<Range>>,
}

impl Selection {
    fn compile(view: &Value, collection: &str, report: &Value) -> Self {
        let names = view
            .get("names")
            .map(|v| json::strings(v).into_iter().collect());
        let owners = if (collection == "types" || collection == "methods")
            && view.get("declaring_types").is_some()
        {
            Some(
                json::array_at(view, "declaring_types")
                    .iter()
                    .filter_map(Value::as_i64)
                    .collect(),
            )
        } else {
            None
        };
        let namespaces = if collection == "types" && view.get("namespaces").is_some() {
            Some(
                json::strings(view.get("namespaces").unwrap())
                    .into_iter()
                    .collect(),
            )
        } else {
            None
        };
        let image_ranges = if collection == "types" {
            view.get("image_indices").map(|indices| {
                // Deduplicate, map to ranges, sort by start, then merge overlaps.
                let mut unique: BTreeSet<u64> = BTreeSet::new();
                if let Some(items) = indices.as_array() {
                    for value in items {
                        if let Some(index) = value.as_u64() {
                            unique.insert(index);
                        }
                    }
                }
                let images = json::array_at(report, "images");
                let mut selected: Vec<Range> = unique
                    .into_iter()
                    .filter_map(|index| {
                        let image = images.get(usize::try_from(index).ok()?)?;
                        let type_count =
                            image.get("type_count").and_then(Value::as_i64).unwrap_or(0);
                        if type_count == 0 {
                            return None;
                        }
                        let type_start =
                            image.get("type_start").and_then(Value::as_i64).unwrap_or(0);
                        Some(Range {
                            start: type_start,
                            end: type_start + type_count,
                        })
                    })
                    .collect();
                selected.sort_by_key(|range| range.start);
                let mut ranges: Vec<Range> = Vec::new();
                for range in selected {
                    match ranges.last_mut() {
                        Some(last) if range.start <= last.end => {
                            last.end = last.end.max(range.end);
                        }
                        _ => ranges.push(range),
                    }
                }
                ranges
            })
        } else {
            None
        };
        Selection {
            names,
            owners,
            namespaces,
            image_ranges,
        }
    }

    fn matches(&self, row: &Value, index: usize) -> bool {
        if let Some(names) = &self.names {
            let name = row.get("name").and_then(Value::as_str).unwrap_or("");
            if !names.contains(name) {
                return false;
            }
        }
        if let Some(owners) = &self.owners {
            match row.get("declaring_type").and_then(Value::as_i64) {
                Some(value) if owners.contains(&value) => {}
                _ => return false,
            }
        }
        if let Some(namespaces) = &self.namespaces {
            match row.get("namespace").and_then(Value::as_str) {
                Some(value) if namespaces.contains(value) => {}
                _ => return false,
            }
        }
        let Some(ranges) = &self.image_ranges else {
            return true;
        };
        // Upper-bound binary search: last range whose start <= index.
        let index = index as i64;
        let mut lower = 0usize;
        let mut upper = ranges.len();
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            if ranges[middle].start <= index {
                lower = middle + 1;
            } else {
                upper = middle;
            }
        }
        if lower == 0 {
            return false;
        }
        let range = ranges[lower - 1];
        index < range.end
    }
}

/// `projectIl2cppMetadataView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "il2cpp-metadata" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "IL2CPP metadata Evidence supports summary and selected sections/images/types/methods pages.",
        ));
    }
    let (report, counts) = checked_report(parent)?;

    let artifact = report.get("artifact").cloned().unwrap_or(Value::Null);
    let artifact_path = artifact.get("path").and_then(Value::as_str);
    let artifact_sha256 = artifact.get("sha256").and_then(Value::as_str);
    let subject = parent.subject;
    if subject.is_object()
        && (subject.get("format").and_then(Value::as_str) != Some("file")
            || subject.get("local_path").and_then(Value::as_str) != artifact_path
            || subject
                .get("digest")
                .and_then(|digest| digest.get("sha256"))
                .and_then(Value::as_str)
                != artifact_sha256)
    {
        return Err(view_error(
            &["source", "subject"],
            "invalid_value",
            "IL2CPP metadata artifact identity does not match its parent subject.",
        ));
    }

    let shared_artifact = json!({ "path": artifact_path, "sha256": artifact_sha256 });
    let mut unknowns = vec![
        "Counts and page exhaustion cover retained metadata facts, not runtime loading or native code addresses.".to_owned(),
    ];
    if !subject.is_object() {
        unknowns.push(
            "The parent has no recorded subject; its normalized artifact identity cannot be cross-checked against a subject digest.".to_owned(),
        );
    }
    let limitations = parent.limitations.clone();
    let shared = |map: &mut Map<String, Value>| {
        map.insert("parent_evidence_id".into(), json!(parent.evidence_id));
        map.insert("parent_operation".into(), json!("inspect_il2cpp_metadata"));
        map.insert("parent_digest".into(), json!(parent.digest()));
        map.insert("artifact".into(), shared_artifact.clone());
        map.insert("limitations".into(), json!(limitations));
        map.insert("unknowns".into(), json!(unknowns));
    };

    if kind == "summary" {
        // identity = report without the row collections.
        let mut identity = json::without(&report, &["sections", "images", "types", "methods"]);
        identity.insert("counts".into(), counts.clone());
        let mut out = Map::new();
        out.insert("kind".into(), json!("summary"));
        out.insert("view".into(), view.clone());
        shared(&mut out);
        out.insert("summary".into(), Value::Object(identity));
        out.insert("coverage".into(), complete_within_view(1, 1));
        return Ok(Value::Object(out));
    }

    let collection = json::str_at(view, "collection")
        .unwrap_or_default()
        .to_owned();
    let rows = json::array_at(&report, &collection);
    let selection = Selection::compile(view, &collection, &report);
    let fields: Option<HashSet<String>> = view
        .get("fields")
        .map(|v| json::strings(v).into_iter().collect());
    let (offset, limit) = offset_limit(view);

    let mut items: Vec<Value> = Vec::new();
    let mut total = 0usize;
    for index in row_indices(rows.len(), view.get("indices")) {
        let row = &rows[index];
        if !selection.matches(row, index) {
            continue;
        }
        if total >= offset && items.len() < limit {
            items.push(select_fields(row, index, fields.as_ref()));
        }
        total += 1;
    }

    let mut out = Map::new();
    out.insert("kind".into(), json!("il2cpp-metadata"));
    out.insert("view".into(), view.clone());
    shared(&mut out);
    out.insert("items".into(), Value::Array(items.clone()));
    out.insert(
        "metadata_version".into(),
        report
            .get("metadata_version")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert("counts".into(), counts);
    out.insert("coverage".into(), page_coverage(offset, items.len(), total));
    Ok(Value::Object(out))
}
