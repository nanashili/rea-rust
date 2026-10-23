//! Views over retained `inspect_macho` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/machoView.ts`.
use crate::common::json::{self, object, unique_sorted};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, view_error, view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};

/// `MACHO_COLLECTIONS`.
const COLLECTIONS: [&str; 8] = [
    "entrypoints",
    "architectures",
    "build_metadata",
    "load_commands",
    "dependencies",
    "imports",
    "exports",
    "segments",
];

fn collection_limitations(collection: &Value) -> Vec<String> {
    json::strings(collection.get("limitations").unwrap_or(&Value::Null))
}

/// `projectMachoView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "macho" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "Mach-O inspection supports summary and macho views.",
        ));
    }
    // `parseMachoReport`.
    let report = parent.parse_result("inspect_macho")?;
    if parent.has_subject()
        && !matches!(parent.subject_format(), Some("mach-o" | "mach-o-universal"))
    {
        return Err(view_error(
            &["source", "subject"],
            "invalid_value",
            "Mach-O parent Evidence subject must identify a thin or universal Mach-O.",
        ));
    }
    let collection = |name: &str| report.get(name).unwrap_or(&Value::Null);
    let incomplete: Vec<&str> = COLLECTIONS
        .iter()
        .copied()
        .filter(|name| collection(name).get("exhaustive").and_then(Value::as_bool) != Some(true))
        .collect();
    let mut unknowns = Vec::new();
    if !incomplete.is_empty() {
        unknowns.push(format!(
            "Native tools did not report exhaustive {}; page exhaustion does not establish absence of unreturned rows.",
            incomplete.join(", ")
        ));
    }
    let artifact = if parent.has_subject() {
        json!({
            "path": parent.subject.get("local_path").cloned().unwrap_or(Value::Null),
            "sha256": parent
                .subject
                .get("digest")
                .and_then(|digest| digest.get("sha256"))
                .cloned()
                .unwrap_or(Value::Null),
        })
    } else {
        unknowns.push(
            "The parent has no recorded subject, so the inspected artifact path and SHA-256 are unknown.".to_owned(),
        );
        json!({ "path": "", "sha256": null })
    };
    let shared = [
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!("inspect_macho")),
        ("parent_digest", json!(parent.digest())),
        ("artifact", artifact),
        ("unknowns", json!(unknowns)),
    ];
    let with_shared =
        |entries: Vec<(&'static str, Value)>| object(shared.iter().cloned().chain(entries));
    let report_limitations = json::strings(report.get("limitations").unwrap_or(&Value::Null));
    let field = |name: &str| report.get(name).cloned().unwrap_or(Value::Null);
    if kind == "summary" {
        // `summarizeMacho`.
        let limitations = unique_sorted(
            parent
                .limitations
                .iter()
                .cloned()
                .chain(report_limitations.iter().cloned())
                .chain(
                    COLLECTIONS
                        .iter()
                        .flat_map(|name| collection_limitations(collection(name))),
                ),
        );
        let mut collections = Map::new();
        let mut returned = 0usize;
        for name in COLLECTIONS {
            let source = collection(name);
            let items = json::array_at(source, "items").len();
            returned += items;
            collections.insert(
                name.into(),
                json!({
                    "returned": items,
                    "total": source.get("total").cloned().unwrap_or(Value::Null),
                    "exhaustive": source.get("exhaustive").cloned().unwrap_or(Value::Null),
                }),
            );
        }
        let summary = json!({
            "format": field("format"),
            "selected_architecture": field("selected_architecture"),
            "endian": field("endian"),
            "word_size": field("word_size"),
            "file_type": field("file_type"),
            "flags": field("flags"),
            "uuid": field("uuid"),
            "collections": collections,
            "provenance_count": json::array_at(&report, "provenance").len(),
            "limitation_count": limitations.len(),
        });
        return Ok(with_shared(vec![
            ("kind", json!("summary")),
            ("view", view.clone()),
            ("limitations", json!(limitations)),
            ("summary", summary),
            ("coverage", complete_within_view(returned, returned)),
        ]));
    }
    let facet = json::str_at(view, "facet").unwrap_or_default();
    let (rows, total, exhaustive, source_limitations) = if facet == "provenance" {
        let rows = json::array_at(&report, "provenance");
        (rows, json!(rows.len()), json!(true), Vec::new())
    } else {
        let source = collection(facet);
        (
            json::array_at(source, "items"),
            source.get("total").cloned().unwrap_or(Value::Null),
            source.get("exhaustive").cloned().unwrap_or(Value::Null),
            collection_limitations(source),
        )
    };
    let (offset, limit) = offset_limit(view);
    let item = page(rows, offset, limit);
    let examined = item.len();
    let limitations = unique_sorted(
        parent
            .limitations
            .iter()
            .cloned()
            .chain(report_limitations)
            .chain(source_limitations),
    );
    Ok(object(
        [
            ("kind", json!("macho")),
            ("view", view.clone()),
            ("item", Value::Array(item)),
        ]
        .into_iter()
        .chain(shared.iter().cloned())
        .chain([
            ("limitations", json!(limitations)),
            ("source_total", total),
            ("source_exhaustive", exhaustive),
            ("coverage", page_coverage(offset, examined, rows.len())),
        ]),
    ))
}
