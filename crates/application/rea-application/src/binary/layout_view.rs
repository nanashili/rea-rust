//! Authenticated, non-rerunning views over retained binary-layout Evidence.

use crate::binary::layout::OPERATION as PARENT_OPERATION;
use rea_core::{
    canonical_json,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";
const PAGE_SIZE: usize = 64;

/// Project a view without reopening the binary or decoding it again.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;
    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "Binary layout view requires inspect_binary_layout Evidence.",
        ));
    }

    let report: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(&format!(
                "Binary layout normalized result is invalid: {error}"
            ))
        })?;
    validate_report(&report)?;
    let requested = parse_view(view)?;
    let body = match requested {
        RequestedView::Summary => summary(&record, &report),
        RequestedView::Facet { facet: facet_name } => facet(&report, facet_name)?,
        RequestedView::Item {
            collection,
            selector,
        } => item(&report, collection, selector)?,
        RequestedView::Page {
            collection,
            offset,
            limit,
        } => page(&report, collection, offset, limit),
    };
    create_view_evidence(&record, view.clone(), body)
}

#[derive(Clone, Copy)]
enum Collection {
    Sections,
    Symbols,
}

impl Collection {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "sections" => Some(Self::Sections),
            "symbols" => Some(Self::Symbols),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Sections => "sections",
            Self::Symbols => "symbols",
        }
    }
}

enum RequestedView {
    Summary,
    Facet {
        facet: String,
    },
    Item {
        collection: Collection,
        selector: Selector,
    },
    Page {
        collection: Collection,
        offset: usize,
        limit: usize,
    },
}

enum Selector {
    Index(usize),
    Name(String),
}

fn parse_view(view: &Value) -> Result<RequestedView, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("Binary layout view must be an object."))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Binary layout view kind is required."))?;

    match kind {
        "summary" => Ok(RequestedView::Summary),
        "facet" => Ok(RequestedView::Facet {
            facet: object
                .get("facet")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Binary layout facet is required."))?
                .to_owned(),
        }),
        "item" => {
            let collection = parse_collection(object)?;
            let selector = if let Some(index) = object.get("index").and_then(Value::as_u64) {
                Selector::Index(index_as_usize(index, "index")?)
            } else if let Some(name) = object.get("name").and_then(Value::as_str) {
                Selector::Name(name.to_owned())
            } else {
                return Err(invalid(
                    "Section and symbol items are selected by index or exact name.",
                ));
            };
            Ok(RequestedView::Item {
                collection,
                selector,
            })
        }
        "page" => {
            let collection = parse_collection(object)?;
            let offset = nonnegative_number(object.get("offset"), 0, "offset")?;
            let limit = nonnegative_number(object.get("limit"), PAGE_SIZE, "limit")?;
            if limit == 0 {
                return Err(invalid("Binary layout view limit must be positive."));
            }
            Ok(RequestedView::Page {
                collection,
                offset,
                limit,
            })
        }
        _ => Err(invalid(
            "Layout views require summary, facet, item or page selections.",
        )),
    }
}

fn parse_collection(object: &Map<String, Value>) -> Result<Collection, Failure> {
    let value = object
        .get("collection")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Binary layout collection is required."))?;
    Collection::parse(value)
        .ok_or_else(|| invalid("Binary layout collections are sections or symbols."))
}

fn nonnegative_number(
    value: Option<&Value>,
    default: usize,
    field: &str,
) -> Result<usize, Failure> {
    let Some(value) = value else {
        return Ok(default);
    };
    let number = value.as_u64().ok_or_else(|| {
        invalid(&format!(
            "Binary layout {field} must be a non-negative integer."
        ))
    })?;
    index_as_usize(number, field)
}

fn index_as_usize(value: u64, field: &str) -> Result<usize, Failure> {
    usize::try_from(value).map_err(|_| {
        invalid(&format!(
            "Binary layout {field} exceeds the host index limit."
        ))
    })
}

fn validate_report(report: &Value) -> Result<(), Failure> {
    let object = report
        .as_object()
        .ok_or_else(|| invalid("Binary layout normalized result must be an object."))?;
    for field in [
        "artifact",
        "sections",
        "segments",
        "symbols",
        "relocations",
        "limitations",
    ] {
        if !object.contains_key(field) {
            return Err(invalid(&format!(
                "Binary layout result is missing {field}."
            )));
        }
    }
    if !object["artifact"].is_object()
        || object["artifact"]["path"].as_str().is_none()
        || object["artifact"]["sha256"].as_str().is_none()
    {
        return Err(invalid("Binary layout artifact identity is invalid."));
    }
    for field in ["sections", "segments", "symbols", "relocations"] {
        if !object[field].is_array() {
            return Err(invalid(&format!("Binary layout {field} must be an array.")));
        }
    }
    if !object["limitations"].is_array() {
        return Err(invalid("Binary layout limitations must be an array."));
    }
    Ok(())
}

fn summary(record: &EvidenceRecord, report: &Value) -> Value {
    let sections = array_len(report, "sections");
    let segments = array_len(report, "segments");
    let symbols = array_len(report, "symbols");
    let relocations = array_len(report, "relocations");
    let total = sections + segments + symbols + relocations;
    json!({
        "kind": "summary",
        "view": {"kind": "summary"},
        "summary": {
            "bytes": report["artifact"]["bytes"],
            "format": report["format"],
            "architecture": report["architecture"],
            "image_type": report["image_type"],
            "entry": report["entry_point"],
            "counts": {"sections": sections, "segments": segments, "symbols": symbols, "relocations": relocations},
            "limitation_count": array_len(report, "limitations"),
        },
        "coverage": complete_coverage(total),
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": parent_digest(record),
        "artifact": report["artifact"],
        "limitations": report["limitations"],
        "unknowns": unknowns(report),
    })
}

fn facet(report: &Value, facet: String) -> Result<Value, Failure> {
    let value = match facet.as_str() {
        "mitigations" | "linkage" => report[&facet].clone(),
        _ => return Err(invalid("Binary layout facets are mitigations or linkage.")),
    };
    Ok(json!({
        "kind": "facet", "view": {"kind":"facet", "facet":facet}, "facet":value,
        "coverage": complete_coverage(1),
        "artifact": report["artifact"], "limitations": report["limitations"], "unknowns": unknowns(report),
    }))
}

fn item(report: &Value, collection: Collection, selector: Selector) -> Result<Value, Failure> {
    let rows = rows(report, collection)?;
    let selector_value = match &selector {
        Selector::Index(index) => json!({"index": index}),
        Selector::Name(name) => json!({"name": name}),
    };
    let row = match selector {
        Selector::Index(index) => rows
            .get(index)
            .cloned()
            .ok_or_else(|| out_of_range(collection, index, rows.len()))?,
        Selector::Name(name) => select_name(collection, rows, &name)?.1,
    };
    Ok(json!({
        "kind":"item", "view":{"kind":"item", "collection":collection.name(), "selector": selector_value}, "item":row,
        "coverage":complete_coverage(rows.len()), "artifact":report["artifact"], "limitations":report["limitations"], "unknowns":unknowns(report),
    }))
}

fn select_name(
    collection: Collection,
    rows: &[Value],
    name: &str,
) -> Result<(usize, Value), Failure> {
    let matches: Vec<(usize, Value)> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            (row["name"]["unknown_reason"].is_null()
                && row["name"]["display"].as_str() == Some(name))
            .then(|| (index, row.clone()))
        })
        .collect();
    match matches.len() {
        1 => Ok(matches.into_iter().next().expect("one match")),
        0 => Err(invalid(&format!(
            "No {} named {name:?}. Collection has {} entries; page it to inspect exact indexes and names.",
            collection.name(),
            rows.len()
        ))),
        _ => Err(invalid(&format!(
            "Multiple {} named {name:?}; select one by index.",
            collection.name()
        ))),
    }
}

fn page(report: &Value, collection: Collection, offset: usize, limit: usize) -> Value {
    let source = rows(report, collection).unwrap_or(&[]);
    let items: Vec<Value> = source.iter().skip(offset).take(limit).cloned().collect();
    json!({
        "kind":"page", "view":{"kind":"page", "collection":collection.name(), "offset":offset, "limit":limit}, "items":items,
        "coverage":page_coverage(offset, items.len(), source.len()), "artifact":report["artifact"], "limitations":report["limitations"], "unknowns":unknowns(report),
    })
}

fn rows<'a>(report: &'a Value, collection: Collection) -> Result<&'a [Value], Failure> {
    report[collection.name()]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("Binary layout collection is missing."))
}

fn array_len(report: &Value, field: &str) -> usize {
    report[field].as_array().map_or(0, Vec::len)
}

fn unknowns(report: &Value) -> Vec<String> {
    let mut values = vec![
        "runtime_load_base is unknown".to_owned(),
        "entry_point.execution_status is unknown".to_owned(),
        "relocation_inventory_completeness is unknown".to_owned(),
        "linkage.convenience_maps_completeness is unknown".to_owned(),
        "linkage.runtime_library_paths are unknown".to_owned(),
    ];
    if report["mitigations"]["nx_indicator"].is_null() {
        values.push("mitigations.nx_indicator is unknown".to_owned());
    }
    if report["mitigations"]["relro"].is_null() {
        values.push("mitigations.relro is unknown".to_owned());
    }
    values.sort();
    values
}

fn create_view_evidence(
    record: &EvidenceRecord,
    view: Value,
    mut body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let view_digest = canonical_json::digest(&body).map_err(|error| invalid(&error.to_string()))?;
    body["view_digest"] = json!(view_digest);
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let authority: Value = serde_json::from_str(record.authority().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let path = body["artifact"]["path"].as_str().unwrap_or_default();
    let locations = if path.is_empty() {
        vec![]
    } else {
        vec![json!({"kind":"artifact-path", "path":path})]
    };
    let unsigned = json!({
        "subject":subject, "provider":{"id":"rea-analysis-view","name":"REA analysis view projection","version":"1"},
        "analysis_profile":null, "predicate_type":"rea.analysis-view", "operation":OPERATION,
        "parameters":{"parent_evidence_id":record.evidence_id(),"view":view}, "raw_result":null,
        "normalized_result":body, "confidence":"derived", "authority":authority, "environment":null,
        "limitations":body["limitations"], "relationship_coverage":null, "locations":locations,
        "evidence_links":[record.evidence_id()]
    });
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
            .expect("validated Evidence"),
    )
}

fn parent_digest(record: &EvidenceRecord) -> String {
    record
        .evidence_id()
        .strip_prefix("ev_")
        .unwrap_or(record.evidence_id())
        .to_owned()
}
fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
}
fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
}
fn out_of_range(collection: Collection, index: usize, total: usize) -> Failure {
    invalid(&format!(
        "{} index {index} is outside 0..{} ({total} entries).",
        collection.name(),
        total.saturating_sub(1)
    ))
}
fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the view and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
