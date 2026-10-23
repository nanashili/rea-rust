//! Binary overview from a provider aggregate or complete inventories.
//!
//! Compatibility owners: `#binaryOverview` (`EnhancedTools.ts`),
//! `resolveAnalysisDocument` (`AnalysisDocument.ts`) and `parseSegments`,
//! `parseListCount`, `parseDocuments`, `projectBinaryOverview`
//! (`domain/hopperValues.ts`).
use crate::analysis::{Analysis, is_capability_unavailable};
use crate::domain::address::distance;
use crate::zod::{Schema, array, boolean, field, nullable, object, optional, string, string_min};
use rea_analysis::AnalysisExecution;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::sync::OnceLock;

/// `unwrapProperty`: `value[property]` when `value` is an object holding it.
pub fn unwrap_property<'a>(value: &'a Value, property: &str) -> &'a Value {
    match value {
        Value::Object(object) => object.get(property).unwrap_or(value),
        _ => value,
    }
}

fn segment_schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        array(object(vec![
            field("name", string()),
            field("start", string()),
            field("end", string()),
            field("readable", nullable(boolean())),
            field("writable", nullable(boolean())),
            field("executable", nullable(boolean())),
            optional("image_base", string_min(1)),
            optional("address_space", string_min(1)),
        ]))
    })
}

/// `parseSegments`.
fn parse_segments(value: &Value) -> Result<Vec<Value>, AnalysisError> {
    match segment_schema().parse(unwrap_property(value, "segments")) {
        Ok(Value::Array(segments)) => Ok(segments),
        _ => Err(AnalysisError::output(
            "list_segments",
            "Provider returned an invalid segment list",
        )),
    }
}

/// `parseListCount`: cardinality of a direct or wrapped list or map.
fn parse_list_count(value: &Value, property: &str) -> Result<usize, AnalysisError> {
    match unwrap_property(value, property) {
        Value::Array(items) => Ok(items.len()),
        Value::Object(entries) => Ok(entries.len()),
        _ => Err(AnalysisError::output(
            if property == "procedures" {
                "list_procedures"
            } else {
                "list_strings"
            },
            format!("Provider returned an invalid {property} list"),
        )),
    }
}

/// `parseDocuments`.
fn parse_documents(value: &Value) -> Option<Vec<String>> {
    unwrap_property(value, "documents")
        .as_array()?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect()
}

/// `parseSegmentImageBase`.
fn segment_image_base(segments: &[Value]) -> Option<&str> {
    let base = segments.first()?.get("image_base")?.as_str()?;
    segments
        .iter()
        .all(|segment| segment.get("image_base").and_then(Value::as_str) == Some(base))
        .then_some(base)
}

/// `projectBinaryOverview`.
pub fn project_binary_overview(
    document: &str,
    procedure_count: usize,
    string_count: usize,
    segments: Option<&[Value]>,
) -> Value {
    let mut overview = Map::new();
    overview.insert("document".into(), json!(document));
    if let Some(base) = segments.and_then(segment_image_base) {
        overview.insert("image_base".into(), json!(base));
    }
    if let Some(segments) = segments {
        let projected = segments
            .iter()
            .map(|segment| {
                let start = segment["start"].as_str().unwrap_or_default();
                let end = segment["end"].as_str().unwrap_or_default();
                let mut entry = Map::new();
                entry.insert("name".into(), segment["name"].clone());
                entry.insert("start".into(), json!(start));
                entry.insert("end".into(), json!(end));
                entry.insert("length".into(), json!(distance(start, end)));
                if let Some(base) = segment.get("image_base") {
                    entry.insert("image_base".into(), base.clone());
                }
                if let Some(space) = segment.get("address_space") {
                    entry.insert("address_space".into(), space.clone());
                }
                Value::Object(entry)
            })
            .collect::<Vec<_>>();
        overview.insert("segments".into(), Value::Array(projected));
        overview.insert("segment_count".into(), json!(segments.len()));
    }
    overview.insert("procedure_count".into(), json!(procedure_count));
    overview.insert("string_count".into(), json!(string_count));
    Value::Object(overview)
}

/// `completeSelection`: keep the completed observation if cancellation wins.
fn complete_selection(
    analysis: &Analysis<'_>,
    document: String,
    operation: &str,
    execution: &AnalysisExecution,
) -> Result<String, AnalysisError> {
    if analysis.aborted() {
        let cancelled = AnalysisError::cancelled(operation);
        return Err(match execution.evidence(operation, json!({}), "observed") {
            Ok(evidence) => cancelled.retain_partial_observation(evidence.into_value()),
            Err(error) => error,
        });
    }
    Ok(document)
}

/// `resolveAnalysisDocument` without an explicit document.
pub fn resolve_analysis_document(analysis: &Analysis<'_>) -> Result<String, AnalysisError> {
    if analysis.aborted() {
        return Err(AnalysisError::cancelled("current_document"));
    }
    let current = match analysis.execute("current_document", &Map::new(), false) {
        Ok(current) => current,
        Err(error) => {
            if !is_capability_unavailable(&error) || error.is_cleanup_incomplete() {
                return Err(error);
            }
            if analysis.aborted() {
                return Err(AnalysisError::cancelled("current_document"));
            }
            let listed = analysis.execute("list_documents", &Map::new(), false)?;
            let Some(documents) = parse_documents(&listed.result) else {
                return Err(AnalysisError::output(
                    "list_documents",
                    "expected one document identity when resolving a headless provider",
                ));
            };
            if documents.len() != 1 {
                return Err(AnalysisError::output(
                    "list_documents",
                    format!(
                        "expected exactly one document identity for a provider without current-document selection, received {}",
                        documents.len()
                    ),
                ));
            }
            let document = documents.into_iter().next().unwrap_or_default();
            if document.is_empty() {
                return Err(AnalysisError::output(
                    "list_documents",
                    "provider returned no document identity",
                ));
            }
            return complete_selection(analysis, document, "list_documents", &listed);
        }
    };
    match &current.result {
        Value::String(document) if !document.is_empty() => {
            complete_selection(analysis, document.clone(), "current_document", &current)
        }
        _ => Err(AnalysisError::output(
            "current_document",
            "expected a nonempty document identity string",
        )),
    }
}

/// `#binaryOverview`.
pub fn binary_overview(analysis: &Analysis<'_>) -> Result<Value, AnalysisError> {
    let direct = analysis.call("read_binary_inventory_summary", &Map::new(), false);
    match direct {
        Ok(value) => return Ok(value),
        Err(error) if !is_capability_unavailable(&error) || error.is_cleanup_incomplete() => {
            return Err(error);
        }
        Err(_) => {}
    }
    let document = resolve_analysis_document(analysis)?;
    // The overview requires a string count. When the route does not report
    // list_strings available, read strings first: a typed unavailability is
    // returned before materializing a procedure inventory that cannot be used,
    // and a successful result is reused rather than requested twice.
    let early_strings = (!analysis.supports("list_strings"))
        .then(|| analysis.call("list_strings", &Map::new(), false));
    if let Some(Err(error)) = &early_strings
        && is_capability_unavailable(error)
    {
        return Err(error.clone());
    }
    // The three inventories are requested together; each completes before
    // its result is inspected.
    let segments = analysis.call("list_segments", &Map::new(), false);
    let procedures = analysis.call("list_procedures", &Map::new(), false);
    let strings =
        early_strings.unwrap_or_else(|| analysis.call("list_strings", &Map::new(), false));
    let segments = match segments {
        Ok(value) => Some(value),
        Err(error) if is_capability_unavailable(&error) => None,
        Err(error) => return Err(error),
    };
    let procedures = procedures?;
    let strings = strings?;
    let segments = segments.as_ref().map(parse_segments).transpose()?;
    let procedure_count = parse_list_count(&procedures, "procedures")?;
    let string_count = parse_list_count(&strings, "strings")?;
    Ok(project_binary_overview(
        &document,
        procedure_count,
        string_count,
        segments.as_deref(),
    ))
}
