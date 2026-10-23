//! Normalize the selected analyst outcome from upstream tool payloads.
//!
//! Compatibility owner: `src/android/JadxAnalysis.ts` with the result schemas
//! in `src/domain/android/androidAnalysis.ts`. Only the selected operation's
//! outcome is normalized; ambiguous engine selectors are rejected as input.

use super::protocol::{self, JadxClass, JadxLoad, ProtocolError};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Map, Value, json};

/// A validated Android request carrying its operation and input.
#[derive(Clone, Debug)]
pub struct AndroidRequest {
    pub operation: &'static str,
    pub path: String,
    pub class_name: Option<String>,
    pub method_name: Option<String>,
    pub overload_index: Option<u64>,
    pub query: Option<String>,
}

/// Upstream tool access (text and JSON payloads).
pub trait ToolCaller {
    fn text(&mut self, name: &str, input: Value) -> Result<String, AnalysisError>;
    fn json(&mut self, name: &str, input: Value) -> Result<Value, AnalysisError>;
}

fn input_failure(operation: &str, field: &str, message: impl Into<String>) -> AnalysisError {
    AnalysisError::input(
        operation,
        vec![InputIssue::new(&[field], "invalid_value", message)],
    )
}

fn protocol_output(operation: &str, error: ProtocolError) -> AnalysisError {
    error.into_output(operation)
}

/// `methodsOf(summary)`: stable same-name overload indices.
struct NormalizedMethod {
    name: String,
    reported_signature: String,
    overload_index: u64,
    is_constructor: bool,
    dex_descriptor: String,
}

fn methods_of(summary: &JadxClass) -> Vec<NormalizedMethod> {
    let mut seen: Map<String, Value> = Map::new();
    summary
        .methods
        .iter()
        .map(|method| {
            let index = seen.get(&method.name).and_then(Value::as_u64).unwrap_or(0);
            seen.insert(method.name.clone(), json!(index + 1));
            NormalizedMethod {
                name: method.name.clone(),
                reported_signature: method.signature.clone(),
                overload_index: index,
                is_constructor: method.is_constructor,
                dex_descriptor: method.dex_descriptor.clone(),
            }
        })
        .collect()
}

fn method_value(method: &NormalizedMethod) -> Value {
    json!({
        "name": method.name,
        "reported_signature": method.reported_signature,
        "overload_index": method.overload_index,
        "is_constructor": method.is_constructor,
        "dex_descriptor": method.dex_descriptor,
    })
}

/// `classSummary(tools, request)`.
fn class_summary(
    tools: &mut dyn ToolCaller,
    request: &AndroidRequest,
    class_name: &str,
) -> Result<JadxClass, AnalysisError> {
    let raw = tools.json("get_class_summary", json!({ "class_name": class_name }))?;
    if let Some(object) = raw.as_object()
        && let Some(error) = object.get("error").and_then(Value::as_str)
    {
        return Err(AnalysisError::output(
            request.operation,
            format!("JADX class summary failed: {error}"),
        ));
    }
    let summary = protocol::parse_class(&raw).map_err(|_| {
        AnalysisError::output(
            request.operation,
            "JADX class summary failed or was malformed; negative counts are not an empty class",
        )
    })?;
    if summary.full_name != class_name {
        return Err(input_failure(
            request.operation,
            "class_name",
            format!(
                "Exact class {class_name} resolved to {}; use the fully qualified class name from search_android_classes.",
                summary.full_name
            ),
        ));
    }
    if summary.method_count != summary.methods.len() as u64
        || summary.field_count != summary.fields.len() as u64
        || summary.inner_class_count != summary.inner_classes.len() as u64
    {
        return Err(AnalysisError::output(
            request.operation,
            "JADX class member counts do not match the returned inventory",
        ));
    }
    Ok(summary)
}

/// `inspectPackage(tools, loaded, engine)`.
fn inspect_package(
    tools: &mut dyn ToolCaller,
    operation: &str,
    loaded: &JadxLoad,
    engine: &Value,
) -> Result<Value, AnalysisError> {
    let app = protocol::parse_app(&tools.json("get_app_info", json!({}))?)
        .map_err(|error| protocol_output(operation, error))?;
    let manifest = protocol::normalize_text(&tools.text("get_android_manifest", json!({}))?);
    let empty_to_null = |value: &str| {
        if value.is_empty() {
            Value::Null
        } else {
            json!(value)
        }
    };
    Ok(json!({
        "engine": engine,
        "package_name": empty_to_null(&app.package),
        "version_name": empty_to_null(&app.version_name),
        "version_code": empty_to_null(&app.version_code),
        "min_sdk": empty_to_null(&app.min_sdk),
        "target_sdk": empty_to_null(&app.target_sdk),
        "permissions": app.permissions,
        "manifest": manifest.to_value(),
        "class_count": loaded.class_count,
        "resource_count": loaded.resource_count,
        "signature_verification": "not_performed",
    }))
}

/// `searchClasses(tools, request, loaded, engine)`.
fn search_classes(
    tools: &mut dyn ToolCaller,
    request: &AndroidRequest,
    loaded: &JadxLoad,
    engine: &Value,
) -> Result<Value, AnalysisError> {
    let query = request.query.clone().unwrap_or_default();
    let mut matches: Vec<String> = Vec::new();
    let page_size: u64 = 4096;
    let mut offset: u64 = 0;
    loop {
        let page = protocol::parse_class_page(&tools.json(
            "list_classes",
            json!({ "query": query, "offset": offset, "limit": page_size }),
        )?)
        .map_err(|error| protocol_output(request.operation, error))?;
        let identity_changed = page.total_classes != loaded.class_count
            || page.offset != offset
            || page.limit != page_size
            || page.next_offset < offset
            || page.next_offset > loaded.class_count
            || page.items.len() as u64 > page_size
            || page.items.len() as u64 > page.next_offset - offset
            || (query.is_empty() && page.items.len() as u64 != page.next_offset - offset)
            || page.items.iter().any(|name| !name.contains(&query));
        if identity_changed {
            return Err(AnalysisError::output(
                request.operation,
                "JADX class pagination changed identity or counts",
            ));
        }
        let incomplete = (offset < loaded.class_count && page.next_offset == offset)
            || (page.next_offset < loaded.class_count && page.items.len() as u64 != page_size);
        if incomplete {
            return Err(AnalysisError::output(
                request.operation,
                "JADX class pagination is incomplete",
            ));
        }
        matches.extend(page.items.iter().cloned());
        offset = page.next_offset;
        if offset >= loaded.class_count {
            break;
        }
    }
    // Occurrence counts in first-seen order (serde_json preserve_order keeps
    // insertion order, matching the TS Map iteration used for duplicate_names).
    let mut occurrences: Map<String, Value> = Map::new();
    for name in &matches {
        let count = occurrences.get(name).and_then(Value::as_u64).unwrap_or(0) + 1;
        occurrences.insert(name.clone(), json!(count));
    }
    let duplicate_names: Vec<Value> = occurrences
        .iter()
        .filter_map(|(name, count)| {
            let count = count.as_u64().unwrap_or(0);
            if count > 1 {
                Some(json!({ "name": name, "occurrences": count }))
            } else {
                None
            }
        })
        .collect();
    Ok(json!({
        "engine": engine,
        "query": query,
        "total_classes": loaded.class_count,
        "matches": matches,
        "duplicate_names": duplicate_names,
        "coverage": "complete",
    }))
}

/// `matchingMethods(summary, request)`.
fn matching_methods<'a>(
    summary: &'a JadxClass,
    request: &AndroidRequest,
    normalized: &'a [NormalizedMethod],
) -> Result<Vec<&'a NormalizedMethod>, AnalysisError> {
    let candidates: Vec<&NormalizedMethod> = match &request.method_name {
        Some(method_name) => normalized
            .iter()
            .filter(|method| &method.name == method_name)
            .collect(),
        None => Vec::new(),
    };
    if let Some(method_name) = &request.method_name
        && candidates.is_empty()
    {
        return Err(input_failure(
            request.operation,
            "method_name",
            format!(
                "Method {}.{method_name} was not found; inspect_android_class lists available methods.",
                summary.full_name
            ),
        ));
    }
    Ok(candidates)
}

fn overload_choices(candidates: &[&NormalizedMethod]) -> String {
    candidates
        .iter()
        .map(|method| format!("{}: {}", method.overload_index, method.reported_signature))
        .collect::<Vec<_>>()
        .join("; ")
}

/// `inspectMethod(tools, request, summary, engine)`.
fn inspect_method(
    tools: &mut dyn ToolCaller,
    request: &AndroidRequest,
    summary: &JadxClass,
    engine: &Value,
) -> Result<Value, AnalysisError> {
    let normalized = methods_of(summary);
    let candidates = matching_methods(summary, request, &normalized)?;
    if candidates.len() > 1 && request.overload_index.is_none() {
        return Err(input_failure(
            request.operation,
            "overload_index",
            format!(
                "Select one of {} overloads: {}",
                candidates.len(),
                overload_choices(&candidates)
            ),
        ));
    }
    let index = request.overload_index.unwrap_or(0);
    let Some(selected) = candidates.get(index as usize).copied() else {
        return Err(input_failure(
            request.operation,
            "overload_index",
            format!(
                "Index {index} is outside the {} matching overloads.",
                candidates.len()
            ),
        ));
    };
    let method_name = request.method_name.clone().unwrap_or_default();
    let body = protocol::parse_method_body(&tools.json(
        "get_method_body",
        json!({
            "class_name": summary.full_name,
            "method_name": method_name,
            "overload_index": index,
            "smali_fallback": true,
        }),
    )?)
    .map_err(|error| protocol_output(request.operation, error))?;
    if body.class_name != summary.full_name
        || body.method_name != method_name
        || body.overload_index != index
        || body.overload_count != candidates.len() as u64
        || body.dex_descriptor != selected.dex_descriptor
    {
        return Err(AnalysisError::output(
            request.operation,
            "JADX returned a different method or overload inventory",
        ));
    }
    let source = protocol::normalize_text(&body.body);
    Ok(json!({
        "engine": engine,
        "class_name": summary.full_name,
        "method": method_value(selected),
        "overload_count": candidates.len(),
        "representation": body.mode,
        "body_status": if body.body.is_empty() { "not_available" } else { "available" },
        "fell_back": body.fell_back,
        "markers": body.markers,
        "source": source.to_value(),
    }))
}

/// `traceReferences(tools, request, summary, engine)`.
fn trace_references(
    tools: &mut dyn ToolCaller,
    request: &AndroidRequest,
    summary: &JadxClass,
    engine: &Value,
) -> Result<Value, AnalysisError> {
    let normalized = methods_of(summary);
    let candidates = matching_methods(summary, request, &normalized)?;
    if request.method_name.is_none() && request.overload_index.is_some() {
        return Err(input_failure(
            request.operation,
            "overload_index",
            "Method name is required for an overload index.",
        ));
    }
    if candidates.len() > 1 && request.overload_index.is_none() {
        return Err(input_failure(
            request.operation,
            "overload_index",
            format!(
                "Select one of {} overloads: {}",
                candidates.len(),
                overload_choices(&candidates)
            ),
        ));
    }
    let index = request.overload_index.unwrap_or(0);
    let selected = match &request.method_name {
        None => None,
        Some(_) => candidates.get(index as usize).copied(),
    };
    if request.method_name.is_some() && selected.is_none() {
        return Err(input_failure(
            request.operation,
            "overload_index",
            format!(
                "Index {index} is outside the {} matching overloads.",
                candidates.len()
            ),
        ));
    }
    let expected_target = match &request.method_name {
        None => summary.full_name.clone(),
        Some(method_name) => format!("{}.{method_name}", summary.full_name),
    };
    let (tool_name, arguments) = match &request.method_name {
        None => (
            "get_xrefs_to_class",
            json!({
                "class_name": summary.full_name,
                "limit": 2_147_483_647u64,
                "resolve_line": false,
            }),
        ),
        Some(method_name) => (
            "get_xrefs_to_method",
            json!({
                "class_name": summary.full_name,
                "method_name": method_name,
                "overload_index": index,
                "limit": 2_147_483_647u64,
                "resolve_line": false,
            }),
        ),
    };
    let xrefs = protocol::parse_xrefs(&tools.json(tool_name, arguments)?)
        .map_err(|error| protocol_output(request.operation, error))?;
    let selector_mismatch = selected.is_some_and(|method| {
        xrefs.overload_index != Some(index)
            || xrefs.reported_signature.as_deref() != Some(method.reported_signature.as_str())
    });
    if xrefs.target != expected_target
        || selector_mismatch
        || xrefs.total != xrefs.count
        || xrefs.count != xrefs.items.len() as u64
    {
        return Err(AnalysisError::output(
            request.operation,
            "JADX references are incomplete or refer to another target",
        ));
    }
    let references: Vec<Value> = xrefs
        .items
        .iter()
        .map(|reference| {
            json!({
                "kind": reference.kind,
                "name": reference.name,
                "reported_full_name": reference.full_name,
                "containing_class": reference.containing_class,
                "top_class": reference.top_class,
                "source_line": Value::Null,
                "dex_offset": Value::Null,
                "direct_invokes": reference
                    .direct_invokes
                    .as_ref()
                    .map(|invokes| Value::Array(invokes.iter().map(protocol::DirectInvoke::to_value).collect()))
                    .unwrap_or(Value::Null),
                "direct_invokes_exhaustive": reference
                    .direct_invokes_exhaustive
                    .map(Value::Bool)
                    .unwrap_or(Value::Null),
            })
        })
        .collect();
    Ok(json!({
        "engine": engine,
        "class_name": summary.full_name,
        "method_name": request.method_name.clone().map(Value::String).unwrap_or(Value::Null),
        "overload_index": selected.map(|method| json!(method.overload_index)).unwrap_or(Value::Null),
        "reported_signature": selected.map(|method| json!(method.reported_signature)).unwrap_or(Value::Null),
        "dex_descriptor": selected.map(|method| json!(method.dex_descriptor)).unwrap_or(Value::Null),
        "total": xrefs.total,
        "references": references,
        "coverage": "complete",
        "reference_unit": "using_node",
    }))
}

/// `inspectClass`: normalize one class summary.
fn inspect_class(summary: &JadxClass, engine: &Value) -> Value {
    let methods: Vec<Value> = methods_of(summary).iter().map(method_value).collect();
    let fields: Vec<Value> = summary
        .fields
        .iter()
        .map(|field| json!({ "name": field.name, "reported_type": field.field_type }))
        .collect();
    json!({
        "engine": engine,
        "class_name": summary.full_name,
        "methods": methods,
        "fields": fields,
        "inner_classes": summary.inner_classes,
    })
}

/// `analyzeJadxRequest(tools, request, loaded, engine)`.
pub fn analyze_jadx_request(
    tools: &mut dyn ToolCaller,
    request: &AndroidRequest,
    loaded: &JadxLoad,
    engine: &Value,
) -> Result<Value, AnalysisError> {
    match request.operation {
        "inspect_android_package" => inspect_package(tools, request.operation, loaded, engine),
        "search_android_classes" => search_classes(tools, request, loaded, engine),
        other => {
            let class_name = request.class_name.clone().unwrap_or_default();
            let summary = class_summary(tools, request, &class_name)?;
            match other {
                "inspect_android_class" => Ok(inspect_class(&summary, engine)),
                "inspect_android_method" => inspect_method(tools, request, &summary, engine),
                _ => trace_references(tools, request, &summary, engine),
            }
        }
    }
}
