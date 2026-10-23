//! Authenticated, non-rerunning views over retained Interface Builder Evidence.

use rea_core::{
    canonical_json,
    evidence::is_sha256,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "decode_interface_builder";
const PAGE_SIZE: usize = 64;

enum RequestedView {
    Summary,
    Page {
        collection: Collection,
        document: Option<String>,
        offset: usize,
        limit: usize,
        normalized: Value,
    },
}

struct TargetBinding {
    sha256: String,
    path: String,
}

#[derive(Clone, Copy)]
enum Collection {
    Documents,
    Nodes,
    Edges,
    Coverage,
}

impl Collection {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "documents" => Some(Self::Documents),
            "nodes" => Some(Self::Nodes),
            "edges" => Some(Self::Edges),
            "coverage" => Some(Self::Coverage),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Documents => "documents",
            Self::Nodes => "nodes",
            Self::Edges => "edges",
            Self::Coverage => "coverage",
        }
    }
}

/// Project a summary or stable page without reopening the app bundle.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(&error.to_string()))?;
    project_record(&record, parent, view)
}

/// Project a view from an Evidence record that its caller has already authenticated.
pub fn project_record(
    record: &EvidenceRecord,
    parent: &Value,
    view: &Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "Interface Builder view requires decode_interface_builder Evidence.",
        ));
    }

    let mut report: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(&format!(
                "Interface Builder normalized result is invalid: {error}"
            ))
        })?;
    let target = validate_parent(&record, &mut report)?;
    let requested = parse_view(view)?;
    let normalized_view = normalized_view(&requested);
    let limitations = merged_limitations(parent, &report)?;
    let body = match requested {
        RequestedView::Summary => summarize(&record, &report, &limitations, &target)?,
        requested_page @ RequestedView::Page { .. } => {
            page(&record, &report, requested_page, &limitations, &target)?
        }
    };

    create_view_evidence(&record, normalized_view, body)
}

fn validate_parent(record: &EvidenceRecord, report: &mut Value) -> Result<TargetBinding, Failure> {
    validate_report_schema(report)?;

    let target_sha256 = report["target_sha256"]
        .as_str()
        .filter(|digest| is_sha256(digest))
        .ok_or_else(|| invalid("Interface Builder report has no valid target SHA-256."))?;
    if report["graph"]["target_sha256"].as_str() != Some(target_sha256) {
        return Err(invalid(
            "Interface Builder report and graph must identify the same target SHA-256.",
        ));
    }

    let subject: Value = serde_json::from_str(record.subject().get()).map_err(|error| {
        invalid(&format!(
            "Interface Builder Evidence subject is invalid: {error}"
        ))
    })?;
    let path = if subject.is_null() {
        String::new()
    } else {
        if subject["digest"]["sha256"].as_str() != Some(target_sha256) {
            return Err(invalid(
                "Interface Builder parent subject and graph must identify the same target SHA-256.",
            ));
        }
        subject["local_path"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };

    for field in ["documents", "nodes", "edges", "coverage"] {
        let rows = if field == "documents" {
            report[field].as_array()
        } else {
            report["graph"][field].as_array()
        };
        if rows.is_none() {
            return Err(invalid(&format!(
                "Interface Builder report is missing its {field} collection."
            )));
        }
    }
    if report["graph"]["truncated"].as_bool().is_none() {
        return Err(invalid(
            "Interface Builder report has no graph truncation state.",
        ));
    }
    Ok(TargetBinding {
        sha256: target_sha256.to_owned(),
        path,
    })
}

fn validate_report_schema(report: &mut Value) -> Result<(), Failure> {
    require_exact_fields(
        report,
        &["target_sha256", "documents", "graph", "limitations"],
        "Interface Builder report",
    )?;
    let target_sha256 = required_string(report, "target_sha256", "report", true)?;
    if !is_sha256(target_sha256) {
        return Err(invalid("Interface Builder target_sha256 is invalid."));
    }

    let documents = required_array(report, "documents", "report")?;
    if documents.len() > 64 {
        return Err(invalid(
            "Interface Builder report contains more than 64 documents.",
        ));
    }
    for document in documents {
        validate_document(document)?;
    }

    string_array(report.get("limitations"), "report limitations")?;
    validate_graph(&report["graph"])?;
    apply_evidence_defaults(report);
    Ok(())
}

fn apply_evidence_defaults(report: &mut Value) {
    for collection in ["nodes", "edges"] {
        let Some(rows) = report["graph"][collection].as_array_mut() else {
            continue;
        };
        for row in rows {
            let Some(evidence_rows) = row["evidence"].as_array_mut() else {
                continue;
            };
            for evidence in evidence_rows {
                if let Some(fields) = evidence.as_object_mut() {
                    fields.entry("artifact_path").or_insert(Value::Null);
                    fields.entry("artifact_sha256").or_insert(Value::Null);
                }
            }
        }
    }
}

fn validate_document(document: &Value) -> Result<(), Failure> {
    require_exact_fields(
        document,
        &[
            "relative_path",
            "archive_sha256",
            "document_kind",
            "object_count",
            "connection_count",
            "hierarchy_complete",
        ],
        "Interface Builder document",
    )?;
    required_string(document, "relative_path", "document", true)?;
    let archive_sha256 = required_string(document, "archive_sha256", "document", true)?;
    if !is_sha256(archive_sha256) {
        return Err(invalid(
            "Interface Builder document archive_sha256 is invalid.",
        ));
    }
    if !matches!(
        document["document_kind"].as_str(),
        Some("nib" | "storyboard_scene")
    ) {
        return Err(invalid("Interface Builder document_kind is unsupported."));
    }
    nonnegative_integer(&document["object_count"], "document object_count")?;
    nonnegative_integer(&document["connection_count"], "document connection_count")?;
    if !document["hierarchy_complete"].is_boolean() {
        return Err(invalid(
            "Interface Builder document hierarchy_complete must be boolean.",
        ));
    }
    Ok(())
}

fn validate_graph(graph: &Value) -> Result<(), Failure> {
    require_exact_fields(
        graph,
        &[
            "target_sha256",
            "provider",
            "nodes",
            "edges",
            "coverage",
            "truncated",
        ],
        "Interface Builder graph",
    )?;
    let target_sha256 = required_string(graph, "target_sha256", "graph", true)?;
    if !is_sha256(target_sha256) {
        return Err(invalid("Interface Builder graph target_sha256 is invalid."));
    }
    validate_graph_provider(&graph["provider"])?;
    for node in required_array(graph, "nodes", "graph")? {
        validate_node(node)?;
    }
    for edge in required_array(graph, "edges", "graph")? {
        validate_edge(edge)?;
    }
    for row in required_array(graph, "coverage", "graph")? {
        validate_coverage_row(row)?;
    }
    if !graph["truncated"].is_boolean() {
        return Err(invalid(
            "Interface Builder graph truncated must be boolean.",
        ));
    }
    Ok(())
}

fn validate_graph_provider(provider: &Value) -> Result<(), Failure> {
    require_exact_fields(
        provider,
        &["id", "version", "tool_version"],
        "graph provider",
    )?;
    required_string(provider, "id", "graph provider", true)?;
    match &provider["version"] {
        Value::Null => {}
        Value::String(_) => {}
        _ => {
            return Err(invalid(
                "Interface Builder graph provider version is invalid.",
            ));
        }
    }
    required_string(provider, "tool_version", "graph provider", true)?;
    Ok(())
}

fn validate_node(node: &Value) -> Result<(), Failure> {
    require_exact_fields(
        node,
        &["id", "kind", "name", "location", "attributes", "evidence"],
        "Interface Builder node",
    )?;
    required_string(node, "id", "node", true)?;
    let kind = required_string(node, "kind", "node", true)?;
    if !matches!(
        kind,
        "storyboard"
            | "scene"
            | "view_controller"
            | "view"
            | "control"
            | "constraint"
            | "layout_guide"
            | "resource"
            | "placeholder"
            | "external_object"
            | "outlet"
            | "action"
            | "segue"
            | "objc_class"
            | "objc_selector"
            | "swift_declaration"
            | "swift_requirement"
            | "dispatch_table"
            | "dispatch_slot"
            | "thunk"
            | "function"
            | "state_value"
            | "global_value"
            | "field"
            | "branch_condition"
            | "sink"
            | "unknown"
    ) {
        return Err(invalid("Interface Builder node kind is unsupported."));
    }
    required_string(node, "name", "node", true)?;
    validate_nullable_location(&node["location"], "node location")?;
    if !node["attributes"].is_object() {
        return Err(invalid(
            "Interface Builder node attributes must be an object.",
        ));
    }
    validate_evidence_array(&node["evidence"], false)
}

fn validate_edge(edge: &Value) -> Result<(), Failure> {
    let resolution = edge
        .get("resolution")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Interface Builder edge resolution is required."))?;
    if resolution == "unresolved" {
        require_exact_fields(
            edge,
            &[
                "id",
                "from",
                "to",
                "relation",
                "resolution",
                "reason",
                "evidence",
                "limitations",
            ],
            "unresolved Interface Builder edge",
        )?;
        if !edge["to"].is_null() {
            return Err(invalid(
                "Unresolved Interface Builder edges must have a null destination.",
            ));
        }
        required_string(edge, "reason", "unresolved edge", true)?;
        validate_evidence_array(&edge["evidence"], false)?;
    } else {
        require_exact_fields(
            edge,
            &[
                "id",
                "from",
                "to",
                "relation",
                "resolution",
                "evidence",
                "limitations",
            ],
            "resolved Interface Builder edge",
        )?;
        required_string(edge, "to", "edge", true)?;
        if !matches!(
            resolution,
            "observed" | "inferred" | "resolved" | "ambiguous"
        ) {
            return Err(invalid("Interface Builder edge resolution is unsupported."));
        }
        validate_evidence_array(&edge["evidence"], true)?;
    }
    required_string(edge, "id", "edge", true)?;
    required_string(edge, "from", "edge", true)?;
    let relation = required_string(edge, "relation", "edge", true)?;
    if !matches!(
        relation,
        "contains"
            | "outlet_to"
            | "target_action"
            | "segue_to"
            | "objc_dispatch"
            | "swift_witness_dispatch"
            | "swift_vtable_dispatch"
            | "thunk_to"
            | "direct_call"
            | "indirect_call"
            | "provider_call"
            | "reads"
            | "writes"
            | "flows_to"
            | "controls"
    ) {
        return Err(invalid("Interface Builder edge relation is unsupported."));
    }
    string_array(edge.get("limitations"), "edge limitations").map(|_| ())
}

fn validate_coverage_row(row: &Value) -> Result<(), Failure> {
    require_exact_fields(
        row,
        &["facet", "status", "reason", "examined", "omitted"],
        "Interface Builder coverage row",
    )?;
    required_string(row, "facet", "coverage row", true)?;
    if !matches!(
        row["status"].as_str(),
        Some("complete" | "partial" | "unsupported" | "not_requested")
    ) {
        return Err(invalid("Interface Builder coverage status is unsupported."));
    }
    if !row["reason"].is_null() && !row["reason"].is_string() {
        return Err(invalid("Interface Builder coverage reason is invalid."));
    }
    nonnegative_integer(&row["examined"], "coverage examined")?;
    nonnegative_integer(&row["omitted"], "coverage omitted")?;
    Ok(())
}

fn validate_evidence_array(value: &Value, require_one: bool) -> Result<(), Failure> {
    let evidence = value
        .as_array()
        .ok_or_else(|| invalid("Interface Builder row evidence must be an array."))?;
    if require_one && evidence.is_empty() {
        return Err(invalid(
            "Resolved Interface Builder edges require evidence.",
        ));
    }
    for item in evidence {
        validate_evidence(item)?;
    }
    Ok(())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    require_fields(
        evidence,
        &["kind", "description", "location"],
        &[
            "provider",
            "reported_address",
            "call_reference",
            "artifact_path",
            "artifact_sha256",
        ],
        "Interface Builder evidence",
    )?;
    validate_evidence_kind_and_description(evidence)?;
    validate_required_location(&evidence["location"], "evidence location")?;
    validate_evidence_provider(evidence.get("provider"))?;
    validate_optional_reported_address(evidence.get("reported_address"))?;
    validate_optional_call_reference(evidence.get("call_reference"))?;
    validate_evidence_artifact_identity(evidence)?;
    Ok(())
}

fn validate_evidence_kind_and_description(evidence: &Value) -> Result<(), Failure> {
    if !matches!(
        evidence["kind"].as_str(),
        Some(
            "binary_metadata"
                | "interface_builder_resource"
                | "symbol"
                | "reference"
                | "decompiler"
        )
    ) {
        return Err(invalid("Interface Builder evidence kind is unsupported."));
    }
    required_string(evidence, "description", "evidence", true)?;
    Ok(())
}

fn validate_evidence_provider(provider: Option<&Value>) -> Result<(), Failure> {
    let Some(provider) = provider else {
        return Ok(());
    };
    require_exact_fields(provider, &["id", "name", "version"], "evidence provider")?;
    required_string(provider, "id", "evidence provider", true)?;
    required_string(provider, "name", "evidence provider", true)?;
    if !provider["version"].is_null() && !provider["version"].is_string() {
        return Err(invalid(
            "Interface Builder evidence provider version is invalid.",
        ));
    }
    Ok(())
}

fn validate_optional_reported_address(value: Option<&Value>) -> Result<(), Failure> {
    if value.is_some_and(|value| !value.is_string()) {
        return Err(invalid(
            "Interface Builder reported_address must be a string.",
        ));
    }
    Ok(())
}

fn validate_optional_call_reference(value: Option<&Value>) -> Result<(), Failure> {
    let Some(reference) = value else {
        return Ok(());
    };
    require_exact_fields(
        reference,
        &[
            "classification",
            "provider_type",
            "provenance",
            "source_address",
            "target_address",
        ],
        "Interface Builder call reference",
    )?;
    if !matches!(
        reference["classification"].as_str(),
        Some("none" | "unknown" | "direct" | "objective_c")
    ) || !is_integer_number(&reference["provider_type"])
    {
        return Err(invalid("Interface Builder call_reference is invalid."));
    }
    required_string(reference, "provenance", "call reference", true)?;
    if !reference["source_address"].is_string() || !reference["target_address"].is_string() {
        return Err(invalid(
            "Interface Builder call_reference endpoints are invalid.",
        ));
    }
    Ok(())
}

fn validate_evidence_artifact_identity(evidence: &Value) -> Result<(), Failure> {
    if evidence.get("artifact_path").is_some_and(|value| {
        !(value.is_null() || value.as_str().is_some_and(|path| !path.is_empty()))
    }) {
        return Err(invalid(
            "Interface Builder evidence artifact_path is invalid.",
        ));
    }
    if let Some(digest) = evidence.get("artifact_sha256") {
        if !digest.is_null() && !digest.as_str().is_some_and(is_sha256) {
            return Err(invalid(
                "Interface Builder evidence artifact_sha256 is invalid.",
            ));
        }
    }
    Ok(())
}

fn is_integer_number(value: &Value) -> bool {
    value.as_f64().is_some_and(|number| {
        number.is_finite() && number.fract() == 0.0 && number.abs() <= 9_007_199_254_740_991.0
    })
}

fn validate_nullable_location(value: &Value, field: &str) -> Result<(), Failure> {
    if value.is_null() {
        return Ok(());
    }

    validate_required_location(value, field)
}

fn validate_required_location(value: &Value, field: &str) -> Result<(), Failure> {
    require_exact_fields(value, &["address", "file_offset"], field)?;
    if !value["address"].is_null() && !value["address"].is_string() {
        return Err(invalid(&format!(
            "Interface Builder {field} address is invalid."
        )));
    }
    if !value["file_offset"].is_null() {
        nonnegative_integer(&value["file_offset"], field)?;
    }
    Ok(())
}

fn required_array<'a>(
    value: &'a Value,
    field: &str,
    owner: &str,
) -> Result<&'a Vec<Value>, Failure> {
    value.get(field).and_then(Value::as_array).ok_or_else(|| {
        invalid(&format!(
            "Interface Builder {owner} {field} must be an array."
        ))
    })
}

fn required_string<'a>(
    value: &'a Value,
    field: &str,
    owner: &str,
    nonempty: bool,
) -> Result<&'a str, Failure> {
    let text = value.get(field).and_then(Value::as_str).ok_or_else(|| {
        invalid(&format!(
            "Interface Builder {owner} {field} must be a string."
        ))
    })?;
    if nonempty && text.is_empty() {
        return Err(invalid(&format!(
            "Interface Builder {owner} {field} must not be empty."
        )));
    }
    Ok(text)
}

fn nonnegative_integer(value: &Value, field: &str) -> Result<(), Failure> {
    let Some(number) = value.as_f64() else {
        return Err(invalid(&format!(
            "Interface Builder {field} must be a non-negative integer."
        )));
    };
    if !number.is_finite()
        || number < 0.0
        || number.fract() != 0.0
        || number > 9_007_199_254_740_991.0
    {
        return Err(invalid(&format!(
            "Interface Builder {field} must be a non-negative integer."
        )));
    }
    Ok(())
}

fn require_exact_fields(value: &Value, fields: &[&str], owner: &str) -> Result<(), Failure> {
    require_fields(value, fields, &[], owner)
}

fn require_fields(
    value: &Value,
    required: &[&str],
    optional: &[&str],
    owner: &str,
) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("Interface Builder {owner} must be an object.")))?;
    if required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "Interface Builder {owner} does not match its schema."
        )));
    }
    Ok(())
}

fn parse_view(view: &Value) -> Result<RequestedView, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("Interface Builder view must be an object."))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Interface Builder view kind is required."))?;

    match kind {
        "summary" => {
            reject_unknown_fields(object, &["kind"])?;
            Ok(RequestedView::Summary)
        }
        "interface-builder" => parse_page_view(object),
        _ => Err(invalid(
            "Interface Builder Evidence supports summary and interface-builder views.",
        )),
    }
}

fn parse_page_view(object: &Map<String, Value>) -> Result<RequestedView, Failure> {
    let collection_name = object
        .get("collection")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Interface Builder collection is required."))?;
    let collection = Collection::parse(collection_name)
        .ok_or_else(|| invalid("Unknown Interface Builder collection."))?;
    let allow_document = matches!(collection, Collection::Nodes | Collection::Edges);
    let allowed = if allow_document {
        &["kind", "collection", "document", "offset", "limit"][..]
    } else {
        &["kind", "collection", "offset", "limit"][..]
    };
    reject_unknown_fields(object, allowed)?;

    let document = match object.get("document") {
        None => None,
        Some(Value::String(value)) if !value.is_empty() && allow_document => Some(value.clone()),
        Some(Value::String(_)) if allow_document => {
            return Err(invalid("Interface Builder document must not be empty."));
        }
        Some(_) => {
            return Err(invalid(
                "Interface Builder document is only valid for nodes or edges.",
            ));
        }
    };
    let offset = page_number(object.get("offset"), 0, "offset", false)?;
    let limit = page_number(object.get("limit"), PAGE_SIZE, "limit", true)?;
    let mut normalized = json!({
        "kind": "interface-builder",
        "collection": collection.name(),
        "offset": offset,
        "limit": limit,
    });
    if let Some(document) = &document {
        normalized["document"] = json!(document);
    }

    Ok(RequestedView::Page {
        collection,
        document,
        offset,
        limit,
        normalized,
    })
}

fn page_number(
    value: Option<&Value>,
    default: usize,
    field: &str,
    must_be_positive: bool,
) -> Result<usize, Failure> {
    let Some(value) = value else {
        return Ok(default);
    };
    let number = parse_nonnegative_integer(value).ok_or_else(|| {
        invalid(&format!(
            "Interface Builder {field} must be a non-negative integer."
        ))
    })?;
    if must_be_positive && number == 0 {
        return Err(invalid(&format!(
            "Interface Builder {field} must be positive."
        )));
    }
    Ok(number)
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(
            "Interface Builder view contains an unsupported field.",
        ));
    }
    Ok(())
}

fn parse_nonnegative_integer(value: &Value) -> Option<usize> {
    if let Some(integer) = value.as_u64() {
        if integer > 9_007_199_254_740_991 {
            return None;
        }
        return usize::try_from(integer).ok();
    }
    let number = value.as_f64()?;
    if !number.is_finite()
        || number < 0.0
        || number.fract() != 0.0
        || number > 9_007_199_254_740_991.0
    {
        return None;
    }
    Some(number as usize)
}

fn normalized_view(requested: &RequestedView) -> Value {
    match requested {
        RequestedView::Summary => json!({"kind": "summary"}),
        RequestedView::Page { normalized, .. } => normalized.clone(),
    }
}

fn merged_limitations(parent: &Value, report: &Value) -> Result<Vec<String>, Failure> {
    let parent_limitations = string_array(parent.get("limitations"), "parent limitations")?;
    let report_limitations = string_array(report.get("limitations"), "report limitations")?;
    let mut limitations = parent_limitations;
    limitations.extend(report_limitations);
    limitations.sort();
    limitations.dedup();
    Ok(limitations)
}

fn string_array(value: Option<&Value>, field: &str) -> Result<Vec<String>, Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("Interface Builder {field} must be an array.")))?;
    values
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("Interface Builder {field} must contain strings.")))
        })
        .collect()
}

fn summarize(
    parent: &EvidenceRecord,
    report: &Value,
    limitations: &[String],
    target: &TargetBinding,
) -> Result<Value, Failure> {
    let documents = report["documents"]
        .as_array()
        .expect("validated collection");
    let graph = &report["graph"];
    let nodes = graph["nodes"].as_array().expect("validated collection");
    let edges = graph["edges"].as_array().expect("validated collection");
    let coverage = graph["coverage"].as_array().expect("validated collection");
    let available = documents.len() + nodes.len() + edges.len() + coverage.len();

    Ok(json!({
        "kind": "summary",
        "view": {"kind": "summary"},
        "parent_evidence_id": parent.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": parent.evidence_id().strip_prefix("ev_").unwrap_or(parent.evidence_id()),
        "artifact": artifact_binding(target),
        "limitations": limitations,
        "unknowns": interface_builder_unknowns(graph["truncated"].as_bool().unwrap_or(false)),
        "summary": {
            "target_sha256": target.sha256,
            "provider": graph["provider"],
            "documents": documents,
            "available_counts": {
                "nodes": nodes.len(),
                "edges": edges.len(),
                "coverage": coverage.len(),
            },
            "node_kinds": tally(nodes, "kind")?,
            "edge_relations": tally(edges, "relation")?,
            "coverage_statuses": tally(coverage, "status")?,
            "truncated": graph["truncated"],
            "limitation_count": limitations.len(),
        },
        "coverage": complete_coverage(available),
    }))
}

fn page(
    parent: &EvidenceRecord,
    report: &Value,
    requested: RequestedView,
    limitations: &[String],
    target: &TargetBinding,
) -> Result<Value, Failure> {
    let RequestedView::Page {
        collection,
        document,
        offset,
        limit,
        normalized,
    } = requested
    else {
        unreachable!("page receives only a page request")
    };
    let documents = report["documents"]
        .as_array()
        .expect("validated collection");
    let graph = &report["graph"];
    let source_rows = match collection {
        Collection::Documents => documents,
        Collection::Nodes => graph["nodes"].as_array().expect("validated collection"),
        Collection::Edges => graph["edges"].as_array().expect("validated collection"),
        Collection::Coverage => graph["coverage"].as_array().expect("validated collection"),
    };
    let rows = if let Some(document_path) = document.as_deref() {
        if !documents
            .iter()
            .any(|row| row["relative_path"].as_str() == Some(document_path))
        {
            return Err(invalid(
                "Select an exact documents[].relative_path from this decoded report.",
            ));
        }
        source_rows
            .iter()
            .filter(|row| evidence_names_document(row, document_path))
            .collect::<Vec<_>>()
    } else {
        source_rows.iter().collect::<Vec<_>>()
    };
    let total = rows.len();
    let start = offset.min(total);
    let end = start.saturating_add(limit).min(total);
    let items = rows[start..end]
        .iter()
        .map(|row| (*row).clone())
        .collect::<Vec<_>>();
    let source_truncated = graph["truncated"]
        .as_bool()
        .expect("validated truncation state");

    Ok(json!({
        "kind": "interface-builder",
        "view": normalized,
        "items": items,
        "parent_evidence_id": parent.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": parent.evidence_id().strip_prefix("ev_").unwrap_or(parent.evidence_id()),
        "artifact": artifact_binding(target),
        "limitations": limitations,
        "unknowns": interface_builder_unknowns(source_truncated),
        "source_truncated": source_truncated,
        "coverage": page_coverage(offset, end - start, total),
    }))
}

fn evidence_names_document(row: &Value, document_path: &str) -> bool {
    row["evidence"].as_array().is_some_and(|evidence| {
        evidence
            .iter()
            .any(|item| item["artifact_path"] == document_path)
    })
}

fn artifact_binding(target: &TargetBinding) -> Value {
    json!({
        "path": target.path,
        "sha256": target.sha256,
    })
}

fn interface_builder_unknowns(source_truncated: bool) -> Vec<String> {
    let mut unknowns = vec![
        "Rows describe recognized archive objects and connections only; unrecognized classes, fields and runtime-created UI remain unknown.".to_owned(),
    ];
    if source_truncated {
        unknowns.push(
            "The decoded graph is incomplete (see coverage and limitations for the cause); page exhaustion does not establish absence of undecoded objects or connections.".to_owned(),
        );
    }
    unknowns
}

fn tally(rows: &[Value], field: &str) -> Result<BTreeMap<String, usize>, Failure> {
    let mut counts = BTreeMap::new();
    for row in rows {
        let label = row
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(&format!("Interface Builder {field} value is missing.")))?;
        *counts.entry(label.to_owned()).or_insert(0usize) += 1;
    }
    Ok(counts)
}

fn complete_coverage(total: usize) -> Value {
    json!({
        "status": "complete-within-view",
        "examined": total,
        "total": total,
        "next_offset": null,
        "exhausted": true,
    })
}

fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({
        "status": if examined == 0 { "empty" } else { "page" },
        "examined": examined,
        "total": total,
        "next_offset": if exhausted { Value::Null } else { json!(offset + examined) },
        "exhausted": exhausted,
    })
}

fn create_view_evidence(
    parent: &EvidenceRecord,
    view: Value,
    mut body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let view_digest = canonical_json::digest(&body).map_err(|error| invalid(&error.to_string()))?;
    body["view_digest"] = json!(view_digest);

    let subject: Value = serde_json::from_str(parent.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let authority: Value = serde_json::from_str(parent.authority().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let locations = body["artifact"]["path"]
        .as_str()
        .filter(|path| !path.is_empty())
        .map(|path| vec![json!({"kind":"artifact-path", "path":path})])
        .unwrap_or_default();
    let limitations = body["limitations"].clone();

    let unsigned = json!({
        "subject": subject,
        "provider": {"id":"rea-analysis-view","name":"REA analysis view projection","version":"1"},
        "analysis_profile": null,
        "predicate_type":"rea.analysis-view",
        "operation": OPERATION,
        "parameters":{"parent_evidence_id":parent.evidence_id(),"view":view},
        "raw_result":null,
        "normalized_result":body,
        "confidence":"derived",
        "authority":authority,
        "environment":null,
        "limitations":limitations,
        "relationship_coverage":null,
        "locations":locations,
        "evidence_links":[parent.evidence_id()],
    });
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
            .expect("validated Evidence is valid JSON"),
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::evidence::{NativeFormat, Subject};

    fn parent_evidence() -> Value {
        let target_sha256 = "a".repeat(64);
        let archive_sha256 = "b".repeat(64);
        let subject = Subject::new(
            "/tmp/Example.app",
            target_sha256.clone(),
            NativeFormat::Directory,
            None,
        )
        .expect("valid subject");
        let archive_evidence = || {
            json!([{
                "kind": "interface_builder_resource",
                "description": "Decoded from the selected nib archive.",
                "location": {"address": null, "file_offset": null},
                "artifact_path": "Resources/Main.nib",
                "artifact_sha256": archive_sha256,
            }])
        };
        let normalized = json!({
            "target_sha256": target_sha256,
            "documents": [{
                "relative_path": "Resources/Main.nib",
                "archive_sha256": archive_sha256,
                "document_kind": "nib",
                "object_count": 2,
                "connection_count": 1,
                "hierarchy_complete": true,
            }],
            "graph": {
                "target_sha256": target_sha256,
                "provider": {"id": "rea-artifact-graph", "version": "1", "tool_version": "rea-interface-builder/1"},
                "nodes": [
                    {"id": "ib:root", "kind": "scene", "name": "Scene", "location": {"address": null, "file_offset": null}, "attributes": {}, "evidence": archive_evidence()},
                    {"id": "ib:view", "kind": "view", "name": "Main View", "location": {"address": null, "file_offset": null}, "attributes": {}, "evidence": archive_evidence()},
                ],
                "edges": [{
                    "id": "ib:contains",
                    "from": "ib:root",
                    "to": "ib:view",
                    "relation": "contains",
                    "resolution": "observed",
                    "evidence": archive_evidence(),
                    "limitations": [],
                }],
                "coverage": [
                    {"facet": "objects", "status": "complete", "reason": null, "examined": 2, "omitted": 0},
                    {"facet": "connections", "status": "partial", "reason": "one unresolved connection", "examined": 1, "omitted": 1},
                ],
                "truncated": true,
            },
            "limitations": ["source limitation"],
        });
        let unsigned = json!({
            "subject": subject,
            "provider": {"id": "rea-artifact-graph", "name": "REA safe artifact graph provider", "version": "1"},
            "analysis_profile": null,
            "predicate_type": "rea.artifact-analysis",
            "operation": PARENT_OPERATION,
            "parameters": {"target_sha256": target_sha256},
            "raw_result": null,
            "normalized_result": normalized,
            "confidence": "observed",
            "authority": "analyst-inference",
            "environment": null,
            "limitations": ["parent limitation"],
            "relationship_coverage": null,
            "locations": [],
            "evidence_links": [],
        });
        let raw = serde_json::value::to_raw_value(&unsigned).expect("unsigned Evidence JSON");
        let record = EvidenceRecord::create_unsigned(&raw).expect("parent Evidence");
        serde_json::from_str(record.raw().get()).expect("parent Evidence value")
    }

    fn project_value(parent: &Value, view: Value) -> Value {
        let raw = project(parent, &view).expect("view projection");
        serde_json::from_str(raw.get()).expect("derived Evidence JSON")
    }

    fn reissue_evidence(mut evidence: Value) -> Value {
        evidence
            .as_object_mut()
            .expect("Evidence object")
            .remove("evidence_id");
        let raw = serde_json::value::to_raw_value(&evidence).expect("unsigned Evidence JSON");
        let record = EvidenceRecord::create_unsigned(&raw).expect("reissued Evidence");
        serde_json::from_str(record.raw().get()).expect("reissued Evidence JSON")
    }

    #[test]
    fn summary_reports_retained_counts_and_keeps_parent_link() {
        let parent = parent_evidence();
        let output = project_value(&parent, json!({"kind": "summary"}));
        let result = &output["normalized_result"];

        assert_eq!(result["kind"], "summary");
        assert_eq!(result["artifact"]["path"], "/tmp/Example.app");
        assert_eq!(result["artifact"]["sha256"], "a".repeat(64));
        assert_eq!(result["summary"]["available_counts"]["nodes"], 2);
        assert_eq!(result["summary"]["node_kinds"]["scene"], 1);
        assert_eq!(result["summary"]["node_kinds"]["view"], 1);
        assert_eq!(result["summary"]["limitation_count"], 2);
        assert_eq!(result["coverage"]["status"], "complete-within-view");
        assert_eq!(output["evidence_links"][0], parent["evidence_id"]);
        assert_eq!(output["provider"]["id"], "rea-analysis-view");
        assert_eq!(output["authority"], parent["authority"]);
        assert_eq!(output["limitations"], result["limitations"]);
        assert_eq!(output["subject"], parent["subject"]);
        assert_eq!(
            output["locations"][0],
            json!({"kind":"artifact-path", "path":"/tmp/Example.app"})
        );

        let mut projection = result.clone();
        let view_digest = projection["view_digest"]
            .as_str()
            .expect("view digest")
            .to_owned();
        projection
            .as_object_mut()
            .expect("view result object")
            .remove("view_digest");
        assert_eq!(canonical_json::digest(&projection).unwrap(), view_digest);
    }

    #[test]
    fn node_pages_filter_by_exact_archive_and_preserve_source_truncation() {
        let parent = parent_evidence();
        let output = project_value(
            &parent,
            json!({
                "kind": "interface-builder",
                "collection": "nodes",
                "document": "Resources/Main.nib",
                "offset": 1,
                "limit": 1,
            }),
        );
        let result = &output["normalized_result"];

        assert_eq!(result["items"].as_array().unwrap().len(), 1);
        assert_eq!(result["items"][0]["name"], "Main View");
        assert_eq!(result["source_truncated"], true);
        assert_eq!(result["unknowns"].as_array().unwrap().len(), 2);
        assert_eq!(result["coverage"]["total"], 2);
        assert_eq!(result["coverage"]["next_offset"], Value::Null);
        assert_eq!(result["view"]["limit"], 1);
    }

    #[test]
    fn document_edge_and_coverage_collections_are_paged_from_retained_rows() {
        let parent = parent_evidence();
        let cases = [
            (
                json!({"kind":"interface-builder", "collection":"documents", "limit":1}),
                "Resources/Main.nib",
            ),
            (
                json!({"kind":"interface-builder", "collection":"edges", "document":"Resources/Main.nib", "limit":1}),
                "ib:contains",
            ),
            (
                json!({"kind":"interface-builder", "collection":"coverage", "offset":1, "limit":1}),
                "connections",
            ),
        ];

        for (view, expected_label) in cases {
            let output = project_value(&parent, view);
            let items = output["normalized_result"]["items"]
                .as_array()
                .expect("page items");
            assert_eq!(items.len(), 1);

            let label = if items[0].get("relative_path").is_some() {
                items[0]["relative_path"].as_str().unwrap()
            } else if items[0].get("id").is_some() {
                items[0]["id"].as_str().unwrap()
            } else {
                items[0]["facet"].as_str().unwrap()
            };
            assert_eq!(label, expected_label);
        }
    }

    #[test]
    fn normalizes_default_nullable_evidence_fields_before_paging() {
        let mut parent = parent_evidence();
        let evidence = parent["normalized_result"]["graph"]["nodes"][0]["evidence"][0]
            .as_object_mut()
            .expect("evidence object");
        evidence.remove("artifact_path");
        evidence.remove("artifact_sha256");
        let parent = reissue_evidence(parent);

        let output = project_value(
            &parent,
            json!({"kind":"interface-builder", "collection":"nodes", "offset":0, "limit":1}),
        );
        let source_evidence = &output["normalized_result"]["items"][0]["evidence"][0];

        assert!(source_evidence["artifact_path"].is_null());
        assert!(source_evidence["artifact_sha256"].is_null());
    }

    #[test]
    fn view_rejects_unknown_fields_and_nonexistent_document_filters() {
        let parent = parent_evidence();
        assert!(project(&parent, &json!({"kind": "summary", "extra": true})).is_err());
        assert!(
            project(
                &parent,
                &json!({"kind": "interface-builder", "collection": "nodes", "document": "Missing.nib"}),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_parent_rows_that_do_not_match_the_typescript_report_schema() {
        let mut parent = parent_evidence();
        parent["normalized_result"]["graph"]["nodes"][0]["unexpected"] = json!(true);
        let parent = reissue_evidence(parent);

        assert!(project(&parent, &json!({"kind":"summary"})).is_err());
    }
}
