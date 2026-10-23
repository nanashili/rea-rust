//! Authenticated, bounded views over retained IL2CPP metadata Evidence.

use rea_core::{
    canonical_json,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "inspect_il2cpp_metadata";
const DEFAULT_LIMIT: usize = 64;
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

/// Project a summary or stable metadata page without reopening the artifact.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;
    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "IL2CPP metadata view requires inspect_il2cpp_metadata Evidence.",
        ));
    }

    let report: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(&format!(
                "IL2CPP metadata normalized result is invalid: {error}"
            ))
        })?;
    validate_report(&report)?;
    validate_subject(&record, &report)?;

    let request = parse_view(view, &report)?;
    let body = match request {
        Request::Summary { view } => summary(&record, &report, view)?,
        Request::Page {
            view,
            collection,
            indices,
            names,
            image_indices,
            namespaces,
            declaring_types,
            fields,
            offset,
            limit,
        } => page(
            &record,
            &report,
            view,
            collection,
            indices,
            names,
            image_indices,
            namespaces,
            declaring_types,
            fields,
            offset,
            limit,
        )?,
    };

    create_view_evidence(&record, body)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Collection {
    Sections,
    Images,
    Types,
    Methods,
    Fields,
    Properties,
    Events,
    Parameters,
}

impl Collection {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "sections" => Some(Self::Sections),
            "images" => Some(Self::Images),
            "types" => Some(Self::Types),
            "methods" => Some(Self::Methods),
            "fields" => Some(Self::Fields),
            "properties" => Some(Self::Properties),
            "events" => Some(Self::Events),
            "parameters" => Some(Self::Parameters),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Sections => "sections",
            Self::Images => "images",
            Self::Types => "types",
            Self::Methods => "methods",
            Self::Fields => "fields",
            Self::Properties => "properties",
            Self::Events => "events",
            Self::Parameters => "parameters",
        }
    }
}

enum Request {
    Summary {
        view: Value,
    },
    Page {
        view: Value,
        collection: Collection,
        indices: Option<Vec<usize>>,
        names: Option<BTreeSet<String>>,
        image_indices: Option<Vec<usize>>,
        namespaces: Option<BTreeSet<String>>,
        declaring_types: Option<BTreeSet<i64>>,
        fields: Option<BTreeSet<String>>,
        offset: usize,
        limit: usize,
    },
}

fn parse_view(view: &Value, report: &Value) -> Result<Request, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("IL2CPP metadata view must be an object."))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("IL2CPP metadata view kind is required."))?;

    if kind == "summary" {
        if object.len() != 1 {
            return Err(invalid("Summary view accepts only kind."));
        }
        return Ok(Request::Summary {
            view: json!({"kind": "summary"}),
        });
    }
    if kind != "il2cpp-metadata" {
        return Err(invalid(
            "IL2CPP metadata Evidence supports summary and il2cpp-metadata views.",
        ));
    }

    let collection_name = object
        .get("collection")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("IL2CPP metadata collection is required."))?;
    let collection = Collection::parse(collection_name)
        .ok_or_else(|| invalid("Unknown IL2CPP metadata collection."))?;
    let allowed = allowed_keys(collection);
    if object.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(invalid(
            "IL2CPP metadata view contains an unsupported field.",
        ));
    }

    let indices = parse_indices(object.get("indices"), "indices")?;
    let image_indices = parse_indices(object.get("image_indices"), "image_indices")?;
    let names = parse_strings(object.get("names"), "names")?;
    let namespaces = parse_strings(object.get("namespaces"), "namespaces")?;
    let declaring_types = parse_declaring_types(object.get("declaring_types"))?;
    let fields = parse_fields(object.get("fields"), collection)?;
    let offset = parse_nonnegative(object.get("offset"), "offset")?.unwrap_or(0);
    let limit = parse_nonnegative(object.get("limit"), "limit")?.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 {
        return Err(invalid("IL2CPP metadata view limit must be positive."));
    }
    if collection != Collection::Types && (image_indices.is_some() || namespaces.is_some()) {
        return Err(invalid("image_indices and namespaces apply only to types."));
    }
    if matches!(
        collection,
        Collection::Fields | Collection::Properties | Collection::Events | Collection::Parameters
    ) && names.is_some()
    {
        return Err(invalid(
            "names is unavailable for IL2CPP member collections because the retained rows contain name indices, not decoded names.",
        ));
    }
    if !matches!(
        collection,
        Collection::Types
            | Collection::Methods
            | Collection::Fields
            | Collection::Properties
            | Collection::Events
            | Collection::Parameters
    ) && declaring_types.is_some()
    {
        return Err(invalid(
            "declaring_types applies only to type, method, and member collections.",
        ));
    }
    let _ = report;

    Ok(Request::Page {
        view: normalized_page_view(
            object,
            collection,
            indices.as_deref(),
            names.as_ref(),
            image_indices.as_deref(),
            namespaces.as_ref(),
            declaring_types.as_ref(),
            fields.as_ref(),
            offset,
            limit,
        ),
        collection,
        indices,
        names,
        image_indices,
        namespaces,
        declaring_types,
        fields,
        offset,
        limit,
    })
}

fn allowed_keys(collection: Collection) -> BTreeSet<&'static str> {
    let mut keys = BTreeSet::from([
        "kind",
        "collection",
        "indices",
        "names",
        "offset",
        "limit",
        "fields",
    ]);
    match collection {
        Collection::Types => {
            keys.insert("image_indices");
            keys.insert("namespaces");
            keys.insert("declaring_types");
        }
        Collection::Methods => {
            keys.insert("declaring_types");
        }
        Collection::Fields
        | Collection::Properties
        | Collection::Events
        | Collection::Parameters => {
            keys.insert("declaring_types");
        }
        Collection::Sections | Collection::Images => {}
    }
    keys
}

fn parse_nonnegative(value: Option<&Value>, field: &str) -> Result<Option<usize>, Failure> {
    let Some(value) = value else { return Ok(None) };
    let number = value
        .as_u64()
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| invalid(&format!("{field} must be a nonnegative integer.")))?;
    Ok(Some(number))
}

fn parse_indices(value: Option<&Value>, field: &str) -> Result<Option<Vec<usize>>, Failure> {
    let Some(values) = optional_filter_array(value, field)? else {
        return Ok(None);
    };
    let mut result = values
        .iter()
        .map(|value| parse_nonnegative(Some(value), field).map(|number| number.unwrap()))
        .collect::<Result<Vec<_>, _>>()?;
    result.sort_unstable();
    result.dedup();
    Ok(Some(result))
}

fn parse_strings(value: Option<&Value>, field: &str) -> Result<Option<BTreeSet<String>>, Failure> {
    let Some(values) = optional_filter_array(value, field)? else {
        return Ok(None);
    };
    Ok(Some(
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid(&format!("{field} must contain strings.")))
            })
            .collect::<Result<BTreeSet<_>, _>>()?,
    ))
}

fn parse_declaring_types(value: Option<&Value>) -> Result<Option<BTreeSet<i64>>, Failure> {
    let Some(values) = optional_filter_array(value, "declaring_types")? else {
        return Ok(None);
    };
    Ok(Some(
        values
            .iter()
            .map(|value| {
                let number = value
                    .as_i64()
                    .filter(|number| *number >= -1)
                    .ok_or_else(|| invalid("declaring_types must contain integers >= -1."))?;
                Ok(number)
            })
            .collect::<Result<BTreeSet<_>, Failure>>()?,
    ))
}

fn parse_fields(
    value: Option<&Value>,
    collection: Collection,
) -> Result<Option<BTreeSet<String>>, Failure> {
    let Some(values) = optional_filter_array(value, "fields")? else {
        return Ok(None);
    };
    let allowed = row_fields(collection);
    Ok(Some(
        values
            .iter()
            .map(|value| {
                let field = value
                    .as_str()
                    .ok_or_else(|| invalid("fields must contain strings."))?;
                if !allowed.contains(field) {
                    return Err(invalid("fields contains an unsupported row field."));
                }
                Ok(field.to_owned())
            })
            .collect::<Result<BTreeSet<_>, Failure>>()?,
    ))
}

/// Optional filters preserve the distinction between omission and an explicit
/// value.  The source view schema treats omission as "no filter", while null
/// is invalid and an empty array deliberately selects no rows.
fn optional_filter_array<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> Result<Option<&'a [Value]>, Failure> {
    let Some(value) = value else {
        return Ok(None);
    };

    if value.is_null() {
        return Err(invalid(&format!(
            "{field} must be an array when provided; omit it to leave the filter unset."
        )));
    }

    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(&format!("{field} must be an array.")))
        .map(Some)
}

fn row_fields(collection: Collection) -> BTreeSet<&'static str> {
    match collection {
        Collection::Sections => BTreeSet::from(["index", "name", "offset", "size", "count"]),
        Collection::Images => BTreeSet::from(["index", "name", "type_start", "type_count"]),
        Collection::Types => BTreeSet::from([
            "index",
            "name",
            "namespace",
            "method_start",
            "method_count",
            "nested_type_start",
            "nested_type_count",
            "declaring_type",
            "generic_arity",
            "image_index",
            "image_name",
        ]),
        Collection::Methods => BTreeSet::from([
            "index",
            "metadata_index",
            "name",
            "declaring_type",
            "return_type",
            "return_parameter_token",
            "parameter_start",
            "generic_container",
            "generic_arity",
            "token",
            "flags",
            "iflags",
            "slot",
            "parameter_count",
            "image_index",
            "image_name",
        ]),
        Collection::Fields => BTreeSet::from([
            "index",
            "metadata_index",
            "name_index",
            "declaring_type",
            "type_index",
            "custom_attribute_index",
            "source_offset",
            "token",
        ]),
        Collection::Properties => BTreeSet::from([
            "index",
            "metadata_index",
            "name_index",
            "declaring_type",
            "getter_index",
            "setter_index",
            "attributes",
            "source_offset",
            "token",
        ]),
        Collection::Events => BTreeSet::from([
            "index",
            "metadata_index",
            "name_index",
            "declaring_type",
            "type_index",
            "add_index",
            "remove_index",
            "raise_index",
            "source_offset",
            "token",
        ]),
        Collection::Parameters => BTreeSet::from([
            "index",
            "metadata_index",
            "name_index",
            "declaring_type",
            "type_index",
            "custom_attribute_index",
            "flags",
            "declaring_method",
            "source_offset",
            "token",
        ]),
    }
}

fn normalized_page_view(
    object: &Map<String, Value>,
    collection: Collection,
    indices: Option<&[usize]>,
    names: Option<&BTreeSet<String>>,
    image_indices: Option<&[usize]>,
    namespaces: Option<&BTreeSet<String>>,
    declaring_types: Option<&BTreeSet<i64>>,
    fields: Option<&BTreeSet<String>>,
    offset: usize,
    limit: usize,
) -> Value {
    let mut result = Map::new();
    result.insert("kind".into(), json!("il2cpp-metadata"));
    result.insert("collection".into(), json!(collection.name()));
    for (key, value) in [
        ("indices", indices.map(|values| json!(values))),
        (
            "names",
            names.map(|values| json!(values.iter().collect::<Vec<_>>())),
        ),
        ("image_indices", image_indices.map(|values| json!(values))),
        (
            "namespaces",
            namespaces.map(|values| json!(values.iter().collect::<Vec<_>>())),
        ),
        (
            "declaring_types",
            declaring_types.map(|values| json!(values.iter().collect::<Vec<_>>())),
        ),
        (
            "fields",
            fields.map(|values| json!(values.iter().collect::<Vec<_>>())),
        ),
    ] {
        if let Some(value) = value {
            result.insert(key.into(), value);
        }
    }
    result.insert("offset".into(), json!(offset));
    result.insert("limit".into(), json!(limit));
    let _ = object;
    Value::Object(result)
}

fn validate_report(report: &Value) -> Result<(), Failure> {
    for field in [
        "artifact",
        "magic",
        "metadata_version",
        "index_widths",
        "sections",
        "images",
        "types",
        "methods",
        "limitations",
    ] {
        if !report.get(field).is_some() {
            return Err(invalid(
                "IL2CPP metadata report is missing a required field.",
            ));
        }
    }
    if report["artifact"]["path"].as_str().is_none()
        || report["artifact"]["sha256"].as_str().is_none()
        || report["artifact"]["bytes"].as_u64().is_none()
    {
        return Err(invalid("IL2CPP metadata artifact identity is invalid."));
    }
    if report["magic"].as_u64() != Some(0xfab11baf) {
        return Err(invalid("IL2CPP metadata magic is invalid."));
    }
    if !matches!(report["metadata_version"].as_i64(), Some(29 | 31 | 39)) {
        return Err(invalid("IL2CPP metadata version is unsupported."));
    }
    validate_index_widths(&report["index_widths"])?;
    for collection in ["sections", "images", "types", "methods"] {
        if !report[collection].is_array() {
            return Err(invalid("IL2CPP metadata collections must be arrays."));
        }
    }
    for collection in ["fields", "properties", "events", "parameters"] {
        if let Some(value) = report.get(collection)
            && !value.is_array()
        {
            return Err(invalid(
                "IL2CPP metadata member collections must be arrays.",
            ));
        }
    }
    validate_member_collection(&report["fields"], "fields")?;
    validate_member_collection(&report["properties"], "properties")?;
    validate_member_collection(&report["events"], "events")?;
    validate_member_collection(&report["parameters"], "parameters")?;
    let artifact_bytes = report["artifact"]["bytes"]
        .as_u64()
        .ok_or_else(|| invalid("IL2CPP metadata artifact byte count is invalid."))?;
    let sections = report["sections"]
        .as_array()
        .ok_or_else(|| invalid("IL2CPP metadata sections must be an array."))?;
    if sections.len() != SECTION_NAMES.len() {
        return Err(invalid(
            "IL2CPP metadata sections must contain the canonical header sections.",
        ));
    }
    for (index, (section, expected_name)) in sections.iter().zip(SECTION_NAMES).enumerate() {
        let object = section
            .as_object()
            .ok_or_else(|| invalid("IL2CPP metadata section is invalid."))?;
        if object.get("name").and_then(Value::as_str) != Some(expected_name) {
            return Err(invalid(
                "IL2CPP metadata sections must preserve header order.",
            ));
        }
        let offset = object
            .get("offset")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("IL2CPP metadata section offset is invalid."))?;
        let size = object
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("IL2CPP metadata section size is invalid."))?;
        if offset
            .checked_add(size)
            .map_or(true, |end| end > artifact_bytes)
        {
            return Err(invalid(
                "IL2CPP metadata section range is outside the artifact.",
            ));
        }
        let count = object
            .get("count")
            .ok_or_else(|| invalid("IL2CPP metadata section count is missing."))?;
        if !count.is_null() && count.as_u64().is_none() {
            return Err(invalid(&format!(
                "IL2CPP metadata section {index} count is invalid."
            )));
        }
    }
    if !report["limitations"]
        .as_array()
        .is_some_and(|values| values.iter().all(Value::is_string))
    {
        return Err(invalid("IL2CPP metadata limitations must contain strings."));
    }
    Ok(())
}

fn validate_member_collection(value: &Value, name: &str) -> Result<(), Failure> {
    let Some(rows) = value.as_array() else {
        return Ok(());
    };
    for (index, row) in rows.iter().enumerate() {
        let object = row
            .as_object()
            .ok_or_else(|| invalid("IL2CPP metadata member row is invalid."))?;
        if object
            .get("metadata_index")
            .and_then(Value::as_u64)
            .is_none()
            || object
                .get("source_offset")
                .and_then(Value::as_u64)
                .is_none()
            || object
                .get("declaring_type")
                .and_then(Value::as_i64)
                .is_none()
        {
            return Err(invalid(&format!(
                "IL2CPP metadata {name} row {index} has an invalid source identity."
            )));
        }
    }
    Ok(())
}

fn validate_index_widths(widths: &Value) -> Result<(), Failure> {
    let object = widths
        .as_object()
        .ok_or_else(|| invalid("IL2CPP metadata index widths are invalid."))?;
    let expected = ["type_definition", "generic_container", "parameter", "type"];
    if object
        .keys()
        .any(|key| !expected.contains(&key.as_str()) && key != "type_width_source")
        || expected.iter().any(|key| !object.contains_key(*key))
    {
        return Err(invalid("IL2CPP metadata index widths are invalid."));
    }
    for field in expected {
        if !matches!(object[field].as_u64(), Some(1 | 2 | 4)) {
            return Err(invalid("IL2CPP metadata index widths are invalid."));
        }
    }
    if !matches!(
        object["type_width_source"].as_str(),
        Some("interface-offsets-record" | "type-definition-record" | "fixed-width-version")
    ) {
        return Err(invalid("IL2CPP metadata index widths are invalid."));
    }
    Ok(())
}

fn validate_subject(record: &EvidenceRecord, report: &Value) -> Result<(), Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    if subject.is_null() {
        return Ok(());
    }
    if subject["format"].as_str() != Some("file")
        || subject["local_path"].as_str() != report["artifact"]["path"].as_str()
        || subject["digest"]["sha256"].as_str() != report["artifact"]["sha256"].as_str()
    {
        return Err(invalid(
            "IL2CPP metadata artifact identity does not match its parent subject.",
        ));
    }
    Ok(())
}

fn summary(record: &EvidenceRecord, report: &Value, view: Value) -> Result<Value, Failure> {
    let counts = counts(report)?;
    let mut summary = report
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("Metadata report must be an object."))?;
    for field in [
        "sections",
        "images",
        "types",
        "methods",
        "fields",
        "properties",
        "events",
        "parameters",
    ] {
        summary.remove(field);
    }
    summary.insert("counts".into(), counts);
    Ok(shared(
        record,
        report,
        json!({"kind":"summary", "view":view, "summary":summary, "coverage":complete_coverage(1)}),
    ))
}

fn counts(report: &Value) -> Result<Value, Failure> {
    let types = report["types"]
        .as_array()
        .ok_or_else(|| invalid("Metadata types must be an array."))?;
    Ok(json!({
        "sections": report["sections"].as_array().map_or(0, Vec::len),
        "images": report["images"].as_array().map_or(0, Vec::len),
        "types": types.len(),
        "methods": report["methods"].as_array().map_or(0, Vec::len),
        "fields": collection_count(report, "fields"),
        "properties": collection_count(report, "properties"),
        "events": collection_count(report, "events"),
        "parameters": collection_count(report, "parameters"),
        "nested_types": types.iter().filter(|row| row["declaring_type"].as_i64() != Some(-1)).count(),
    }))
}

fn collection_count(report: &Value, collection: &str) -> Value {
    report
        .get(collection)
        .and_then(Value::as_array)
        .map_or(Value::Null, |rows| json!(rows.len()))
}

#[allow(clippy::too_many_arguments)]
fn page(
    record: &EvidenceRecord,
    report: &Value,
    view: Value,
    collection: Collection,
    indices: Option<Vec<usize>>,
    names: Option<BTreeSet<String>>,
    image_indices: Option<Vec<usize>>,
    namespaces: Option<BTreeSet<String>>,
    declaring_types: Option<BTreeSet<i64>>,
    fields: Option<BTreeSet<String>>,
    offset: usize,
    limit: usize,
) -> Result<Value, Failure> {
    let rows = report[collection.name()]
        .as_array()
        .ok_or_else(|| invalid("Metadata collection must be an array."))?;
    let selected = selected_rows(
        report,
        rows,
        collection,
        indices.as_deref(),
        names.as_ref(),
        image_indices.as_deref(),
        namespaces.as_ref(),
        declaring_types.as_ref(),
    );
    let total = selected.len();
    let start = offset.min(total);
    let end = start.saturating_add(limit).min(total);
    let items = selected[start..end]
        .iter()
        .map(|(index, row)| select_row(*index, row, fields.as_ref()))
        .collect::<Vec<_>>();
    let mut body = json!({"kind":"il2cpp-metadata", "view":view, "items":items, "metadata_version":report["metadata_version"], "counts":counts(report)?, "coverage":page_coverage(offset, end - start, total)});
    body = shared(record, report, body);
    Ok(body)
}

fn selected_rows<'a>(
    report: &'a Value,
    rows: &'a [Value],
    collection: Collection,
    indices: Option<&[usize]>,
    names: Option<&BTreeSet<String>>,
    image_indices: Option<&[usize]>,
    namespaces: Option<&BTreeSet<String>>,
    declaring_types: Option<&BTreeSet<i64>>,
) -> Vec<(usize, &'a Value)> {
    let requested = indices.map_or_else(
        || (0..rows.len()).collect::<Vec<_>>(),
        |values| {
            values
                .iter()
                .copied()
                .filter(|index| *index < rows.len())
                .collect()
        },
    );
    requested
        .into_iter()
        .filter_map(|index| {
            let row = &rows[index];
            if names.is_some_and(|values| !matches_string_field(row, "name", values)) {
                return None;
            }
            if namespaces.is_some_and(|values| !matches_string_field(row, "namespace", values)) {
                return None;
            }
            if !matches_declaring_type(row, declaring_types) {
                return None;
            }
            if let Some(images) = image_indices {
                if collection != Collection::Types || !type_in_images(index, images, report) {
                    return None;
                }
            }
            Some((index, row))
        })
        .collect()
}

fn matches_string_field(row: &Value, field: &str, requested: &BTreeSet<String>) -> bool {
    row.as_object()
        .and_then(|object| object.get(field))
        .and_then(Value::as_str)
        .is_some_and(|value| requested.contains(value))
}

fn matches_declaring_type(row: &Value, requested: Option<&BTreeSet<i64>>) -> bool {
    let Some(requested) = requested else {
        return true;
    };

    row.as_object()
        .and_then(|object| object.get("declaring_type"))
        .and_then(Value::as_i64)
        .is_some_and(|declaring_type| requested.contains(&declaring_type))
}

fn type_in_images(index: usize, image_indices: &[usize], report: &Value) -> bool {
    report["images"].as_array().is_some_and(|images| {
        image_indices.iter().any(|image_index| {
            images.get(*image_index).is_some_and(|image| {
                let start = image["type_start"].as_u64().unwrap_or(usize::MAX as u64) as usize;
                let count = image["type_count"].as_u64().unwrap_or(0) as usize;
                index >= start && index < start.saturating_add(count)
            })
        })
    })
}

fn select_row(index: usize, row: &Value, fields: Option<&BTreeSet<String>>) -> Value {
    let mut item = Map::new();
    item.insert("index".into(), json!(index));
    if let Some(object) = row.as_object() {
        for (key, value) in object {
            if fields.is_none_or(|selected| selected.contains(key)) {
                item.insert(key.clone(), value.clone());
            }
        }
    }
    Value::Object(item)
}

fn shared(record: &EvidenceRecord, report: &Value, mut body: Value) -> Value {
    let mut limitations = Vec::new();
    if let Ok(parent) = serde_json::from_str::<Value>(record.raw().get()) {
        if let Some(parent_limitations) = parent["limitations"].as_array() {
            limitations.extend(parent_limitations.iter().cloned());
        }
    }
    limitations.sort_by_key(|value| value.as_str().unwrap_or_default().to_owned());
    limitations.dedup();

    let mut unknowns = vec![
        "Counts and page exhaustion cover retained metadata facts, not runtime loading or native code addresses.".to_owned(),
    ];
    if record.subject().get() == "null" {
        unknowns.push(
            "The parent has no recorded subject; its normalized artifact identity cannot be cross-checked against a subject digest.".to_owned(),
        );
    }
    body.as_object_mut().unwrap().extend(BTreeMap::from([
        ("parent_evidence_id".to_owned(), json!(record.evidence_id())),
        ("parent_operation".to_owned(), json!(PARENT_OPERATION)),
        (
            "parent_digest".to_owned(),
            json!(
                record
                    .evidence_id()
                    .strip_prefix("ev_")
                    .unwrap_or(record.evidence_id())
            ),
        ),
        (
            "artifact".to_owned(),
            json!({"path":report["artifact"]["path"], "sha256":report["artifact"]["sha256"]}),
        ),
        ("limitations".to_owned(), Value::Array(limitations)),
        ("unknowns".to_owned(), json!(unknowns)),
    ]));
    body
}

fn create_view_evidence(
    record: &EvidenceRecord,
    mut body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let digest = canonical_json::digest(&body).map_err(|error| invalid(&error.to_string()))?;
    body["view_digest"] = json!(digest);
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let authority: Value = serde_json::from_str(record.authority().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let path = body["artifact"]["path"].as_str().unwrap_or_default();
    let unsigned = json!({
        "subject":subject, "provider":{"id":"rea-analysis-view","name":"REA analysis view projection","version":"1"},
        "analysis_profile":null, "predicate_type":"rea.analysis-view", "operation":OPERATION,
        "parameters":{"parent_evidence_id":record.evidence_id(),"view":body["view"]}, "raw_result":null,
        "normalized_result":body, "confidence":"derived", "authority":authority, "environment":null,
        "limitations":body["limitations"], "relationship_coverage":null,
        "locations":if path.is_empty() { json!([]) } else { json!([{"kind":"artifact-path","path":path}]) },
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

fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
}
fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
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
