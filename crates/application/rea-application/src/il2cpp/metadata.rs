//! Read-only Unity IL2CPP `global-metadata.dat` inspection.
//!
//! The decoder deliberately owns the complete byte interpretation here.  The
//! runtime adapters only select a path and retain the authenticated Evidence.

use rea_core::{
    cancellation::Cancellation,
    evidence::Provider,
    evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget},
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
    json_output::{self, Error as JsonOutputError},
};
use rea_host::fs::stable_file::{self, FileAccess, ReadFailure, ReadIssue, Snapshot};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, sync::Arc};

use crate::il2cpp::metadata_member_rows::{
    MemberOwnership, MemberRows, MemberRowsError, MemberSectionDescriptors, SectionDescriptor,
    TypeMemberRanges, parse_member_rows_for_version_cancellable,
    resolve_member_ownership_cancellable,
};

pub const OPERATION: &str = "inspect_il2cpp_metadata";
const PROVIDER: Provider = Provider {
    id: "il2cpp-metadata",
    name: "REA IL2CPP global-metadata reader",
    version: Some("1"),
};
const MAGIC: u32 = 0xfab1_1baf;
const MAX_INPUT: usize = 256 * 1024 * 1024;
const MAX_OUTPUT: usize = 64 * 1024 * 1024;
// These minima describe the compact projected rows; optional generic arity,
// wider numbers, and non-empty names only increase their encoded size.
const IMAGE_ROW_MIN_BYTES: usize =
    compact_row_minimum_bytes(&[("name", 2), ("type_start", 1), ("type_count", 1)]);
const TYPE_ROW_MIN_BYTES: usize = compact_row_minimum_bytes(&[
    ("metadata_index", 1),
    ("source_offset", 1),
    ("name", 2),
    ("namespace", 2),
    ("method_start", 1),
    ("method_count", 1),
    ("field_start", 1),
    ("field_count", 1),
    ("property_start", 1),
    ("property_count", 1),
    ("event_start", 1),
    ("event_count", 1),
    ("nested_type_start", 1),
    ("nested_type_count", 1),
    ("declaring_type", 1),
]);
const METHOD_ROW_MIN_BYTES: usize = compact_row_minimum_bytes(&[
    ("metadata_index", 1),
    ("method_index", 1),
    ("source_offset", 1),
    ("name", 2),
    ("declaring_type", 1),
]);
const FIELD_ROW_MIN_BYTES: usize = compact_row_minimum_bytes(&[
    ("metadata_index", 1),
    ("source_offset", 1),
    ("name_index", 1),
    ("type_index", 1),
    ("custom_attribute_index", 1),
    ("token", 1),
    ("declaring_type", 1),
]);
const PROPERTY_ROW_MIN_BYTES: usize = compact_row_minimum_bytes(&[
    ("metadata_index", 1),
    ("source_offset", 1),
    ("name_index", 1),
    ("getter_index", 1),
    ("setter_index", 1),
    ("attributes", 1),
    ("token", 1),
    ("declaring_type", 1),
]);
const EVENT_ROW_MIN_BYTES: usize = compact_row_minimum_bytes(&[
    ("metadata_index", 1),
    ("source_offset", 1),
    ("name_index", 1),
    ("type_index", 1),
    ("add_index", 1),
    ("remove_index", 1),
    ("raise_index", 1),
    ("token", 1),
    ("declaring_type", 1),
]);
const PARAMETER_ROW_MIN_BYTES: usize = compact_row_minimum_bytes(&[
    ("metadata_index", 1),
    ("source_offset", 1),
    ("name_index", 1),
    ("token", 1),
    ("type_index", 1),
    ("custom_attribute_index", 1),
    ("flags", 1),
    ("declaring_type", 1),
    ("declaring_method", 2),
]);

const fn compact_row_minimum_bytes(fields: &[(&str, usize)]) -> usize {
    let mut bytes = 2;
    let mut index = 0;

    while index < fields.len() {
        if index > 0 {
            bytes += 1;
        }
        bytes += fields[index].0.len() + 3 + fields[index].1;
        index += 1;
    }

    bytes
}
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

/// Validate and project a previously captured IL2CPP metadata Evidence record.
///
/// The artifact reader owns byte decoding. This boundary only authenticates a
/// retained report and checks the fields needed by the public contract; it
/// never reopens the recorded path or infers facts from a partial payload.
pub fn project_captured_evidence(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    if object.len() != 1 || !object.contains_key("evidence") {
        return Err(invalid(
            "input",
            "Captured inspection requires exactly one evidence field",
        ));
    }

    let evidence = object
        .get("evidence")
        .ok_or_else(|| invalid("evidence", "Evidence is required"))?;
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid("evidence", &error.to_string()))?;
    let record =
        EvidenceRecord::parse(&raw).map_err(|error| invalid("evidence", &error.to_string()))?;
    if !record.operation_matches(OPERATION) {
        return Err(invalid(
            "evidence.operation",
            "Evidence operation must be inspect_il2cpp_metadata",
        ));
    }

    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid("evidence.normalized_result", &error.to_string()))?;
    validate_captured_report(&result)?;
    Ok(result)
}

fn validate_captured_report(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("result", "IL2CPP metadata result must be an object"))?;
    reject_unknown_keys(
        object,
        &[
            "artifact",
            "magic",
            "metadata_version",
            "index_widths",
            "sections",
            "images",
            "types",
            "methods",
            "fields",
            "properties",
            "events",
            "parameters",
            "limitations",
        ],
        "result",
    )?;
    let artifact = object
        .get("artifact")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("result.artifact", "Artifact identity is required"))?;
    reject_unknown_keys(artifact, &["path", "sha256", "bytes"], "result.artifact")?;
    let path = artifact
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("result.artifact.path", "Artifact path is required"))?;
    if path.is_empty() || !Path::new(path).is_absolute() {
        return Err(invalid(
            "result.artifact.path",
            "Artifact path must be absolute",
        ));
    }
    let digest = artifact
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("result.artifact.sha256", "Artifact digest is required"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            "result.artifact.sha256",
            "Artifact digest must be lowercase SHA-256",
        ));
    }
    if artifact.get("bytes").and_then(Value::as_u64).is_none() {
        return Err(invalid(
            "result.artifact.bytes",
            "Artifact byte count is required",
        ));
    }
    if object.get("magic").and_then(Value::as_u64) != Some(MAGIC as u64) {
        return Err(invalid("result.magic", "IL2CPP metadata magic is invalid"));
    }
    let version = object
        .get("metadata_version")
        .and_then(Value::as_i64)
        .ok_or_else(|| invalid("result.metadata_version", "Metadata version is required"))?;
    if !matches!(version, 29 | 31 | 39) {
        return Err(invalid(
            "result.metadata_version",
            "Metadata version is unsupported",
        ));
    }
    validate_index_widths(object.get("index_widths"))?;
    validate_sections(
        object.get("sections"),
        artifact["bytes"].as_u64().unwrap_or(0),
    )?;
    validate_rows(
        object.get("images"),
        "images",
        &[
            ("name", RowField::Text),
            ("type_start", RowField::Index),
            ("type_count", RowField::Count),
        ],
    )?;
    validate_rows(
        object.get("types"),
        "types",
        &[
            ("metadata_index", RowField::Count),
            ("source_offset", RowField::Count),
            ("name", RowField::Text),
            ("namespace", RowField::Text),
            ("method_start", RowField::Index),
            ("method_count", RowField::Count),
            ("field_start", RowField::Index),
            ("field_count", RowField::Count),
            ("property_start", RowField::Index),
            ("property_count", RowField::Count),
            ("event_start", RowField::Index),
            ("event_count", RowField::Count),
            ("nested_type_start", RowField::Index),
            ("nested_type_count", RowField::Count),
            ("declaring_type", RowField::Index),
        ],
    )?;
    validate_rows(
        object.get("methods"),
        "methods",
        &[
            ("metadata_index", RowField::Count),
            ("method_index", RowField::Count),
            ("source_offset", RowField::Count),
            ("name", RowField::Text),
            ("declaring_type", RowField::Index),
        ],
    )?;
    for field in ["fields", "properties", "events", "parameters"] {
        validate_member_rows(object.get(field), field)?;
    }
    let limitations = object
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("result.limitations", "Limitations must be an array"))?;
    if !limitations.iter().all(Value::is_string) {
        return Err(invalid(
            "result.limitations",
            "Limitations must contain strings",
        ));
    }
    Ok(())
}

fn validate_member_rows(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("result", &format!("{field} must be an array")))?;
    for (index, row) in rows.iter().enumerate() {
        let object = row.as_object().ok_or_else(|| {
            invalid(
                &format!("result.{field}[{index}]"),
                "Member row must be an object",
            )
        })?;
        for required in ["metadata_index", "source_offset"] {
            if object.get(required).and_then(Value::as_u64).is_none() {
                return Err(invalid(
                    &format!("result.{field}[{index}].{required}"),
                    "Member row index is invalid",
                ));
            }
        }
        if object
            .get("declaring_type")
            .and_then(Value::as_i64)
            .is_none()
        {
            return Err(invalid(
                &format!("result.{field}[{index}].declaring_type"),
                "Member declaring type is invalid",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RowField {
    Text,
    Count,
    Index,
}

fn validate_rows(
    value: Option<&Value>,
    field: &str,
    fields: &[(&str, RowField)],
) -> Result<(), Failure> {
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("result", &format!("{field} must be an array")))?;
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| invalid("result", &format!("{field} rows must be objects")))?;
        let allows_generic_arity = matches!(field, "types" | "methods");
        let mut allowed = fields.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        if allows_generic_arity {
            allowed.push("generic_arity");
        }
        reject_unknown_keys(object, &allowed, &format!("result.{field}"))?;
        for (name, kind) in fields {
            let value = object
                .get(*name)
                .ok_or_else(|| invalid("result", &format!("{field} row is missing {name}")))?;
            let valid = match kind {
                RowField::Text => value.as_str().is_some(),
                RowField::Count => value.as_u64().is_some(),
                RowField::Index => value.as_i64().is_some_and(|index| index >= -1),
            };
            if !valid {
                return Err(invalid(
                    "result",
                    &format!("{field}.{name} has an invalid value"),
                ));
            }
        }
        if allows_generic_arity
            && let Some(value) = object.get("generic_arity")
            && value.as_u64().is_none()
        {
            return Err(invalid(
                "result",
                &format!("{field}.generic_arity has an invalid value"),
            ));
        }
    }
    Ok(())
}

fn reject_unknown_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), Failure> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(path, &format!("Unknown field {key}")));
    }
    Ok(())
}

fn validate_index_widths(value: Option<&Value>) -> Result<(), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("result.index_widths", "Index widths are required"))?;
    reject_unknown_keys(
        object,
        &[
            "type_definition",
            "generic_container",
            "parameter",
            "type",
            "type_width_source",
        ],
        "result.index_widths",
    )?;
    for field in ["type_definition", "generic_container", "parameter", "type"] {
        let width = object.get(field).and_then(Value::as_u64);
        if !matches!(width, Some(1 | 2 | 4)) {
            return Err(invalid(
                "result.index_widths",
                "Index widths must be 1, 2 or 4",
            ));
        }
    }
    if !matches!(
        object.get("type_width_source").and_then(Value::as_str),
        Some("interface-offsets-record" | "type-definition-record" | "fixed-width-version")
    ) {
        return Err(invalid(
            "result.index_widths.type_width_source",
            "Type width source is invalid",
        ));
    }
    Ok(())
}

fn validate_sections(value: Option<&Value>, bytes: u64) -> Result<(), Failure> {
    let sections = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("result.sections", "Sections are required"))?;
    if sections.len() != SECTION_NAMES.len() {
        return Err(invalid("result.sections", "Section count is invalid"));
    }
    for (index, (section, expected_name)) in sections.iter().zip(SECTION_NAMES).enumerate() {
        let object = section
            .as_object()
            .ok_or_else(|| invalid("result.sections", "Section must be an object"))?;
        reject_unknown_keys(
            object,
            &["name", "offset", "size", "count"],
            "result.sections",
        )?;
        if object.get("name").and_then(Value::as_str) != Some(expected_name) {
            return Err(invalid(
                "result.sections",
                &format!("Section {index} is out of order"),
            ));
        }
        let offset = object
            .get("offset")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("result.sections", "Section offset is invalid"))?;
        let size = object
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("result.sections", "Section size is invalid"))?;
        if offset.checked_add(size).is_none_or(|end| end > bytes) {
            return Err(invalid(
                "result.sections",
                "Section range is outside the artifact",
            ));
        }
        let count = object
            .get("count")
            .ok_or_else(|| invalid("result.sections", "Section count is required"))?;
        if !count.is_null() && count.as_u64().is_none() {
            return Err(invalid("result.sections", "Section count is invalid"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Section {
    offset: usize,
    size: usize,
    count: Option<usize>,
}

#[derive(Clone, Copy)]
struct DecodedRowCounts {
    images: usize,
    types: usize,
    methods: usize,
    fields: usize,
    properties: usize,
    events: usize,
    parameters: usize,
}

/// Owns stable reads and retryable cleanup for IL2CPP metadata inspections.
///
/// Runtime sessions retain this owner until shutdown. One-shot CLI callers
/// request an immediate cleanup retry and keep the owner alive through
/// response delivery.
pub struct Il2cppMetadataInspection<F: FileAccess> {
    access: Arc<F>,
    retained: Vec<(String, ReadFailure<F>)>,
}

impl<F: FileAccess> Il2cppMetadataInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            access,
            retained: Vec::new(),
        }
    }

    pub fn close(&mut self) -> Result<(), Failure> {
        crate::artifacts::inspection::close_retained_read_failures(
            &mut self.retained,
            OPERATION,
            PROVIDER,
        )
    }

    pub fn inspect(
        &mut self,
        input: &Value,
        cancellation: &Cancellation,
        completion: crate::artifacts::inspection::Completion,
    ) -> Result<Box<serde_json::value::RawValue>, Failure> {
        let (object, path) = inspection_input(input)?;

        if cancellation.reason().is_some() {
            return Err(cancelled());
        }
        self.close()?;

        let snapshot = match stable_file::read(
            self.access.clone(),
            Path::new(path),
            MAX_INPUT,
            cancellation,
        ) {
            Ok(snapshot) => snapshot,
            Err(failure) => {
                return Err(self.project_read_failure(path, completion, *failure));
            }
        };

        if cancellation.reason().is_some() {
            return Err(cancelled_with_source(path, &snapshot));
        }

        let mut observed_counts = None;
        let report = match decode(
            path,
            &snapshot.bytes,
            &snapshot.sha256,
            cancellation,
            &mut observed_counts,
        ) {
            Ok(report) => report,
            Err(mut failure) => {
                retain_source_observation(&mut failure, path, &snapshot, observed_counts);
                return Err(failure);
            }
        };

        if let Err(mut failure) = ensure_report_size(&report) {
            retain_source_observation(&mut failure, path, &snapshot, observed_counts);
            return Err(failure);
        }

        let evidence = match create_evidence(path, object, &snapshot.sha256, report) {
            Ok(evidence) => evidence,
            Err(mut failure) => {
                retain_source_observation(&mut failure, path, &snapshot, observed_counts);
                return Err(failure);
            }
        };
        if cancellation.reason().is_some() {
            return Err(cancelled_with_evidence(&evidence));
        }

        Ok(evidence)
    }

    fn project_read_failure(
        &mut self,
        path: &str,
        completion: crate::artifacts::inspection::Completion,
        failure: ReadFailure<F>,
    ) -> Failure {
        let partial_observation = failure
            .completed
            .as_ref()
            .map(|snapshot| source_evidence(path, snapshot, None));
        let mut projected = crate::artifacts::inspection::project_retained_read_failure(
            &mut self.retained,
            OPERATION,
            PROVIDER,
            path,
            completion,
            failure,
            |issue, path| {
                crate::artifacts::inspection::read_failure(OPERATION, PROVIDER, issue, path)
            },
            partial_observation
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .map(Box::as_ref),
        );

        if let Some(Err(error)) = partial_observation {
            projected.detail(
                "partial_observation_failure",
                Detail::Text(error.to_string()),
            );
        }

        projected
    }
}

fn inspection_input(input: &Value) -> Result<(&serde_json::Map<String, Value>, &str), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("path", "Expected an absolute path"))?;
    if path.is_empty() || !Path::new(path).is_absolute() {
        return Err(invalid("path", "Expected an absolute local path"));
    }
    Ok((object, path))
}

fn ensure_report_size(report: &Value) -> Result<(), Failure> {
    encoded_json_length(report, MAX_OUTPUT).map(|_| ())
}

fn ensure_row_count_fits_output_limit(counts: DecodedRowCounts) -> Result<(), Failure> {
    if row_count_output_lower_bound(counts)? > MAX_OUTPUT {
        return Err(resource());
    }

    Ok(())
}

fn row_count_output_lower_bound(counts: DecodedRowCounts) -> Result<usize, Failure> {
    let rows = [
        (counts.images, IMAGE_ROW_MIN_BYTES),
        (counts.types, TYPE_ROW_MIN_BYTES),
        (counts.methods, METHOD_ROW_MIN_BYTES),
        (counts.fields, FIELD_ROW_MIN_BYTES),
        (counts.properties, PROPERTY_ROW_MIN_BYTES),
        (counts.events, EVENT_ROW_MIN_BYTES),
        (counts.parameters, PARAMETER_ROW_MIN_BYTES),
    ];
    rows.into_iter()
        .try_fold(0usize, |total, (count, row_bytes)| {
            count
                .checked_mul(row_bytes)
                .and_then(|section_bytes| total.checked_add(section_bytes))
        })
        .ok_or_else(resource)
}

fn encoded_json_length<T: serde::Serialize>(value: &T, maximum: usize) -> Result<usize, Failure> {
    match json_output::admitted_length(value, maximum) {
        Ok(length) => Ok(length),
        Err(JsonOutputError::Limit { .. }) => Err(resource()),
        Err(JsonOutputError::Encoding(error)) => Err(invalid(
            "result",
            &format!("Report could not be encoded: {error}"),
        )),
    }
}

fn create_evidence(
    path: &str,
    parameters: &serde_json::Map<String, Value>,
    sha256: &str,
    report: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    // Exact port of `Il2cppMetadataService` `createEvidence`: caller-selected
    // subject, decoder limitations, and the artifact path plus each non-empty
    // images/typeDefinitions/methods/nestedTypes/strings file-offset range.
    let limitations = report
        .get("limitations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut locations = vec![json!({"kind": "artifact-path", "path": path})];
    for section in report
        .get("sections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let size = section.get("size").and_then(Value::as_u64).unwrap_or(0);
        let offset = section.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let named = matches!(
            section.get("name").and_then(Value::as_str),
            Some("images" | "typeDefinitions" | "methods" | "nestedTypes" | "strings")
        );
        if named && size > 0 {
            locations.push(json!({
                "kind": "file-offset-range",
                "start": offset,
                "end": offset + size,
            }));
        }
    }
    let observation = Observation::new(OPERATION, Value::Object(parameters.clone()), report)
        .confidence("observed")
        .limitations(limitations)
        .locations(locations);
    encode_evidence(path, sha256, observation)
}

/// Bind one observation to the caller-selected file subject through the shared
/// `createEvidence` port.
fn encode_evidence(
    path: &str,
    sha256: &str,
    observation: Observation,
) -> Result<Box<RawValue>, Failure> {
    let subject = SubjectTarget {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        format: "file".to_owned(),
        architecture: None,
    };
    let provider = EvidenceProvider::new(
        PROVIDER.id,
        PROVIDER.name,
        PROVIDER.version.map(str::to_owned),
    );
    let evidence = Evidence::create(Some(&subject), &provider, observation)
        .map_err(|error| invalid("result", &error.to_string()))?;
    evidence
        .to_raw()
        .map_err(|_| invalid("result", "Evidence could not be encoded"))
}

fn cancelled_with_source(path: &str, snapshot: &Snapshot) -> Failure {
    let mut failure = cancelled();
    retain_source_observation(&mut failure, path, snapshot, None);
    failure
}

fn retain_source_observation(
    failure: &mut Failure,
    path: &str,
    snapshot: &Snapshot,
    counts: Option<DecodedRowCounts>,
) {
    match source_evidence(path, snapshot, counts) {
        Ok(evidence) => {
            if let Err(error) = failure.retain(&evidence) {
                failure.detail(
                    "partial_observation_failure",
                    Detail::Text(error.to_string()),
                );
            }
        }
        Err(error) => failure.detail(
            "partial_observation_failure",
            Detail::Text(error.to_string()),
        ),
    }
}

fn source_evidence(
    path: &str,
    snapshot: &Snapshot,
    counts: Option<DecodedRowCounts>,
) -> Result<Box<RawValue>, Failure> {
    let bytes = snapshot.bytes.len();
    let mut source = json!({
        "artifact": {
            "path": path,
            "sha256": snapshot.sha256,
            "bytes": bytes,
        },
        "inventory_status": "not-returned-as-complete",
    });
    if let Some(counts) = counts {
        source["validated_section_row_counts"] = json!({
            "images": counts.images,
            "types": counts.types,
            "methods": counts.methods,
            "fields": counts.fields,
            "properties": counts.properties,
            "events": counts.events,
            "parameters": counts.parameters,
        });
    }
    let observation = Observation::new(
        "observe_il2cpp_metadata_source",
        json!({"path": path}),
        source,
    )
    .predicate("rea.il2cpp-metadata-source")
    .confidence("observed")
    .limitations(vec![
        "This partial source observation does not contain a complete metadata inventory. Section row counts, when available, are derived from the validated header extents and record layout; names and relationships may remain unexamined.".to_owned(),
    ])
    .locations(vec![
        json!({"kind": "artifact-path", "path": path}),
        json!({"kind": "file-offset-range", "start": 0, "end": bytes}),
    ]);
    encode_evidence(path, &snapshot.sha256, observation)
}

fn decode(
    path: &str,
    bytes: &[u8],
    sha256: &str,
    cancellation: &Cancellation,
    observed_counts: &mut Option<DecodedRowCounts>,
) -> Result<Value, Failure> {
    ensure_not_cancelled(cancellation, "metadata header", 0)?;

    let read_u32 = |at: usize| -> Result<u32, Failure> {
        bytes
            .get(at..at + 4)
            .and_then(|v| v.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or_else(|| invalid("path", "Truncated metadata header or record"))
    };
    let read_i32 = |at: usize| -> Result<i32, Failure> {
        bytes
            .get(at..at + 4)
            .and_then(|v| v.try_into().ok())
            .map(i32::from_le_bytes)
            .ok_or_else(|| invalid("path", "Truncated metadata header or record"))
    };
    // `readHeader`: fewer than eight bytes or a foreign magic is outside
    // decoder coverage, as is an undecoded version.
    if bytes.len() < 8 || read_u32(0)? != MAGIC {
        return Err(unsupported(
            path,
            "unrecognized-magic: the file does not start with the IL2CPP global-metadata magic 0xFAB11BAF; encrypted or non-metadata inputs are not decoded",
        ));
    }
    let version = read_i32(4)?;
    if !matches!(version, 29 | 31 | 39) {
        return Err(unsupported(
            path,
            &format!(
                "unsupported-version: metadata version {version} is not supported; versions 29, 31, 39 are decoded"
            ),
        ));
    }
    let counted = version == 39;
    let entry_bytes = if counted { 12 } else { 8 };
    let header_bytes = 8 + SECTION_NAMES.len() * entry_bytes;
    if bytes.len() < header_bytes {
        return Err(invalid("path", "Metadata header is truncated"));
    }
    let mut sections = Vec::new();
    for (i, name) in SECTION_NAMES.iter().enumerate() {
        let at = 8 + i * entry_bytes;
        let offset = read_i32(at)?;
        let size = read_i32(at + 4)?;
        let count = if counted {
            Some(read_i32(at + 8)?)
        } else {
            None
        };
        if offset < 0 || size < 0 || count.is_some_and(|value| value < 0) {
            return Err(invalid(
                "path",
                &format!("Section {name} has a negative header field"),
            ));
        }
        let offset = offset as usize;
        let size = size as usize;
        let count = count.map(|value| value as usize);
        if offset.checked_add(size).is_none()
            || offset + size > bytes.len()
            || (size > 0 && offset < header_bytes)
        {
            return Err(invalid(
                "path",
                &format!("Section {name} is outside the selected artifact"),
            ));
        }
        sections.push(Section {
            offset,
            size,
            count,
        });
    }
    if sections
        .first()
        .is_none_or(|section| section.offset != header_bytes)
    {
        return Err(invalid(
            "path",
            "The first metadata section does not begin immediately after the header",
        ));
    }
    let mut occupied: Vec<(usize, usize)> = sections
        .iter()
        .filter(|s| s.size > 0)
        .map(|s| (s.offset, s.offset + s.size))
        .collect();
    occupied.sort_unstable();
    if occupied.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(invalid("path", "Metadata sections overlap"));
    }
    let section = |name: &str| sections[SECTION_NAMES.iter().position(|v| *v == name).unwrap()];
    let entry_count = |name: &str, width: usize| -> Result<usize, Failure> {
        let s = section(name);
        if counted {
            let c = s.count.unwrap();
            if (c == 0 && s.size != 0) || (c > 0 && (s.size % c != 0 || s.size / c != width)) {
                return Err(invalid(
                    "path",
                    "Metadata record size does not match its header count",
                ));
            }
            Ok(c)
        } else if s.size % width != 0 {
            Err(invalid("path", "Metadata record section is truncated"))
        } else {
            Ok(s.size / width)
        }
    };
    let widths = if counted {
        let td = index_width(section("typeDefinitions").count.unwrap());
        let gc = index_width(section("genericContainers").count.unwrap());
        let parameter = index_width(section("parameters").count.unwrap());
        let interface_record = section("interfaceOffsets");
        let interface_count = interface_record.count.unwrap_or(0);
        if interface_count == 0 && interface_record.size != 0 {
            return Err(invalid(
                "path",
                "Interface-offset records declare bytes for zero records",
            ));
        }
        let (ty, type_width_source) = if interface_count > 0 {
            if interface_record.size % interface_count != 0 {
                return Err(invalid("path", "Interface-offset records are truncated"));
            }
            let record_size = interface_record.size / interface_count;
            if record_size < 4 {
                return Err(invalid(
                    "path",
                    "Interface-offset record is too small for a TypeIndex",
                ));
            }
            (record_size - 4, "interface-offsets-record")
        } else {
            let type_count = section("typeDefinitions").count.unwrap_or(0);
            if type_count == 0 || section("typeDefinitions").size % type_count != 0 {
                return Err(invalid(
                    "path",
                    "Type-definition records are unavailable for TypeIndex width recovery",
                ));
            }
            let record_size = section("typeDefinitions").size / type_count;
            if record_size < 68 + gc {
                return Err(invalid(
                    "path",
                    "Type-definition record is too small for TypeIndex fields",
                ));
            }
            ((record_size - 68 - gc) / 3, "type-definition-record")
        };
        if !matches!(ty, 1 | 2 | 4) {
            return Err(invalid("path", "TypeIndex width is invalid"));
        }
        (td, gc, parameter, ty, type_width_source)
    } else {
        (4, 4, 4, 4, "fixed-width-version")
    };
    let type_record = 68 + (if version == 39 { 3 } else { 4 }) * widths.3 + widths.1;
    let image_record = 32 + 2 * widths.0;
    let method_record =
        16 + if version != 29 { 4 } else { 0 } + widths.0 + widths.3 + widths.2 + widths.1;
    let images_n = entry_count("images", image_record)?;
    let types_n = entry_count("typeDefinitions", type_record)?;
    let nested_n = entry_count("nestedTypes", 4)?;
    let generic_n = entry_count("genericContainers", 16)?;
    let methods_n = entry_count("methods", method_record)?;
    let fields_n = entry_count("fields", 16)?;
    let properties_n = entry_count("properties", 20)?;
    let events_n = entry_count("events", 24)?;
    let parameters_n = entry_count("parameters", 20)?;

    let row_counts = DecodedRowCounts {
        images: images_n,
        types: types_n,
        methods: methods_n,
        fields: fields_n,
        properties: properties_n,
        events: events_n,
        parameters: parameters_n,
    };
    *observed_counts = Some(row_counts);

    ensure_not_cancelled(cancellation, "validated section counts", 0)?;
    ensure_row_count_fits_output_limit(row_counts)?;

    let strings = section("strings");
    let string = |index: i32| -> Result<String, Failure> {
        if index < 0 {
            return Err(invalid("path", "Negative string index"));
        }
        let start = strings
            .offset
            .checked_add(index as usize)
            .ok_or_else(|| invalid("path", "String index overflow"))?;
        if start >= strings.offset + strings.size
            || (start > strings.offset && bytes[start - 1] != 0)
        {
            return Err(invalid("path", "String index is not at a string boundary"));
        }
        let end = bytes[start..strings.offset + strings.size]
            .iter()
            .position(|b| *b == 0)
            .map(|x| start + x)
            .ok_or_else(|| invalid("path", "Unterminated metadata string"))?;
        String::from_utf8(bytes[start..end].to_vec())
            .map_err(|_| invalid("path", "Metadata string is not valid UTF-8"))
    };
    let read_index = |at: usize, width: usize| -> Result<i32, Failure> {
        let v = match width {
            1 => *bytes
                .get(at)
                .ok_or_else(|| invalid("path", "Truncated index"))? as i32,
            2 => u16::from_le_bytes(
                bytes
                    .get(at..at + 2)
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| invalid("path", "Truncated index"))?,
            ) as i32,
            4 => i32::from_le_bytes(
                bytes
                    .get(at..at + 4)
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| invalid("path", "Truncated index"))?,
            ),
            _ => return Err(invalid("path", "Invalid index width")),
        };
        Ok(if (width == 1 && v == 255) || (width == 2 && v == 65535) {
            -1
        } else {
            v
        })
    };
    let mut images = Vec::with_capacity(images_n);
    let im = section("images");
    for i in 0..images_n {
        ensure_not_cancelled(cancellation, "image decoding", i)?;

        let at = im.offset + i * image_record;
        let name = string(i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()))?;
        let start = read_index(at + 8, widths.0)?;
        let count = u32::from_le_bytes(
            bytes[at + 8 + widths.0..at + 12 + widths.0]
                .try_into()
                .unwrap(),
        ) as usize;
        if !valid_range(start, count, types_n) {
            return Err(invalid("path", "Image type range is outside metadata"));
        }
        images.push(json!({"name":name,"type_start":start,"type_count":count}));
    }
    reject_overlapping_image_ranges(&images, cancellation)?;
    let mut types = Vec::with_capacity(types_n);
    let mut type_member_ranges = Vec::with_capacity(types_n);
    let td = section("typeDefinitions");
    let nested = section("nestedTypes");
    let generic_containers = section("genericContainers");
    for i in 0..types_n {
        ensure_not_cancelled(cancellation, "type decoding", i)?;

        let at = td.offset + i * type_record;
        let type_indices = (if version == 39 { 3 } else { 4 }) * widths.3;
        let starts = at + 12 + type_indices + widths.1;
        let name = string(i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()))?;
        let namespace = string(i32::from_le_bytes(
            bytes[at + 4..at + 8].try_into().unwrap(),
        ))?;
        let ms = i32::from_le_bytes(bytes[starts + 4..starts + 8].try_into().unwrap());
        let mc = u16::from_le_bytes(bytes[starts + 32..starts + 34].try_into().unwrap()) as usize;
        let ns = i32::from_le_bytes(bytes[starts + 16..starts + 20].try_into().unwrap());
        let nc = u16::from_le_bytes(bytes[starts + 40..starts + 42].try_into().unwrap()) as usize;
        let field_start = read_index(starts, widths.0)?;
        let property_start = read_index(starts + 12, widths.0)?;
        let event_start = read_index(starts + 8, widths.0)?;
        let field_count =
            u16::from_le_bytes(bytes[starts + 36..starts + 38].try_into().unwrap()) as usize;
        let property_count =
            u16::from_le_bytes(bytes[starts + 34..starts + 36].try_into().unwrap()) as usize;
        let event_count =
            u16::from_le_bytes(bytes[starts + 38..starts + 40].try_into().unwrap()) as usize;
        let generic_container = read_index(at + 8 + type_indices, widths.1)?;
        let generic_arity = generic_arity(
            bytes,
            generic_containers,
            generic_n,
            generic_container,
            "Type",
        )?;
        if !valid_range(ms, mc, methods_n) || !valid_range(ns, nc, nested_n) {
            return Err(invalid("path", "Type range is outside metadata"));
        }
        let mut type_row = json!({
            "metadata_index": i,
            "source_offset": at,
            "name": name,
            "namespace": namespace,
            "method_start": ms,
            "method_count": mc,
            "field_start": field_start,
            "field_count": field_count,
            "property_start": property_start,
            "property_count": property_count,
            "event_start": event_start,
            "event_count": event_count,
            "nested_type_start": ns,
            "nested_type_count": nc,
            "declaring_type": -1,
        });
        if let Some(arity) = generic_arity {
            type_row["generic_arity"] = json!(arity);
        }
        types.push(type_row);
        type_member_ranges.push(TypeMemberRanges {
            type_index: i,
            field_start: i64::from(field_start),
            field_count,
            property_start: i64::from(property_start),
            property_count,
            event_start: i64::from(event_start),
            event_count,
            parameter_start: -1,
            parameter_count: 0,
        });
    }
    for i in 0..types_n {
        ensure_not_cancelled(cancellation, "nested type decoding", i)?;

        let ns = types[i]["nested_type_start"].as_i64().unwrap();
        let nc = types[i]["nested_type_count"].as_u64().unwrap() as usize;
        if nc == 0 {
            continue;
        }
        let nested_start = usize::try_from(ns)
            .map_err(|_| invalid("path", "Nested type range has an invalid start"))?;
        for j in 0..nc {
            let nested_index = nested_start + j;
            ensure_not_cancelled(cancellation, "nested type decoding", nested_index)?;

            let at = nested.offset + nested_index * 4;
            let child = i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            if child < 0 || child as usize >= types_n || child as usize == i {
                return Err(invalid("path", "Nested type index is invalid"));
            }
            if types[child as usize]["declaring_type"].as_i64().unwrap() != -1 {
                return Err(invalid("path", "Nested type has multiple declaring types"));
            }
            types[child as usize]["declaring_type"] = json!(i);
        }
    }
    reject_nested_type_cycles(&types, cancellation)?;

    let mut methods = Vec::with_capacity(methods_n);
    let mt = section("methods");
    for i in 0..methods_n {
        ensure_not_cancelled(cancellation, "method decoding", i)?;

        let at = mt.offset + i * method_record;
        let name = string(i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()))?;
        let owner = read_index(at + 4, widths.0)?;
        if owner < -1 || (owner >= 0 && owner as usize >= types_n) {
            return Err(invalid("path", "Method declaring type is invalid"));
        }
        let return_token_bytes = method_record - (16 + widths.0 + widths.3 + widths.2 + widths.1);
        let parameter_start = at + 4 + widths.0 + widths.3 + return_token_bytes;
        let generic_container = read_index(parameter_start + widths.2, widths.1)?;
        let generic_arity = generic_arity(
            bytes,
            generic_containers,
            generic_n,
            generic_container,
            "Method",
        )?;
        let mut method_row = json!({
            "metadata_index": i,
            "method_index": i,
            "source_offset": at,
            "name": name,
            "declaring_type": owner,
        });
        if let Some(arity) = generic_arity {
            method_row["generic_arity"] = json!(arity);
        }
        methods.push(method_row);
    }
    validate_method_owners(&types, &methods, cancellation)?;

    let mut report = json!({
        "artifact": {
            "path": path,
            "sha256": sha256,
            "bytes": bytes.len(),
        },
        "magic": MAGIC,
        "metadata_version": version,
        "index_widths": {
            "type_definition": widths.0,
            "generic_container": widths.1,
            "parameter": widths.2,
            "type": widths.3,
            "type_width_source": widths.4,
        },
        "sections": sections
            .iter()
            .zip(SECTION_NAMES)
            .map(|(section, name)| {
                json!({
                    "name": name,
                    "offset": section.offset,
                    "size": section.size,
                    "count": section.count,
                })
            })
            .collect::<Vec<_>>(),
        "images": images,
        "types": types,
        "methods": methods,
        "fields": [],
        "properties": [],
        "events": [],
        "parameters": [],
        "limitations": [
            "Only unencrypted global-metadata.dat versions 29, 31 and 39 are decoded; names and counts are file observations, not runtime behavior.",
            "Native code addresses, registration, signatures and generic instances are not recovered.",
            "declaring_type is derived from nestedTypes and type member ranges; unresolved ownership remains -1.",
        ],
    });

    let mut encoded_bytes = encoded_json_length(&report, MAX_OUTPUT)?;
    let members = decode_member_rows(version, bytes, &sections, &type_member_ranges, cancellation)?;
    let projected_members = project_member_rows(&members, cancellation, &mut encoded_bytes)?;

    report["fields"] = Value::Array(projected_members.fields);
    report["properties"] = Value::Array(projected_members.properties);
    report["events"] = Value::Array(projected_members.events);
    report["parameters"] = Value::Array(projected_members.parameters);

    Ok(report)
}

struct ResolvedMemberRows {
    rows: MemberRows,
    ownership: MemberOwnership,
}

struct ProjectedMembers {
    fields: Vec<Value>,
    properties: Vec<Value>,
    events: Vec<Value>,
    parameters: Vec<Value>,
}

fn decode_member_rows(
    version: i32,
    bytes: &[u8],
    sections: &[Section],
    type_ranges: &[TypeMemberRanges],
    cancellation: &Cancellation,
) -> Result<ResolvedMemberRows, Failure> {
    let section = |name: &str| {
        sections[SECTION_NAMES
            .iter()
            .position(|value| *value == name)
            .unwrap()]
    };
    let descriptor = |name: &str| {
        let selected = section(name);
        SectionDescriptor::new(selected.offset, selected.size, selected.count)
    };
    let sections = MemberSectionDescriptors {
        fields: descriptor("fields"),
        properties: descriptor("properties"),
        events: descriptor("events"),
        parameters: descriptor("parameters"),
    };
    let rows = parse_member_rows_for_version_cancellable(version as u32, bytes, &sections, || {
        cancellation.reason().is_some()
    })
    .map_err(|error| member_rows_failure(error, cancellation))?;

    let ownership = resolve_member_ownership_cancellable(&rows, type_ranges, || {
        cancellation.reason().is_some()
    })
    .map_err(|error| member_rows_failure(error, cancellation))?;

    Ok(ResolvedMemberRows { rows, ownership })
}

fn member_rows_failure(error: MemberRowsError, cancellation: &Cancellation) -> Failure {
    match error {
        MemberRowsError::Cancelled { phase, index } => cancelled_at(cancellation, phase, index),
        error => invalid("path", &format!("Unable to decode member rows: {error}")),
    }
}

fn project_member_rows(
    members: &ResolvedMemberRows,
    cancellation: &Cancellation,
    encoded_bytes: &mut usize,
) -> Result<ProjectedMembers, Failure> {
    let mut fields = Vec::with_capacity(members.rows.fields.len());
    for (index, row) in members.rows.fields.iter().enumerate() {
        ensure_not_cancelled(cancellation, "field projection", index)?;
        push_projected_row(
            &mut fields,
            json!({
                "metadata_index": row.index,
                "source_offset": row.source_offset,
                "name_index": row.name_index,
                "type_index": row.type_index,
                "custom_attribute_index": row.custom_attribute_index,
                "token": row.token,
                "declaring_type": project_owner(row.index, &members.ownership.fields),
            }),
            encoded_bytes,
        )?;
    }

    let mut properties = Vec::with_capacity(members.rows.properties.len());
    for (index, row) in members.rows.properties.iter().enumerate() {
        ensure_not_cancelled(cancellation, "property projection", index)?;
        push_projected_row(
            &mut properties,
            json!({
                "metadata_index": row.index,
                "source_offset": row.source_offset,
                "name_index": row.name_index,
                "getter_index": row.getter_index,
                "setter_index": row.setter_index,
                "attributes": row.attributes,
                "token": row.token,
                "declaring_type": project_owner(row.index, &members.ownership.properties),
            }),
            encoded_bytes,
        )?;
    }

    let mut events = Vec::with_capacity(members.rows.events.len());
    for (index, row) in members.rows.events.iter().enumerate() {
        ensure_not_cancelled(cancellation, "event projection", index)?;
        push_projected_row(
            &mut events,
            json!({
                "metadata_index": row.index,
                "source_offset": row.source_offset,
                "name_index": row.name_index,
                "type_index": row.type_index,
                "add_index": row.add_index,
                "remove_index": row.remove_index,
                "raise_index": row.raise_index,
                "token": row.token,
                "declaring_type": project_owner(row.index, &members.ownership.events),
            }),
            encoded_bytes,
        )?;
    }

    let mut parameters = Vec::with_capacity(members.rows.parameters.len());
    for (index, row) in members.rows.parameters.iter().enumerate() {
        ensure_not_cancelled(cancellation, "parameter projection", index)?;
        push_projected_row(
            &mut parameters,
            json!({
                "metadata_index": row.index,
                "source_offset": row.source_offset,
                "name_index": row.name_index,
                "token": row.token,
                "type_index": row.type_index,
                "custom_attribute_index": row.custom_attribute_index,
                "flags": row.flags,
                "declaring_type": project_owner(row.index, &members.ownership.parameters),
                "declaring_method": -1,
            }),
            encoded_bytes,
        )?;
    }

    Ok(ProjectedMembers {
        fields,
        properties,
        events,
        parameters,
    })
}

fn push_projected_row(
    rows: &mut Vec<Value>,
    row: Value,
    encoded_bytes: &mut usize,
) -> Result<(), Failure> {
    let separator_bytes = if rows.is_empty() { 0 } else { 1 };
    let available_bytes = MAX_OUTPUT
        .checked_sub(*encoded_bytes)
        .and_then(|remaining| remaining.checked_sub(separator_bytes))
        .ok_or_else(resource)?;
    let row_bytes = encoded_json_length(&row, available_bytes)?;
    let next_encoded_bytes = (*encoded_bytes)
        .checked_add(separator_bytes)
        .and_then(|length| length.checked_add(row_bytes))
        .ok_or_else(resource)?;

    *encoded_bytes = next_encoded_bytes;
    rows.push(row);
    Ok(())
}

fn project_owner(
    index: usize,
    owners: &[crate::il2cpp::metadata_member_rows::RowOwnership],
) -> Value {
    let candidates = owners
        .get(index)
        .filter(|owner| owner.row_index == index)
        .map(|owner| owner.owner_type_indices.as_slice())
        .unwrap_or_default();

    match candidates {
        [owner] => json!(owner),
        _ => json!(-1),
    }
}

fn index_width(entries: usize) -> usize {
    if entries <= 0xff {
        1
    } else if entries <= 0xffff {
        2
    } else {
        4
    }
}

fn generic_arity(
    bytes: &[u8],
    section: Section,
    total: usize,
    index: i32,
    owner: &str,
) -> Result<Option<usize>, Failure> {
    if index == -1 {
        return Ok(None);
    }

    let index = usize::try_from(index).map_err(|_| {
        invalid(
            "path",
            &format!("{owner} generic container index is invalid"),
        )
    })?;
    if index >= total {
        return Err(invalid(
            "path",
            &format!("{owner} generic container index is outside metadata"),
        ));
    }

    let offset = section.offset + index * 16;
    let arity = u32::from_le_bytes(
        bytes[offset + 4..offset + 8]
            .try_into()
            .map_err(|_| invalid("path", "Generic container record is truncated"))?,
    );
    Ok(Some(arity as usize))
}

fn reject_overlapping_image_ranges(
    images: &[Value],
    cancellation: &Cancellation,
) -> Result<(), Failure> {
    let mut ranges = Vec::with_capacity(images.len());
    for (index, image) in images.iter().enumerate() {
        ensure_not_cancelled(cancellation, "image range collection", index)?;

        let Some(object) = image.as_object() else {
            continue;
        };
        let Some(start) = object.get("type_start").and_then(Value::as_i64) else {
            continue;
        };
        let Some(count) = object.get("type_count").and_then(Value::as_u64) else {
            continue;
        };
        let count = count as usize;
        if count == 0 {
            continue;
        }
        let Ok(start) = usize::try_from(start) else {
            continue;
        };
        let Some(end) = start.checked_add(count) else {
            continue;
        };
        ranges.push((start, end, index));
    }

    ensure_not_cancelled(cancellation, "image range ordering", ranges.len())?;
    ranges.sort_unstable_by_key(|(start, _, _)| *start);
    ensure_not_cancelled(cancellation, "image range validation", 0)?;

    for (index, window) in ranges.windows(2).enumerate() {
        ensure_not_cancelled(cancellation, "image range validation", index)?;

        let (previous_start, previous_end, previous_index) = window[0];
        let (current_start, _, current_index) = window[1];
        if previous_end > current_start {
            return Err(invalid(
                "path",
                &format!(
                    "Image {previous_index} type range [{previous_start}, {previous_end}) overlaps image {current_index} starting at type {current_start}"
                ),
            ));
        }
    }
    Ok(())
}

fn reject_nested_type_cycles(types: &[Value], cancellation: &Cancellation) -> Result<(), Failure> {
    let mut state = vec![0u8; types.len()];

    for first in 0..types.len() {
        ensure_not_cancelled(cancellation, "nested type cycle validation", first)?;

        let mut chain = Vec::new();
        let mut current = first as i32;
        while current >= 0 {
            ensure_not_cancelled(
                cancellation,
                "nested type cycle validation",
                current as usize,
            )?;

            let index = usize::try_from(current).expect("non-negative type index");
            if state[index] == 1 {
                return Err(invalid(
                    "path",
                    &format!("Type {index} is nested inside itself through its declaring types"),
                ));
            }
            if state[index] == 2 {
                break;
            }

            state[index] = 1;
            chain.push(index);
            current = types[index]
                .get("declaring_type")
                .and_then(Value::as_i64)
                .unwrap_or(-1) as i32;
        }

        for (chain_index, index) in chain.into_iter().enumerate() {
            ensure_not_cancelled(cancellation, "nested type cycle validation", chain_index)?;
            state[index] = 2;
        }
    }

    Ok(())
}

fn validate_method_owners(
    types: &[Value],
    methods: &[Value],
    cancellation: &Cancellation,
) -> Result<(), Failure> {
    for (type_index, type_row) in types.iter().enumerate() {
        ensure_not_cancelled(cancellation, "method ownership validation", type_index)?;

        let object = type_row
            .as_object()
            .ok_or_else(|| invalid("path", "Decoded type row is not an object"))?;
        let start = object
            .get("method_start")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid("path", "Decoded type method start is invalid"))?;
        let count = object
            .get("method_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("path", "Decoded type method count is invalid"))?
            as usize;
        if start < 0 {
            continue;
        }
        let start = usize::try_from(start).expect("non-negative method start");
        let end = start
            .checked_add(count)
            .ok_or_else(|| invalid("path", "Type method range overflows host index range"))?;
        for method_index in start..end {
            ensure_not_cancelled(cancellation, "method ownership validation", method_index)?;

            let method = methods
                .get(method_index)
                .and_then(Value::as_object)
                .ok_or_else(|| invalid("path", "Type method range exceeds decoded methods"))?;
            let owner = method
                .get("declaring_type")
                .and_then(Value::as_i64)
                .ok_or_else(|| invalid("path", "Decoded method declaring type is invalid"))?;
            if owner != type_index as i64 {
                return Err(invalid(
                    "path",
                    &format!(
                        "Method {method_index} is in type {type_index}'s range but declares type {owner}"
                    ),
                ));
            }
        }
    }

    for (method_index, method) in methods.iter().enumerate() {
        ensure_not_cancelled(cancellation, "method ownership validation", method_index)?;

        let owner = method
            .get("declaring_type")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid("path", "Decoded method declaring type is invalid"))?;
        let Some(type_index) = usize::try_from(owner).ok() else {
            continue;
        };
        let type_row = types
            .get(type_index)
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("path", "Decoded method owner is outside type definitions"))?;
        let start = type_row
            .get("method_start")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid("path", "Decoded type method start is invalid"))?;
        let count = type_row
            .get("method_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("path", "Decoded type method count is invalid"))?
            as usize;
        let in_range = usize::try_from(start)
            .ok()
            .and_then(|start| start.checked_add(count).map(|end| (start, end)))
            .is_some_and(|(start, end)| method_index >= start && method_index < end);
        if !in_range {
            return Err(invalid(
                "path",
                &format!(
                    "Method {method_index} declares type {owner} but is outside its method range"
                ),
            ));
        }
    }

    Ok(())
}

fn valid_range(start: i32, count: usize, total: usize) -> bool {
    if start < -1 {
        return false;
    }
    if start == -1 {
        return count == 0;
    }
    (start as usize)
        .checked_add(count)
        .is_some_and(|end| end <= total)
}

fn invalid(path: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and retry.".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
/// `AnalysisUnsupportedTargetError` for an input outside decoder coverage.
fn unsupported(path: &str, reason: &str) -> Failure {
    Failure::new(
        "unsupported_target",
        "unsupported_target",
        format!("Unsupported target for {OPERATION} at {path}: {reason}"),
        false,
        "Select a target supported by this operation or choose an operation supporting the reported target format.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
fn resource() -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        "IL2CPP metadata exceeds the retained report budget.".into(),
        false,
        "Use a smaller metadata artifact.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("maximum_bytes", Detail::Count(MAX_OUTPUT as u64)),
        ]),
    )
}
fn cancelled() -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        "The operation was cancelled before completion.".into(),
        false,
        "Retry the operation if the result is still needed.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn ensure_not_cancelled(
    cancellation: &Cancellation,
    phase: &str,
    index: usize,
) -> Result<(), Failure> {
    if cancellation.reason().is_some() {
        return Err(cancelled_at(cancellation, phase, index));
    }

    Ok(())
}

fn cancelled_at(cancellation: &Cancellation, phase: &str, index: usize) -> Failure {
    let mut failure = cancelled();
    failure.detail("phase", Detail::Text(phase.to_owned()));
    failure.detail("index", Detail::Count(index as u64));

    if let Some(reason) = cancellation.reason() {
        failure.detail("cancellation_reason", Detail::Text(reason.to_owned()));
    }

    failure
}

fn cancelled_with_evidence(evidence: &serde_json::value::RawValue) -> Failure {
    let mut failure = Failure::new(
        "cancelled",
        "cancelled",
        "IL2CPP metadata inspection completed, but delivery was cancelled.".into(),
        false,
        "Use the retained partial observation if it is still needed.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    );
    if let Err(error) = failure.retain(evidence) {
        failure.detail(
            "partial_observation_failure",
            Detail::Text(error.to_string()),
        );
    }

    failure
}
