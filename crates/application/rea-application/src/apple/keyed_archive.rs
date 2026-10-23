//! Read-only NSKeyedArchiver projection over a stable property-list snapshot.
//!
//! The projection preserves the `$objects` table and UID edges. It never
//! instantiates archived classes or recursively expands object references.

use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use rea_core::{
    cancellation::Cancellation,
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::{Detail, Failure, InputIssue},
    json_output,
};
use rea_host::fs::stable_file::{FileAccess, Snapshot};
use rea_rust_analysis::plist;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub const OPERATION: &str = "inspect_keyed_archive";
const MAX_OBJECTS: usize = 200_000;
const MAX_REFERENCE_EDGES: usize = 200_000;
const MAX_VALUES_PER_SCAN: usize = 200_000;
const MAX_NESTING: usize = 128;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const NIB_ARCHIVE_SIGNATURE: &[u8] = b"NIBArchive";
const PROVIDER: Provider = Provider {
    id: "rust-keyed-archive-reader",
    name: "REA Rust keyed archive reader",
    version: Some("1"),
};

const LIMITATIONS: [&str; 4] = [
    "Archive classes are never instantiated. Class names and serialized fields are observed; class-specific semantics are unknown.",
    "Conditional references serialized as UID 0 cannot be distinguished from ordinary nil references. Missing fields remain absent in the raw serialized value.",
    "Root selection selects the named $top entry; object pagination retains original indices and does not recursively expand references.",
    "Standalone inspection identifies the selected plist as both target and archive; a containing app-bundle digest is not available in this local-file workflow.",
];

#[derive(Clone, Debug)]
pub struct KeyedArchiveSelection {
    pub root: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

/// Project an already decoded keyed archive without reading its source path.
///
/// Acquisition, plist decoding, and Evidence retention belong to the caller.
/// This entry point only applies the stable object-table projection to decoded
/// facts, preserving original object IDs and UID paths.
pub fn project_decoded_archive(
    value: &Value,
    target_sha256: &str,
    archive_path: &str,
    archive_sha256: &str,
    archive_format: &str,
    selection: &KeyedArchiveSelection,
) -> Result<Value, Failure> {
    let source_format = match archive_format {
        "binary-plist" => plist::Format::Binary,
        "xml-plist" => plist::Format::Xml,
        other => {
            return Err(invalid_decoded_archive(
                archive_path,
                format!("unsupported archive_format: {other}"),
            ));
        }
    };
    let projection = project_keyed_archive(value, source_format, &[], &[], selection)
        .map_err(|error| project_failure(archive_path, error))?;
    let mut limitations = LIMITATIONS
        .iter()
        .map(|limitation| (*limitation).to_owned())
        .collect::<Vec<_>>();
    limitations.sort();

    serde_json::to_value(ArchiveReport {
        target_sha256: target_sha256.to_owned(),
        archive_path: archive_path.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        archive_format: projection.format,
        roots: projection.roots,
        objects: projection.objects,
        references: projection.references,
        total_objects: projection.total_objects,
        total_references: projection.total_references,
        offset: selection.offset,
        next_offset: projection.next_offset,
        truncated: projection.truncated,
        limitations,
    })
    .map_err(|error| invalid_decoded_archive(archive_path, error.to_string()))
}

fn invalid_decoded_archive(path: &str, reason: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Decoded keyed archive facts are invalid.".into(),
        false,
        "Provide a decoded NSKeyedArchiver value and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("path".into(), Detail::Text(path.into())),
            ("reason".into(), Detail::Text(reason)),
        ]),
    )
}

#[derive(Default)]
pub struct KeyedArchiveAnalyzer;

impl ArtifactAnalyzer for KeyedArchiveAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = plist::MAX_INPUT_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(
            path,
            snapshot,
            &KeyedArchiveSelection {
                root: None,
                offset: 0,
                limit: 20_000,
            },
        )
    }
}

pub struct KeyedArchiveInspection<F: FileAccess> {
    inner: ArtifactInspection<F, KeyedArchiveAnalyzer>,
}

impl<F: FileAccess> KeyedArchiveInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
        }
    }

    pub fn with_records(
        access: Arc<F>,
        records: Arc<crate::ledger::artifact_records::ArtifactRecords>,
    ) -> Self {
        Self {
            inner: ArtifactInspection::with_records(access, records),
        }
    }

    pub fn records(&self) -> &Arc<crate::ledger::artifact_records::ArtifactRecords> {
        self.inner.records()
    }

    pub fn close(&mut self) -> Result<(), Failure> {
        self.inner.close()
    }

    pub fn inspect(
        &mut self,
        path: &str,
        selection: &KeyedArchiveSelection,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        let selection = selection.clone();
        self.inner.inspect_with_operation(
            OPERATION,
            path,
            plist::MAX_INPUT_BYTES,
            cancellation,
            completion,
            move |path, snapshot, _| build_evidence(path, snapshot, &selection),
        )
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ArchiveFormat {
    BinaryPlist,
    XmlPlist,
}

#[derive(Debug, Serialize)]
struct ArchiveReport {
    target_sha256: String,
    archive_path: String,
    archive_sha256: String,
    archive_format: ArchiveFormat,
    roots: Map<String, Value>,
    objects: Vec<ArchiveObject>,
    references: Vec<ArchiveReference>,
    total_objects: usize,
    total_references: usize,
    offset: usize,
    next_offset: Option<usize>,
    truncated: bool,
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ArchiveObject {
    id: usize,
    kind: &'static str,
    class_id: Option<u64>,
    class_name: Option<String>,
    status: &'static str,
    value: Value,
}

#[derive(Debug, Serialize)]
struct ArchiveReference {
    source: Option<usize>,
    path: Vec<PathPart>,
    target: Option<u64>,
    status: &'static str,
    raw: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum PathPart {
    Key(String),
    Index(usize),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum SourcePathPart {
    Key(String),
    Index(usize),
}

#[derive(Clone, Debug)]
struct PendingValue<'a> {
    value: &'a Value,
    path: Vec<PathPart>,
    source_path: Vec<SourcePathPart>,
}

#[derive(Clone, Debug)]
struct UidValue {
    target: Option<u64>,
    raw: Value,
}

#[derive(Debug)]
enum ProjectionError {
    Unsupported(String),
    Malformed(String),
    Limit(String),
    InvalidRoot {
        selected: String,
        available: Vec<String>,
    },
}

fn build_evidence(
    path: &str,
    snapshot: Snapshot,
    selection: &KeyedArchiveSelection,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    if snapshot.bytes.starts_with(NIB_ARCHIVE_SIGNATURE) {
        return Err(project_failure(
            path,
            ProjectionError::Unsupported(
                "the selected file is a compiled NIBArchive; decode it with decode_interface_builder".into(),
            ),
        ));
    }

    let decoded = plist::read_keyed_archive_with_provenance(&snapshot.bytes, path.to_owned())
        .map_err(|error| plist_failure(path, error))?;
    let projection = project_keyed_archive(
        &decoded.report.value,
        decoded.report.format,
        &decoded.typed_scalar_paths,
        &decoded.binary_uid_paths,
        selection,
    )
    .map_err(|error| project_failure(path, error))?;

    let digest = snapshot.sha256;
    let mut limitations = decoded.report.limitations;
    for limitation in LIMITATIONS {
        if !limitations.iter().any(|existing| existing == limitation) {
            limitations.push(limitation.into());
        }
    }
    let report = ArchiveReport {
        target_sha256: digest.clone(),
        archive_path: path.to_owned(),
        archive_sha256: digest.clone(),
        archive_format: projection.format,
        roots: projection.roots,
        objects: projection.objects,
        references: projection.references,
        total_objects: projection.total_objects,
        total_references: projection.total_references,
        offset: selection.offset,
        next_offset: projection.next_offset,
        truncated: projection.truncated,
        limitations: limitations.clone(),
    };

    let subject = Subject::new(path, digest, NativeFormat::Plist, None)
        .map_err(|error| execution_failure(path, error.to_string()))?;
    let locations = vec![Location::ArtifactPath {
        path: path.to_owned(),
    }];
    let evidence = ArtifactEvidence::new_with_parameters(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: report,
            limitations,
            locations,
        },
        json!({
            "root": selection.root,
            "offset": selection.offset,
            "limit": selection.limit,
        }),
    )
    .map_err(|error| execution_failure(path, error.to_string()))?;

    match json_output::admitted_length(&evidence, MAX_OUTPUT_BYTES) {
        Ok(_) => Ok(Arc::new(evidence)),
        Err(json_output::Error::Limit { maximum }) => Err(resource_failure(path, maximum)),
        Err(json_output::Error::Encoding(error)) => Err(execution_failure(path, error.to_string())),
    }
}

#[derive(Debug)]
struct Projection {
    format: ArchiveFormat,
    roots: Map<String, Value>,
    objects: Vec<ArchiveObject>,
    references: Vec<ArchiveReference>,
    total_objects: usize,
    total_references: usize,
    next_offset: Option<usize>,
    truncated: bool,
}

fn project_keyed_archive(
    value: &Value,
    source_format: plist::Format,
    typed_scalar_paths: &[Vec<plist::ValuePathSegment>],
    binary_uid_paths: &[Vec<plist::ValuePathSegment>],
    selection: &KeyedArchiveSelection,
) -> Result<Projection, ProjectionError> {
    let format = match source_format {
        plist::Format::Binary => ArchiveFormat::BinaryPlist,
        plist::Format::Xml => ArchiveFormat::XmlPlist,
        plist::Format::OpenStep => {
            return Err(ProjectionError::Unsupported(
                "OpenStep property lists are not supported as NSKeyedArchiver archives.".into(),
            ));
        }
    };

    let typed_scalars = source_path_set(typed_scalar_paths);
    let archive = record_at(value, &[], &typed_scalars).ok_or_else(|| {
        ProjectionError::Unsupported("the property-list root is not a dictionary".into())
    })?;
    match archive.get("$archiver") {
        Some(Value::String(name)) if name == "NSKeyedArchiver" => {}
        Some(Value::String(name)) => {
            return Err(ProjectionError::Unsupported(format!(
                "the $archiver value is {name:?}, not NSKeyedArchiver"
            )));
        }
        Some(_) => {
            return Err(ProjectionError::Unsupported(
                "the $archiver value is not a string".into(),
            ));
        }
        None => {
            return Err(ProjectionError::Unsupported(
                "the property list has no $archiver key".into(),
            ));
        }
    }

    let table = archive
        .get("$objects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProjectionError::Malformed("NSKeyedArchiver $objects is not an array".into())
        })?;
    if table.len() > MAX_OBJECTS {
        return Err(ProjectionError::Limit(format!(
            "Archive exceeds {MAX_OBJECTS} object-table entries"
        )));
    }

    let top_path = vec![SourcePathPart::Key("$top".into())];
    let top = archive
        .get("$top")
        .and_then(|top| record_at(top, &top_path, &typed_scalars))
        .ok_or_else(|| {
            ProjectionError::Malformed("NSKeyedArchiver $top is not a dictionary".into())
        })?;
    if top.is_empty() {
        return Err(ProjectionError::Malformed(
            "NSKeyedArchiver has no $top roots".into(),
        ));
    }
    if let Some(selected) = &selection.root
        && !top.contains_key(selected)
    {
        return Err(ProjectionError::InvalidRoot {
            selected: selected.clone(),
            available: top.keys().cloned().collect(),
        });
    }

    let selected_roots = select_roots(top, selection.root.as_deref());
    let uid_paths = source_path_set(binary_uid_paths);

    let mut references = Vec::new();
    let roots_pending = selected_roots
        .iter()
        .rev()
        .map(|(name, root)| PendingValue {
            value: root,
            path: vec![PathPart::Key(name.clone())],
            source_path: vec![
                SourcePathPart::Key("$top".into()),
                SourcePathPart::Key(name.clone()),
            ],
        })
        .collect();
    scan_values(
        None,
        roots_pending,
        &typed_scalars,
        &uid_paths,
        table,
        &mut references,
    )?;

    let mut objects = Vec::with_capacity(table.len().min(selection.limit));
    for (id, value) in table.iter().enumerate() {
        let source_path = vec![
            SourcePathPart::Key("$objects".into()),
            SourcePathPart::Index(id),
        ];
        scan_values(
            Some(id),
            vec![PendingValue {
                value,
                path: Vec::new(),
                source_path: source_path.clone(),
            }],
            &typed_scalars,
            &uid_paths,
            table,
            &mut references,
        )?;

        let fields = record_at(value, &source_path, &typed_scalars);
        let class_uid_path = source_path
            .iter()
            .cloned()
            .chain([SourcePathPart::Key("$class".into())])
            .collect::<Vec<_>>();
        let class_id = fields
            .and_then(|fields| fields.get("$class"))
            .and_then(|class| uid_value(class, &class_uid_path, &uid_paths))
            .and_then(|uid| uid.target);
        let class_descriptor = class_id
            .and_then(|class_id| usize::try_from(class_id).ok())
            .and_then(|class_id| table.get(class_id).map(|value| (class_id, value)))
            .and_then(|(class_id, value)| {
                let class_path = vec![
                    SourcePathPart::Key("$objects".into()),
                    SourcePathPart::Index(class_id),
                ];
                record_at(value, &class_path, &typed_scalars)
            });
        let class_name = class_descriptor
            .and_then(|descriptor| descriptor.get("$classname"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let is_nil = id == 0 && value.as_str() == Some("$null");
        let kind = if is_nil {
            "nil"
        } else if value.is_array() {
            "array"
        } else if record_at(value, &source_path, &typed_scalars).is_none() {
            "scalar"
        } else if fields
            .is_some_and(|fields| fields.get("$classname").is_some_and(Value::is_string))
        {
            "class-descriptor"
        } else if fields.is_some_and(|fields| fields.contains_key("$class")) {
            "archived-object"
        } else {
            "dictionary"
        };
        let status = if is_nil {
            "nil"
        } else if kind == "archived-object" {
            if class_name.is_some() {
                "unknown-class"
            } else {
                "unresolved-class"
            }
        } else {
            "observed"
        };

        if id >= selection.offset && objects.len() < selection.limit {
            objects.push(ArchiveObject {
                id,
                kind,
                class_id,
                class_name,
                status,
                value: project_value(value, &source_path, &typed_scalars, &uid_paths),
            });
        }
    }

    let total_objects = table.len();
    let page_end = selection.offset.saturating_add(objects.len());
    let next_offset = (page_end < total_objects).then_some(page_end);
    let truncated = selection.offset != 0 || objects.len() != total_objects;
    let total_references = references.len();
    references.retain(|reference| {
        reference
            .source
            .is_none_or(|source| source >= selection.offset && source < page_end)
    });
    let roots = selected_roots
        .iter()
        .map(|(name, root)| {
            let path = vec![
                SourcePathPart::Key("$top".into()),
                SourcePathPart::Key(name.clone()),
            ];
            (
                name.clone(),
                project_value(root, &path, &typed_scalars, &uid_paths),
            )
        })
        .collect();

    Ok(Projection {
        format,
        roots,
        objects,
        total_objects,
        total_references,
        references,
        next_offset,
        truncated,
    })
}

fn select_roots<'a>(
    top: &'a Map<String, Value>,
    selected: Option<&str>,
) -> Vec<(String, &'a Value)> {
    if let Some(selected) = selected {
        return top
            .get(selected)
            .map(|value| vec![(selected.to_owned(), value)])
            .unwrap_or_default();
    }

    let mut roots = top
        .iter()
        .map(|(name, value)| (name.clone(), value))
        .collect::<Vec<_>>();
    roots.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    roots
}

fn scan_values<'a>(
    source: Option<usize>,
    initial: Vec<PendingValue<'a>>,
    typed_scalar_paths: &BTreeSet<Vec<SourcePathPart>>,
    uid_paths: &BTreeSet<Vec<SourcePathPart>>,
    table: &[Value],
    references: &mut Vec<ArchiveReference>,
) -> Result<(), ProjectionError> {
    let mut pending = initial;
    let mut examined = 0;

    while let Some(item) = pending.pop() {
        examined += 1;
        if examined > MAX_VALUES_PER_SCAN || item.path.len() > MAX_NESTING {
            return Err(ProjectionError::Limit(format!(
                "Archive exceeds {MAX_VALUES_PER_SCAN} values per scan or {MAX_NESTING} nesting levels"
            )));
        }

        if let Some(uid) = uid_value(item.value, &item.source_path, uid_paths) {
            let status = reference_status(uid.target, table);
            references.push(ArchiveReference {
                source,
                path: item.path,
                target: uid.target,
                status,
                raw: uid.raw,
            });
            if references.len() > MAX_REFERENCE_EDGES {
                return Err(ProjectionError::Limit(format!(
                    "Archive exceeds {MAX_REFERENCE_EDGES} reference edges"
                )));
            }
            continue;
        }

        if let Some(items) = item.value.as_array() {
            for (index, child) in items.iter().enumerate().rev() {
                pending.push(PendingValue {
                    value: child,
                    path: append_path(&item.path, PathPart::Index(index)),
                    source_path: append_source_path(
                        &item.source_path,
                        SourcePathPart::Index(index),
                    ),
                });
            }
            continue;
        }

        if let Some(fields) = record_at(item.value, &item.source_path, typed_scalar_paths) {
            let mut keys = fields.keys().collect::<Vec<_>>();
            keys.sort_unstable_by(|left, right| right.cmp(left));

            for key in keys {
                let child = &fields[key];
                pending.push(PendingValue {
                    value: child,
                    path: append_path(&item.path, PathPart::Key(key.clone())),
                    source_path: append_source_path(
                        &item.source_path,
                        SourcePathPart::Key(key.clone()),
                    ),
                });
            }
        }
    }

    Ok(())
}

fn append_path(path: &[PathPart], segment: PathPart) -> Vec<PathPart> {
    let mut result = path.to_vec();
    result.push(segment);
    result
}

fn append_source_path(path: &[SourcePathPart], segment: SourcePathPart) -> Vec<SourcePathPart> {
    let mut result = path.to_vec();
    result.push(segment);
    result
}

fn uid_value(
    value: &Value,
    source_path: &[SourcePathPart],
    uid_paths: &BTreeSet<Vec<SourcePathPart>>,
) -> Option<UidValue> {
    if uid_paths.contains(source_path) {
        let wrapper = value.as_object()?;
        if wrapper.get("$plist_type").and_then(Value::as_str) != Some("uid") {
            return None;
        }
        let raw_number = wrapper.get("value").and_then(Value::as_str)?;
        let integer = raw_number.parse::<u128>().ok();
        let target = integer
            .filter(|integer| *integer <= u128::from(MAX_SAFE_INTEGER))
            .and_then(|integer| u64::try_from(integer).ok());
        let raw = target
            .map(|target| json!({"UID": target}))
            .unwrap_or_else(|| value.clone());
        return Some(UidValue { target, raw });
    }

    let fields = value.as_object()?;
    if fields.len() != 1 {
        return None;
    }
    let numeric = fields.get("UID").or_else(|| fields.get("CF$UID"))?;
    if !numeric.is_number() {
        return None;
    }

    let target = safe_uid_number(numeric);
    Some(UidValue {
        target,
        raw: value.clone(),
    })
}

fn source_path_set(paths: &[Vec<plist::ValuePathSegment>]) -> BTreeSet<Vec<SourcePathPart>> {
    paths
        .iter()
        .map(|path| {
            path.iter()
                .map(|part| match part {
                    plist::ValuePathSegment::Key(key) => SourcePathPart::Key(key.clone()),
                    plist::ValuePathSegment::Index(index) => SourcePathPart::Index(*index),
                })
                .collect()
        })
        .collect()
}

fn safe_uid_number(value: &Value) -> Option<u64> {
    let number = value.as_number()?;
    if let Some(integer) = number.as_u64() {
        return (integer <= MAX_SAFE_INTEGER).then_some(integer);
    }

    let number = number.as_f64()?;
    if !number.is_finite()
        || number.fract() != 0.0
        || number < 0.0
        || number > MAX_SAFE_INTEGER as f64
    {
        return None;
    }
    Some(number as u64)
}

fn reference_status(target: Option<u64>, table: &[Value]) -> &'static str {
    let Some(target) = target else {
        return "malformed";
    };
    let Ok(index) = usize::try_from(target) else {
        return "unresolved";
    };
    if index >= table.len() {
        return "unresolved";
    }
    if index == 0 && table.first().and_then(Value::as_str) == Some("$null") {
        return "nil";
    }
    "resolved"
}

fn project_value(
    value: &Value,
    source_path: &[SourcePathPart],
    typed_scalar_paths: &BTreeSet<Vec<SourcePathPart>>,
    uid_paths: &BTreeSet<Vec<SourcePathPart>>,
) -> Value {
    if let Some(uid) = uid_value(value, source_path, uid_paths) {
        return uid.raw;
    }
    if typed_scalar_paths.contains(source_path) {
        return value.clone();
    }
    match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .enumerate()
                .map(|(index, child)| {
                    project_value(
                        child,
                        &append_source_path(source_path, SourcePathPart::Index(index)),
                        typed_scalar_paths,
                        uid_paths,
                    )
                })
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, child)| {
                    (
                        key.clone(),
                        project_value(
                            child,
                            &append_source_path(source_path, SourcePathPart::Key(key.clone())),
                            typed_scalar_paths,
                            uid_paths,
                        ),
                    )
                })
                .collect(),
        ),
        scalar => scalar.clone(),
    }
}

fn record_at<'a>(
    value: &'a Value,
    source_path: &[SourcePathPart],
    typed_scalar_paths: &BTreeSet<Vec<SourcePathPart>>,
) -> Option<&'a Map<String, Value>> {
    if typed_scalar_paths.contains(source_path) {
        return None;
    }
    record(value)
}

fn record(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn plist_failure(path: &str, error: plist::Error) -> Failure {
    match error {
        plist::Error::InputTooLarge => resource_failure_with_reason(
            path,
            format!(
                "Keyed archive exceeds the {}-byte read limit.",
                plist::MAX_INPUT_BYTES
            ),
        ),
        plist::Error::Depth => resource_failure_with_reason(
            path,
            format!("Keyed archive exceeds the supported {MAX_NESTING}-level nesting bound."),
        ),
        plist::Error::Capacity => resource_failure_with_reason(
            path,
            "Keyed archive exceeds the bounded object or decoded-representation capacity.".into(),
        ),
        plist::Error::Invalid(reason) => parse_failure(path, reason),
    }
}

fn project_failure(path: &str, error: ProjectionError) -> Failure {
    match error {
        ProjectionError::Unsupported(reason) => Failure::new(
            "unsupported_target",
            "unsupported_target",
            "The selected property list is not a supported NSKeyedArchiver archive.".into(),
            false,
            "Select an NSKeyedArchiver property list and retry.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("path", Detail::Text(path.into())),
                ("reason", Detail::Text(reason)),
            ]),
        ),
        ProjectionError::Malformed(reason) => parse_failure(path, reason),
        ProjectionError::Limit(reason) => resource_failure_with_reason(path, reason),
        ProjectionError::InvalidRoot {
            selected,
            available,
        } => {
            let issue = InputIssue {
                path: vec!["root".into()],
                reason: "invalid_value",
                message: format!(
                    "Archive root does not exist: {selected}. Available $top roots: {}",
                    available.join(", ")
                ),
                expected: Some("an existing $top root name"),
            };
            Failure::new(
                "invalid_request",
                "invalid_input",
                "Analysis input is invalid. Check the arguments and try again.".into(),
                true,
                "Select one of the archive's $top roots or omit root.".into(),
                BTreeMap::from([
                    ("operation", Detail::Text(OPERATION.into())),
                    ("issues", Detail::Issues(vec![issue])),
                ]),
            )
        }
    }
}

fn parse_failure(path: &str, reason: String) -> Failure {
    Failure::new(
        "parse_failed",
        "analysis_output",
        "The selected property list could not be decoded as a valid keyed archive.".into(),
        false,
        "Inspect the file with a compatible property-list decoder and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

fn execution_failure(path: &str, reason: String) -> Failure {
    Failure::new(
        "execution_failed",
        "provider_execution",
        "Keyed archive inspection could not complete.".into(),
        true,
        "Check the selected local file and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

fn resource_failure(path: &str, maximum: usize) -> Failure {
    resource_failure_with_reason(
        path,
        format!("Keyed archive output exceeds the {maximum}-byte inline output budget."),
    )
}

fn resource_failure_with_reason(path: &str, reason: String) -> Failure {
    Failure::new(
        "resource_limit",
        "resource_limit",
        "Keyed archive inspection exceeded a supported resource bound.".into(),
        false,
        "Select a smaller archive or a narrower object page.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML_ARCHIVE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>$archiver</key><string>NSKeyedArchiver</string>
  <key>$version</key><integer>100000</integer>
  <key>$objects</key><array>
    <string>$null</string>
    <dict><key>$class</key><dict><key>CF$UID</key><integer>2</integer></dict><key>name</key><string>Ada</string></dict>
    <dict><key>$classname</key><string>Person</string><key>$classes</key><array><string>Person</string><string>NSObject</string></array></dict>
  </array>
  <key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict>
</dict></plist>"#;

    fn archive_projection(selection: &KeyedArchiveSelection) -> Projection {
        let decoded =
            plist::read_with_provenance(XML_ARCHIVE.as_bytes(), "/tmp/a.plist".into()).unwrap();
        project_keyed_archive(
            &decoded.report.value,
            decoded.report.format,
            &decoded.typed_scalar_paths,
            &decoded.binary_uid_paths,
            selection,
        )
        .unwrap()
    }

    #[test]
    fn projects_roots_objects_class_identity_and_reference_paths() {
        let projection = archive_projection(&KeyedArchiveSelection {
            root: None,
            offset: 0,
            limit: 20_000,
        });

        assert_eq!(projection.total_objects, 3);
        assert_eq!(projection.objects[0].kind, "nil");
        assert_eq!(projection.objects[1].kind, "archived-object");
        assert_eq!(projection.objects[1].class_id, Some(2));
        assert_eq!(projection.objects[1].class_name.as_deref(), Some("Person"));
        assert_eq!(projection.objects[1].status, "unknown-class");
        assert_eq!(projection.total_references, 2);
        assert_eq!(
            projection.references[0].path,
            vec![PathPart::Key("root".into())]
        );
        assert_eq!(projection.references[0].target, Some(1));
        assert_eq!(projection.references[1].source, Some(1));
        assert_eq!(
            projection.references[1].path,
            vec![PathPart::Key("$class".into())]
        );
        assert_eq!(projection.references[1].target, Some(2));
    }

    #[test]
    fn named_root_and_object_pagination_preserve_source_indices() {
        let projection = archive_projection(&KeyedArchiveSelection {
            root: Some("root".into()),
            offset: 1,
            limit: 1,
        });

        assert_eq!(projection.roots.len(), 1);
        assert_eq!(projection.objects.len(), 1);
        assert_eq!(projection.objects[0].id, 1);
        assert_eq!(projection.next_offset, Some(2));
        assert!(projection.truncated);
        assert_eq!(projection.references.len(), 2);
        assert_eq!(projection.references[0].source, None);
        assert_eq!(projection.references[1].source, Some(1));
    }

    #[test]
    fn rejects_unknown_named_root_with_available_names() {
        let error = archive_projection_error(&KeyedArchiveSelection {
            root: Some("missing".into()),
            offset: 0,
            limit: 1,
        });

        assert!(
            matches!(error, ProjectionError::InvalidRoot { selected, .. } if selected == "missing")
        );
    }

    #[test]
    fn only_parser_marked_binary_uid_wrappers_become_binary_uid_edges() {
        let typed_uid = json!({"$plist_type": "uid", "value": "1"});
        let ordinary_dictionary = json!({"$plist_type": "uid", "value": "1"});
        let table = vec![json!("$null"), json!("target")];
        let typed_path = vec![
            SourcePathPart::Key("$objects".into()),
            SourcePathPart::Index(1),
        ];
        let uid_paths = BTreeSet::from([typed_path.clone()]);

        assert!(uid_value(&typed_uid, &typed_path, &uid_paths).is_some());
        assert!(uid_value(&ordinary_dictionary, &[], &uid_paths).is_none());
        assert_eq!(reference_status(Some(1), &table), "resolved");
    }

    fn archive_projection_error(selection: &KeyedArchiveSelection) -> ProjectionError {
        let decoded =
            plist::read_with_provenance(XML_ARCHIVE.as_bytes(), "/tmp/a.plist".into()).unwrap();
        project_keyed_archive(
            &decoded.report.value,
            decoded.report.format,
            &decoded.typed_scalar_paths,
            &decoded.binary_uid_paths,
            selection,
        )
        .unwrap_err()
    }
}
