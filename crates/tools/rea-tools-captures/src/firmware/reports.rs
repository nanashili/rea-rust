//! Parse the pinned Binwalk and Unblob reports into portable facts.
//!
//! Compatibility owner: `src/firmware/FirmwareReports.ts`. Parsing is strict on
//! the fields it derives and lenient on unfamiliar ones, which are retained as
//! diagnostics. Protocol violations become `AnalysisOutputError`s so the
//! service maps them to `Output`.
use super::files::logical_path;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
const INSPECT: &str = "inspect_firmware_regions";
const EXTRACT: &str = "extract_firmware";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
fn output(operation: &str, reason: impl Into<String>) -> AnalysisError {
    AnalysisError::output(operation, reason)
}
/// A reported Binwalk region, in portable form.
#[derive(Clone, Debug)]
pub struct BinwalkRegion {
    pub provider_id: String,
    pub offset: u64,
    pub reported_size: u64,
    pub signature: String,
    pub description: String,
    pub reported_confidence: i64,
}
impl BinwalkRegion {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "provider_id".into(),
            Value::String(self.provider_id.clone()),
        );
        map.insert("offset".into(), Value::from(self.offset));
        map.insert("reported_size".into(), Value::from(self.reported_size));
        map.insert("signature".into(), Value::String(self.signature.clone()));
        map.insert(
            "description".into(),
            Value::String(self.description.clone()),
        );
        map.insert(
            "reported_confidence".into(),
            Value::from(self.reported_confidence),
        );
        map.insert(
            "size_basis".into(),
            Value::String("provider_reported_validation_unknown".into()),
        );
        Value::Object(map)
    }
}
fn as_object<'a>(
    value: &'a Value,
    operation: &str,
    context: &str,
) -> Result<&'a Map<String, Value>, AnalysisError> {
    value
        .as_object()
        .ok_or_else(|| output(operation, format!("{context}: expected object")))
}
fn integer(value: &Value, operation: &str, context: &str) -> Result<u64, AnalysisError> {
    let number = value
        .as_u64()
        .filter(|number| *number <= MAX_SAFE_INTEGER)
        .ok_or_else(|| output(operation, format!("{context}: expected integer")))?;
    Ok(number)
}
fn string(value: &Value, operation: &str, context: &str) -> Result<String, AnalysisError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| output(operation, format!("{context}: expected string")))
}
fn boolean(value: &Value, operation: &str, context: &str) -> Result<bool, AnalysisError> {
    value
        .as_bool()
        .ok_or_else(|| output(operation, format!("{context}: expected boolean")))
}
/// `normalizeBinwalkReport`.
pub fn normalize_binwalk(
    raw: &Value,
    input_path: &str,
    size: u64,
) -> Result<Vec<BinwalkRegion>, AnalysisError> {
    let records = raw
        .as_array()
        .ok_or_else(|| output(INSPECT, "Binwalk report must be an array"))?;
    let analysis = records.first().and_then(|record| record.get("Analysis"));
    let analysis = analysis.and_then(Value::as_object);
    let file_path = analysis
        .and_then(|analysis| analysis.get("file_path"))
        .and_then(Value::as_str);
    let extractions_len = analysis
        .and_then(|analysis| analysis.get("extractions"))
        .and_then(Value::as_object)
        .map(Map::len);
    if records.len() != 1 || file_path != Some(input_path) || extractions_len != Some(0) {
        // The structural parse must still succeed enough to classify this.
        if analysis.is_none() {
            return Err(output(INSPECT, "Binwalk report Analysis is missing"));
        }
        return Err(output(
            INSPECT,
            "Expected one inspection-only report for the selected immutable input",
        ));
    }
    let analysis = analysis.expect("analysis present");
    let file_map = analysis
        .get("file_map")
        .and_then(Value::as_array)
        .ok_or_else(|| output(INSPECT, "Binwalk report file_map is missing"))?;
    let mut regions = Vec::with_capacity(file_map.len());
    for hit in file_map {
        let hit = as_object(hit, INSPECT, "file_map entry")?;
        let offset = integer(require(hit, "offset", INSPECT)?, INSPECT, "offset")?;
        let reported_size = integer(require(hit, "size", INSPECT)?, INSPECT, "size")?;
        if offset >= size || reported_size > size - offset {
            return Err(output(
                INSPECT,
                "Reported region lies outside the selected file",
            ));
        }
        let confidence = require(hit, "confidence", INSPECT)?
            .as_i64()
            .filter(|number| (0..=255).contains(number))
            .ok_or_else(|| output(INSPECT, "confidence: expected integer 0..255"))?;
        regions.push(BinwalkRegion {
            provider_id: string(require(hit, "id", INSPECT)?, INSPECT, "id")?,
            offset,
            reported_size,
            signature: string(require(hit, "name", INSPECT)?, INSPECT, "name")?,
            description: string(
                require(hit, "description", INSPECT)?,
                INSPECT,
                "description",
            )?,
            reported_confidence: confidence,
        });
    }
    Ok(regions)
}
fn require<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    operation: &str,
) -> Result<&'a Value, AnalysisError> {
    object
        .get(key)
        .ok_or_else(|| output(operation, format!("Missing required field: {key}")))
}
// ---------------------------------------------------------------------------
// Unblob
// ---------------------------------------------------------------------------
/// A byte interval `{ offset, length }`.
#[derive(Clone, Copy, Debug)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}
impl ByteRange {
    pub fn to_value(self) -> Value {
        let mut map = Map::new();
        map.insert("offset".into(), Value::from(self.offset));
        map.insert("length".into(), Value::from(self.length));
        Value::Object(map)
    }
}
/// A normalized reported chunk.
#[derive(Clone, Debug)]
pub struct Chunk {
    pub input_path: String,
    pub provider_id: String,
    pub range: ByteRange,
    pub handler: Option<String>,
    pub encrypted: Option<bool>,
    pub root_file_range: Option<ByteRange>,
    pub extraction_failed: bool,
}
/// A parent/child derivation edge.
#[derive(Clone, Debug)]
pub struct Derivation {
    pub parent_path: String,
    pub child_path: String,
    pub provider_blob_id: String,
    pub handler: Option<String>,
    pub parent_file_range: Option<ByteRange>,
}
/// A reported file's identity facts.
#[derive(Clone, Debug)]
pub struct FileFacts {
    pub sha256: Option<String>,
    pub mime_type: Option<String>,
    pub depth: u64,
}
/// A task-wide or multi-file failing extraction stage.
#[derive(Clone, Debug)]
pub struct FailedStage {
    pub input_path: String,
    pub provider_id: Option<String>,
    pub handler: Option<String>,
    pub dependencies: Vec<String>,
    pub kind: FailedStageKind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailedStageKind {
    MissingExtractorDependency,
    ExtractorFailure,
}
/// One standalone missing-dependency row (task-wide).
#[derive(Clone, Debug)]
pub struct MissingDependencyRow {
    pub input_path: String,
    pub dependencies: Vec<String>,
}
/// One chunk-nested missing-dependency row.
#[derive(Clone, Debug)]
pub struct ChunkMissingDependencyRow {
    pub input_path: String,
    pub provider_id: String,
    pub dependencies: Vec<String>,
}
/// The fully normalized Unblob report.
#[derive(Clone, Debug)]
pub struct NormalizedUnblob {
    pub files: BTreeMap<String, FileFacts>,
    pub sizes: HashMap<String, u64>,
    pub chunks: Vec<Chunk>,
    pub derivations: Vec<Derivation>,
    pub depth_limited_paths: Vec<String>,
    pub failed_extraction_stages: Vec<FailedStage>,
    pub diagnostics: Vec<Value>,
    pub missing_dependencies: Vec<MissingDependencyRow>,
    pub chunk_missing_dependencies: Vec<ChunkMissingDependencyRow>,
    pub coverage: Coverage,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    Complete,
    Partial,
}
impl Coverage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
        }
    }
}
/// Context for `normalizeUnblobReport`.
pub struct UnblobContext<'a> {
    pub input_path: &'a str,
    pub output_root: &'a str,
    pub sha256: &'a str,
    pub length: u64,
    pub offset: u64,
    pub max_depth: u64,
}
#[derive(Default)]
struct DependencyFacts {
    names: BTreeSet<String>,
    unnamed: bool,
}
/// `dependencyNames`: collect missing-extractor names from report items.
/// Returns `None` when no accepted dependency failure was present.
fn dependency_names(reports: &[Value]) -> Option<DependencyFacts> {
    let mut names = BTreeSet::new();
    let mut unnamed = false;
    let mut reported = false;
    for item in reports {
        let object = match item.as_object() {
            Some(object) => object,
            None => continue,
        };
        if object.get("__typename__").and_then(Value::as_str)
            != Some("ExtractorDependencyNotFoundReport")
        {
            continue;
        }
        let dependencies = match object.get("dependencies").and_then(Value::as_array) {
            Some(dependencies) if dependencies.iter().all(Value::is_string) => dependencies,
            // `z.array(z.string().min(1)).min(1)` failed to parse; skip.
            _ => continue,
        };
        reported = true;
        if dependencies.is_empty() || dependencies.iter().any(|value| value.as_str() == Some("")) {
            unnamed = true;
        }
        for name in dependencies {
            if let Some(name) = name.as_str() {
                if !name.is_empty() {
                    names.insert(name.to_owned());
                }
            }
        }
    }
    reported.then_some(DependencyFacts { names, unnamed })
}
/// `dependencyRows`: expand the facts into zero or more concrete rows.
fn dependency_rows(facts: &DependencyFacts) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    if !facts.names.is_empty() {
        rows.push(facts.names.iter().cloned().collect());
    }
    if facts.unnamed {
        rows.push(Vec::new());
    }
    rows
}
/// `missingDependencies(value)`: collect named extractors from any nested report.
fn collect_missing_dependencies(value: &Value) -> Vec<String> {
    let mut found = BTreeSet::new();
    collect_missing_dependencies_into(value, &mut found);
    found.into_iter().collect()
}
fn collect_missing_dependencies_into(node: &Value, found: &mut BTreeSet<String>) {
    match node {
        Value::Array(items) => {
            for item in items {
                collect_missing_dependencies_into(item, found);
            }
        }
        Value::Object(object) => {
            if object.get("__typename__").and_then(Value::as_str)
                == Some("ExtractorDependencyNotFoundReport")
            {
                if let Some(dependencies) = object.get("dependencies").and_then(Value::as_array) {
                    if !dependencies.is_empty() && dependencies.iter().all(Value::is_string) {
                        for dependency in dependencies {
                            if let Some(name) = dependency.as_str() {
                                found.insert(name.to_owned());
                            }
                        }
                        return;
                    }
                }
            }
            for child in object.values() {
                collect_missing_dependencies_into(child, found);
            }
        }
        _ => {}
    }
}
/// `extractionDiagnostic`: name the missing extractors and producing stage.
fn extraction_diagnostic(input_path: &str, stage: Option<&str>, report: Value) -> Value {
    let dependencies = collect_missing_dependencies(&report);
    let mut map = Map::new();
    map.insert("input_path".into(), Value::String(input_path.to_owned()));
    if let Some(stage) = stage {
        map.insert("stage".into(), Value::String(stage.to_owned()));
    }
    if !dependencies.is_empty() {
        map.insert(
            "missing_dependencies".into(),
            Value::Array(dependencies.into_iter().map(Value::String).collect()),
        );
    }
    map.insert("report".into(), report);
    Value::Object(map)
}
const KNOWN_TYPES: [&str; 8] = [
    "StatReport",
    "HashReport",
    "FileMagicReport",
    "RandomnessReport",
    "ChunkReport",
    "UnknownChunkReport",
    "CarveDirectoryReport",
    "MultiFileReport",
];
fn hash_report_sha256(report: &Value) -> Result<String, AnalysisError> {
    report
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|sha| {
            sha.len() == 64
                && sha
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .map(str::to_owned)
        .ok_or_else(|| output(EXTRACT, "HashReport sha256 is not a digest"))
}
#[allow(clippy::too_many_lines)]
/// `normalizeUnblobReport`.
pub fn normalize_unblob(
    raw: &Value,
    context: &UnblobContext<'_>,
) -> Result<NormalizedUnblob, AnalysisError> {
    let records = raw
        .as_array()
        .ok_or_else(|| output(EXTRACT, "Unblob report must be an array"))?;
    // Parse each record's task + report list once.
    struct Record {
        task_path: String,
        task_depth: u64,
        task_blob_id: String,
        task_is_multi_file: bool,
        reports: Vec<Value>,
        subtasks: Vec<(String, u64, String, bool)>,
    }
    let mut parsed_records = Vec::with_capacity(records.len());
    for record in records {
        let record = as_object(record, EXTRACT, "extraction record")?;
        let task = as_object(require(record, "task", EXTRACT)?, EXTRACT, "task")?;
        let reports = require(record, "reports", EXTRACT)?
            .as_array()
            .ok_or_else(|| output(EXTRACT, "reports: expected array"))?
            .clone();
        let subtasks_raw = require(record, "subtasks", EXTRACT)?
            .as_array()
            .ok_or_else(|| output(EXTRACT, "subtasks: expected array"))?;
        let mut subtasks = Vec::with_capacity(subtasks_raw.len());
        for child in subtasks_raw {
            let child = as_object(child, EXTRACT, "subtask")?;
            subtasks.push((
                string(require(child, "path", EXTRACT)?, EXTRACT, "path")?,
                integer(require(child, "depth", EXTRACT)?, EXTRACT, "depth")?,
                string(require(child, "blob_id", EXTRACT)?, EXTRACT, "blob_id")?,
                boolean(
                    require(child, "is_multi_file", EXTRACT)?,
                    EXTRACT,
                    "is_multi_file",
                )?,
            ));
        }
        parsed_records.push(Record {
            task_path: string(require(task, "path", EXTRACT)?, EXTRACT, "path")?,
            task_depth: integer(require(task, "depth", EXTRACT)?, EXTRACT, "depth")?,
            task_blob_id: string(require(task, "blob_id", EXTRACT)?, EXTRACT, "blob_id")?,
            task_is_multi_file: boolean(
                require(task, "is_multi_file", EXTRACT)?,
                EXTRACT,
                "is_multi_file",
            )?,
            reports,
            subtasks,
        });
    }
    let logical = |path: &str| logical_path(path, context.input_path, context.output_root);
    // Exactly one root task.
    let roots: Vec<&Record> = parsed_records
        .iter()
        .filter(|record| record.task_path == context.input_path && record.task_depth == 0)
        .collect();
    if roots.len() != 1 {
        return Err(output(EXTRACT, "Expected exactly one selected input task"));
    }
    let root_hash = roots[0]
        .reports
        .iter()
        .find(|report| typename(report) == Some("HashReport"));
    let root_ok = match root_hash {
        Some(report) => hash_report_sha256(report)? == context.sha256,
        None => false,
    };
    if !root_ok {
        return Err(output(
            EXTRACT,
            "Unblob input hash disagrees with selected snapshot",
        ));
    }
    let mut files: BTreeMap<String, FileFacts> = BTreeMap::new();
    let mut sizes: HashMap<String, u64> = HashMap::new();
    let mut depths: Vec<String> = Vec::new();
    let mut failed_stages: Vec<FailedStage> = Vec::new();
    let mut diagnostics: Vec<Value> = Vec::new();
    let mut blob_origins: HashMap<String, (Option<String>, Option<ByteRange>)> = HashMap::new();
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut task_failures: HashSet<String> = HashSet::new();
    let mut missing_dependencies: BTreeMap<String, DependencyFacts> = BTreeMap::new();
    let mut chunk_missing_dependencies: HashMap<(String, String), DependencyFacts> = HashMap::new();
    for record in &parsed_records {
        let path = logical(&record.task_path)?;
        if seen.contains(&path) {
            return Err(output(EXTRACT, format!("Duplicate analysis task: {path}")));
        }
        seen.insert(path.clone());
        if record.task_depth >= context.max_depth {
            depths.push(path.clone());
        }
        let metadata = record
            .reports
            .iter()
            .find(|report| typename(report) == Some("StatReport"))
            .ok_or_else(|| output(EXTRACT, format!("Missing StatReport: {path}")))?;
        let stat = as_object(metadata, EXTRACT, "StatReport")?;
        let stat_path = string(require(stat, "path", EXTRACT)?, EXTRACT, "StatReport.path")?;
        if stat_path != record.task_path {
            return Err(output(
                EXTRACT,
                format!("StatReport is bound to another task: {path}"),
            ));
        }
        let stat_size = integer(require(stat, "size", EXTRACT)?, EXTRACT, "StatReport.size")?;
        let is_dir = boolean(require(stat, "is_dir", EXTRACT)?, EXTRACT, "is_dir")?;
        let is_file = boolean(require(stat, "is_file", EXTRACT)?, EXTRACT, "is_file")?;
        let is_link = boolean(require(stat, "is_link", EXTRACT)?, EXTRACT, "is_link")?;
        if path == "$input" && stat_size != context.length {
            return Err(output(
                EXTRACT,
                "Unblob input size disagrees with selected snapshot",
            ));
        }
        if path == "$input" && (!is_file || is_link || is_dir) {
            return Err(output(
                EXTRACT,
                "Selected input was not reported as a regular file",
            ));
        }
        sizes.insert(path.clone(), stat_size);
        if is_file && !is_link {
            let sha256 = match record
                .reports
                .iter()
                .find(|report| typename(report) == Some("HashReport"))
            {
                Some(report) => Some(hash_report_sha256(report)?),
                None => None,
            };
            let mime_type = match record
                .reports
                .iter()
                .find(|report| typename(report) == Some("FileMagicReport"))
            {
                Some(report) => Some(string(
                    require(
                        as_object(report, EXTRACT, "FileMagicReport")?,
                        "mime_type",
                        EXTRACT,
                    )?,
                    EXTRACT,
                    "mime_type",
                )?),
                None => None,
            };
            files.insert(
                path.clone(),
                FileFacts {
                    sha256,
                    mime_type,
                    depth: record.task_depth,
                },
            );
        }
        for item in &record.reports {
            let kind = typename(item).unwrap_or_default().to_owned();
            if !KNOWN_TYPES.contains(&kind.as_str()) {
                let mut diagnostic = Map::new();
                diagnostic.insert("input_path".into(), Value::String(path.clone()));
                diagnostic.insert("report".into(), item.clone());
                diagnostics.push(Value::Object(diagnostic));
            }
            note_dependencies(&mut missing_dependencies, &path, std::slice::from_ref(item));
            if kind == "ExtractorExecutionErrorReport" && !task_failures.contains(&path) {
                task_failures.insert(path.clone());
                failed_stages.push(FailedStage {
                    input_path: path.clone(),
                    provider_id: None,
                    handler: None,
                    dependencies: Vec::new(),
                    kind: FailedStageKind::ExtractorFailure,
                });
            }
            if kind == "ChunkReport" || kind == "UnknownChunkReport" {
                let region = as_object(item, EXTRACT, "chunk")?;
                let id = string(require(region, "id", EXTRACT)?, EXTRACT, "chunk.id")?;
                let start = integer(
                    require(region, "start_offset", EXTRACT)?,
                    EXTRACT,
                    "start_offset",
                )?;
                let end = integer(
                    require(region, "end_offset", EXTRACT)?,
                    EXTRACT,
                    "end_offset",
                )?;
                let region_size = integer(require(region, "size", EXTRACT)?, EXTRACT, "size")?;
                if end <= start || end > stat_size || region_size != end - start {
                    return Err(output(EXTRACT, format!("Invalid chunk bounds for {path}")));
                }
                let (handler, encrypted, extraction_failed) = if kind == "ChunkReport" {
                    let handler = string(
                        require(region, "handler_name", EXTRACT)?,
                        EXTRACT,
                        "handler_name",
                    )?;
                    let is_encrypted = boolean(
                        require(region, "is_encrypted", EXTRACT)?,
                        EXTRACT,
                        "is_encrypted",
                    )?;
                    let extraction_reports = require(region, "extraction_reports", EXTRACT)?
                        .as_array()
                        .ok_or_else(|| output(EXTRACT, "extraction_reports: expected array"))?;
                    let failed = !extraction_reports.is_empty();
                    for problem in extraction_reports {
                        diagnostics.push(extraction_diagnostic(
                            &path,
                            Some(&handler),
                            problem.clone(),
                        ));
                        note_chunk_dependencies(
                            &mut chunk_missing_dependencies,
                            &path,
                            &id,
                            std::slice::from_ref(problem),
                        );
                    }
                    (Some(handler), Some(is_encrypted), failed)
                } else {
                    (None, None, false)
                };
                add_blob_origin(
                    &mut blob_origins,
                    &path,
                    &id,
                    handler.clone(),
                    Some(ByteRange {
                        offset: start,
                        length: region_size,
                    }),
                )?;
                chunks.push(Chunk {
                    input_path: path.clone(),
                    provider_id: id,
                    range: ByteRange {
                        offset: start,
                        length: region_size,
                    },
                    handler,
                    encrypted,
                    extraction_failed,
                    root_file_range: if path == "$input" {
                        Some(ByteRange {
                            offset: context.offset + start,
                            length: region_size,
                        })
                    } else {
                        None
                    },
                });
            }
            if kind == "MultiFileReport" {
                let multi = as_object(item, EXTRACT, "MultiFileReport")?;
                let id = string(
                    require(multi, "id", EXTRACT)?,
                    EXTRACT,
                    "MultiFileReport.id",
                )?;
                let handler_name = string(
                    require(multi, "handler_name", EXTRACT)?,
                    EXTRACT,
                    "handler_name",
                )?;
                let extraction_reports = require(multi, "extraction_reports", EXTRACT)?
                    .as_array()
                    .ok_or_else(|| output(EXTRACT, "extraction_reports: expected array"))?;
                add_blob_origin(
                    &mut blob_origins,
                    &path,
                    &id,
                    Some(handler_name.clone()),
                    None,
                )?;
                if !extraction_reports.is_empty() {
                    diagnostics.push(extraction_diagnostic(
                        &path,
                        Some(&handler_name),
                        item.clone(),
                    ));
                    let dependencies = dependency_names(extraction_reports);
                    match &dependencies {
                        None => failed_stages.push(FailedStage {
                            input_path: path.clone(),
                            provider_id: Some(id.clone()),
                            handler: Some(handler_name.clone()),
                            dependencies: Vec::new(),
                            kind: FailedStageKind::ExtractorFailure,
                        }),
                        Some(facts) => {
                            for row in dependency_rows(facts) {
                                failed_stages.push(FailedStage {
                                    input_path: path.clone(),
                                    provider_id: Some(id.clone()),
                                    handler: Some(handler_name.clone()),
                                    dependencies: row,
                                    kind: FailedStageKind::MissingExtractorDependency,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    // Derivations.
    let mut records_by_path: HashMap<&str, (u64, &str, bool)> = HashMap::new();
    for record in &parsed_records {
        records_by_path.insert(
            record.task_path.as_str(),
            (
                record.task_depth,
                record.task_blob_id.as_str(),
                record.task_is_multi_file,
            ),
        );
    }
    let mut derivations: Vec<Derivation> = Vec::new();
    for record in &parsed_records {
        let parent_path = logical(&record.task_path)?;
        for (child_path, child_depth, child_blob_id, child_multi) in &record.subtasks {
            let child_logical = logical(child_path)?;
            if !seen.contains(&child_logical) {
                return Err(output(
                    EXTRACT,
                    format!("Missing child task: {child_logical}"),
                ));
            }
            let reported = records_by_path.get(child_path.as_str());
            let matches = reported.is_some_and(|(depth, blob_id, multi)| {
                *depth == *child_depth
                    && *blob_id == child_blob_id.as_str()
                    && *multi == *child_multi
            });
            if !matches {
                return Err(output(
                    EXTRACT,
                    format!("Child task identity disagrees with its analysis: {child_logical}"),
                ));
            }
            let origin = blob_origins.get(&composite_key(&parent_path, child_blob_id));
            derivations.push(Derivation {
                parent_path: parent_path.clone(),
                child_path: child_logical,
                provider_blob_id: child_blob_id.clone(),
                handler: origin.and_then(|origin| origin.0.clone()),
                parent_file_range: origin.and_then(|origin| origin.1),
            });
        }
    }
    // Reachability from `$input`.
    let mut reachable: HashSet<String> = HashSet::new();
    reachable.insert("$input".to_owned());
    let mut pending = vec!["$input".to_owned()];
    let mut children_by_parent: HashMap<String, Vec<String>> = HashMap::new();
    for edge in &derivations {
        children_by_parent
            .entry(edge.parent_path.clone())
            .or_default()
            .push(edge.child_path.clone());
    }
    while let Some(parent) = pending.pop() {
        if let Some(children) = children_by_parent.get(&parent) {
            for child in children.clone() {
                if reachable.insert(child.clone()) {
                    pending.push(child);
                }
            }
        }
    }
    if reachable.len() != seen.len() {
        return Err(output(
            EXTRACT,
            "Report contains tasks disconnected from the selected input",
        ));
    }
    depths.sort();
    failed_stages.sort_by(|left, right| stage_sort_key(left).cmp(&stage_sort_key(right)));
    let missing_dependency_rows = finalize_missing(&missing_dependencies);
    let chunk_missing_dependency_rows = finalize_chunk_missing(&chunk_missing_dependencies);
    let coverage = if !depths.is_empty()
        || !diagnostics.is_empty()
        || chunks
            .iter()
            .any(|chunk| chunk.handler.is_none() || chunk.encrypted == Some(true))
    {
        Coverage::Partial
    } else {
        Coverage::Complete
    };
    Ok(NormalizedUnblob {
        files,
        sizes,
        chunks,
        derivations,
        depth_limited_paths: depths,
        failed_extraction_stages: failed_stages,
        diagnostics,
        missing_dependencies: missing_dependency_rows,
        chunk_missing_dependencies: chunk_missing_dependency_rows,
        coverage,
    })
}
fn typename(value: &Value) -> Option<&str> {
    value.get("__typename__").and_then(Value::as_str)
}
/// `JSON.stringify([parentPath, id])`.
fn composite_key(parent: &str, id: &str) -> String {
    serde_json::to_string(&[parent, id]).unwrap_or_default()
}
fn add_blob_origin(
    origins: &mut HashMap<String, (Option<String>, Option<ByteRange>)>,
    parent_path: &str,
    id: &str,
    handler: Option<String>,
    range: Option<ByteRange>,
) -> Result<(), AnalysisError> {
    let key = composite_key(parent_path, id);
    if origins.contains_key(&key) {
        return Err(output(
            EXTRACT,
            format!("Duplicate blob identity in parent task: {parent_path} ({id})"),
        ));
    }
    origins.insert(key, (handler, range));
    Ok(())
}
fn note_dependencies(
    target: &mut BTreeMap<String, DependencyFacts>,
    path: &str,
    reports: &[Value],
) {
    if let Some(names) = dependency_names(reports) {
        let known = target.entry(path.to_owned()).or_default();
        for name in names.names {
            known.names.insert(name);
        }
        known.unnamed |= names.unnamed;
    }
}
fn note_chunk_dependencies(
    target: &mut HashMap<(String, String), DependencyFacts>,
    path: &str,
    chunk_id: &str,
    reports: &[Value],
) {
    if let Some(names) = dependency_names(reports) {
        let known = target
            .entry((path.to_owned(), chunk_id.to_owned()))
            .or_default();
        for name in names.names {
            known.names.insert(name);
        }
        known.unnamed |= names.unnamed;
    }
}
/// `${input_path}\u0000${provider_id ?? ""}` ordering key for failed stages.
fn stage_sort_key(stage: &FailedStage) -> String {
    format!(
        "{}\u{0}{}",
        stage.input_path,
        stage.provider_id.clone().unwrap_or_default()
    )
}
fn finalize_missing(map: &BTreeMap<String, DependencyFacts>) -> Vec<MissingDependencyRow> {
    // BTreeMap already orders by input_path (code-point order).
    let mut rows = Vec::new();
    for (input_path, facts) in map {
        for dependencies in dependency_rows(facts) {
            rows.push(MissingDependencyRow {
                input_path: input_path.clone(),
                dependencies,
            });
        }
    }
    rows
}
fn finalize_chunk_missing(
    map: &HashMap<(String, String), DependencyFacts>,
) -> Vec<ChunkMissingDependencyRow> {
    let mut rows = Vec::new();
    for ((input_path, provider_id), facts) in map {
        for dependencies in dependency_rows(facts) {
            rows.push(ChunkMissingDependencyRow {
                input_path: input_path.clone(),
                provider_id: provider_id.clone(),
                dependencies,
            });
        }
    }
    rows.sort_by(|left, right| {
        format!("{}\u{0}{}", left.input_path, left.provider_id)
            .cmp(&format!("{}\u{0}{}", right.input_path, right.provider_id))
    });
    rows
}
