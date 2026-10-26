//! Execution-free projection of authenticated Android artifact inventory Evidence.

use crate::javascript::graph::json::{self, Json, Obj};
use crate::javascript::semantic::value_types::JsString;
use rea_core::{
    evidence::record::{EvidenceRecord, EvidenceRecordError},
    failure::{Detail, Failure},
};
use serde_json::value::RawValue;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const OPERATION: &str = "project_android_application_graph";
const INVENTORY_OPERATION: &str = "inventory_artifact";
const MAX_BRIDGE_CANDIDATE_BYTES: usize = 2 * 1024 * 1024;

pub fn validate_input(input: &Json) -> Result<(), Failure> {
    parse_pages(input)
        .map(|_| ())
        .map_err(ProjectionInputError::into_failure)
}

/// Project authenticated inventory pages without decoding or executing APK contents.
pub fn project(input: &Json) -> Result<Json, String> {
    let pages = parse_pages(input).map_err(|error| error.to_string())?;
    project_pages(&pages)
}

/// Project authenticated inventory pages into the derived Evidence shape used by REA.
pub fn project_evidence(input: &Json) -> Result<Box<RawValue>, Failure> {
    let pages = parse_pages(input).map_err(ProjectionInputError::into_failure)?;
    let result = project_pages(&pages).map_err(|reason| invalid(&reason))?;
    let source_evidence_ids = sorted_strings(pages.iter().map(|page| page.record.evidence_id()));
    let subject = projected_subject(
        pages.first().expect("parse_pages rejects empty input"),
        result.at("root_sha256"),
    )?;
    let limitations: Json = result.at("limitations").clone();

    let unsigned = Obj::new()
        .with("subject", subject)
        .with(
            "provider",
            Obj::new()
                .with("id", "rea-android-application")
                .with("name", "REA Android application workflows")
                .with("version", "1"),
        )
        .with("analysis_profile", Json::Null)
        .with("predicate_type", "rea.android-application-graph")
        .with("operation", OPERATION)
        .with(
            "parameters",
            Obj::new().with(
                "inventory_evidence_ids",
                json::strings(source_evidence_ids.clone()),
            ),
        )
        .with("raw_result", Json::Null)
        .with("normalized_result", result)
        .with("confidence", "inferred")
        .with("authority", "analyst-inference")
        .with("environment", Json::Null)
        .with("limitations", limitations)
        .with("relationship_coverage", Json::Null)
        .with("locations", Json::array(Vec::new()))
        .with("evidence_links", json::strings(source_evidence_ids));
    let raw = RawValue::from_string(Json::from(unsigned).stringify())
        .map_err(|error| protocol_failure(&error.to_string()))?;
    let evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| protocol_failure(&error.to_string()))?;
    Ok(RawValue::from_string(evidence.raw().get().to_owned())
        .expect("validated Evidence is valid JSON"))
}

fn project_pages(pages: &[Page]) -> Result<Json, String> {
    let inventory = Inventory::assemble(pages)?;
    if inventory.root_format != "apk" {
        return Err(format!(
            "Android application projection requires APK inventory Evidence; the inventory root format is {}. APK is chosen for a ZIP archive whose name ends in .apk.",
            inventory.root_format
        ));
    }

    let entries = inventory.entries()?;
    let components = classify(&entries);
    let unavailable: Vec<Json> = entries
        .iter()
        .filter_map(|entry| entry.unavailable.clone())
        .collect();
    let managed = component_items(&components, "dex")
        .into_iter()
        .chain(component_items(&components, "jvm_classes"))
        .collect::<Vec<_>>();
    let native = component_items(&components, "native_libraries");
    let (bridges, bridge_coverage) = bridge_candidates(&managed, &native);
    let runtime_families = runtime_families(&entries, &components);
    let inventory_complete = inventory.complete;
    let budget_complete = bridge_coverage.at("status").as_str() == Some("complete");
    let mut limitations = inventory.limitations.clone();
    if !inventory.coverage_complete {
        limitations.push("Source inventory coverage is partial; absence is unknown.".into());
    }
    limitations.extend([
        "Manifest, resource, signing, and bytecode semantics require a dedicated Android provider; this projection reports exact inventory paths and hashes only.".into(),
        "Runtime families are inferred from inventory formats and paths; filename suffixes do not establish valid DEX or JVM class bytes.".into(),
        "Bridge candidates are path-based hypotheses, not decoded JNI declarations or observed runtime calls.".into(),
        "A bridge basis is inferred from the native path and is repeated for every managed component.".into(),
        "ZIP inventory cannot see the APK Signing Block, so an empty signing array does not mean the APK is unsigned.".into(),
    ]);
    if !entries
        .iter()
        .any(|entry| entry.path.as_str() == Some("AndroidManifest.xml"))
    {
        limitations.push("No root AndroidManifest.xml occurrence was observed. The APK family comes from the .apk suffix of a ZIP archive, so these bytes may not be an APK.".into());
    }
    if bridge_coverage.at("status").as_str() == Some("partial") {
        limitations.push(format!(
            "Bridge candidate pairs exceeded the projection safety budget; {} hypotheses are omitted. Component arrays still include every component from the supplied inventory pages.",
            bridge_coverage.at("omitted_candidates").num()
        ));
    }
    if !unavailable.is_empty() {
        limitations.push("Some inventoried occurrences have no authenticated content identity. Their paths and limitations are retained in unavailable_components; component absence is unknown.".into());
    }
    let unavailable_is_empty = unavailable.is_empty();

    let mut result = Obj::new()
        .with("root_sha256", inventory.root_sha256)
        .with("root_format", "apk")
        .with(
            "source_evidence_ids",
            json::strings(sorted_strings(
                pages.iter().map(|page| page.record.evidence_id()),
            )),
        )
        .with("components", components)
        .with("unavailable_components", Json::array(unavailable))
        .with("runtime_families", runtime_families)
        .with("bridge_candidates", bridges)
        .with("bridge_candidate_coverage", bridge_coverage)
        .with(
            "coverage",
            Obj::new()
                .with(
                    "status",
                    if inventory.coverage_complete
                        && inventory_complete
                        && budget_complete
                        && unavailable_is_empty
                    {
                        "complete-within-inventory"
                    } else {
                        "partial"
                    },
                )
                .with("inventory_complete", inventory_complete),
        )
        .with("limitations", json::strings(limitations));
    let digest = Json::from(result.clone()).digest();
    result.set("projection_id", format!("adp_{digest}"));
    Ok(result.into())
}

pub fn retain_result(input: &Json, result: Json) -> Result<Json, Failure> {
    validate_input(input)?;
    if result.as_obj().is_none() {
        return Err(invalid(
            "Android application graph result must be an object",
        ));
    }
    Ok(result)
}

struct Page {
    record: EvidenceRecord,
    result: Json,
}

fn parse_pages(input: &Json) -> Result<Vec<Page>, ProjectionInputError> {
    let object = input
        .as_obj()
        .ok_or_else(|| ProjectionInputError::Invalid("input must be an object".into()))?;
    if object.len() != 1 || !object.has("inventory_evidence") {
        return Err(ProjectionInputError::Invalid(
            "input must contain only inventory_evidence".into(),
        ));
    }

    let pages = object
        .get("inventory_evidence")
        .and_then(|value| match value {
            Json::Array(values) => Some(values.as_slice()),
            _ => None,
        })
        .ok_or_else(|| {
            ProjectionInputError::Invalid("inventory_evidence must be an array".into())
        })?;
    if pages.is_empty() {
        return Err(ProjectionInputError::Invalid(
            "inventory_evidence must contain at least one record".into(),
        ));
    }

    let mut ids = HashSet::new();
    let mut parsed_pages = Vec::with_capacity(pages.len());
    for page in pages {
        let raw = RawValue::from_string(page.stringify())
            .map_err(|error| ProjectionInputError::Invalid(error.to_string()))?;
        let record = EvidenceRecord::parse(&raw).map_err(ProjectionInputError::from)?;
        if record.operation_matches(INVENTORY_OPERATION) {
            parsed_pages.push(parse_inventory_page(record, &mut ids)?);
        } else if record.operation_matches("inspect_artifact") {
            parsed_pages.extend(parse_inspection_pages(record, &mut ids)?);
        } else {
            return Err(ProjectionInputError::Invalid(format!(
                "inventory Evidence operation is {}, expected {INVENTORY_OPERATION:?}",
                record.operation().get()
            )));
        }
    }
    Ok(parsed_pages)
}

fn parse_inventory_page(
    record: EvidenceRecord,
    evidence_ids: &mut HashSet<String>,
) -> Result<Page, ProjectionInputError> {
    if !evidence_ids.insert(record.evidence_id().to_owned()) {
        return Err(ProjectionInputError::Invalid(
            "inventory Evidence IDs must be unique".into(),
        ));
    }
    let normalized =
        rea_core::artifact_inventory::normalize_result_text(record.normalized_result())
            .map_err(ProjectionInputError::Invalid)?;
    let result = json::parse(normalized.get()).map_err(|error| {
        ProjectionInputError::Invalid(format!(
            "normalized inventory Evidence cannot be projected as graph JSON: {error}"
        ))
    })?;

    Ok(Page { record, result })
}

fn parse_inspection_pages(
    carrier: EvidenceRecord,
    evidence_ids: &mut HashSet<String>,
) -> Result<Vec<Page>, ProjectionInputError> {
    let inspection = json::parse(carrier.normalized_result().get()).map_err(|error| {
        ProjectionInputError::Invalid(format!("Artifact inspection result is invalid: {error}"))
    })?;
    let substeps = inspection
        .get("substeps")
        .and_then(Json::as_array)
        .ok_or_else(|| {
            ProjectionInputError::Invalid("Artifact inspection result has no substeps".into())
        })?;
    let mut pages = Vec::with_capacity(substeps.len());
    for substep in substeps {
        let evidence = substep.get("evidence").ok_or_else(|| {
            ProjectionInputError::Invalid("Artifact inspection substep has no Evidence".into())
        })?;
        let raw = RawValue::from_string(evidence.stringify())
            .map_err(|error| ProjectionInputError::Invalid(error.to_string()))?;
        let record = EvidenceRecord::parse(&raw).map_err(ProjectionInputError::from)?;
        if !record.operation_matches(INVENTORY_OPERATION) {
            return Err(ProjectionInputError::Invalid(
                "Artifact inspection substep is not inventory_artifact Evidence".into(),
            ));
        }
        pages.push(parse_inventory_page(record, evidence_ids)?);
    }
    if pages.is_empty() {
        return Err(ProjectionInputError::Invalid(
            "Artifact inspection requires inventory substeps".into(),
        ));
    }
    Ok(pages)
}

fn projected_subject(page: &Page, root_sha256: &Json) -> Result<Json, Failure> {
    if page.record.subject().get() == "null" {
        return Ok(Json::Null);
    }

    let mut subject = json::parse(page.record.subject().get())
        .map_err(|error| protocol_failure(&error.to_string()))?
        .obj();
    if subject.is_empty() && page.record.subject().get() != "{}" {
        return Err(protocol_failure(
            "authenticated Evidence subject is not an object",
        ));
    }
    let Some(Json::Object(mut digest)) = subject.get("digest").cloned() else {
        return Err(protocol_failure(
            "authenticated Evidence subject has no digest object",
        ));
    };
    digest.set("sha256", root_sha256.clone());
    subject.set("digest", digest);
    subject.set("format", "apk");

    Ok(subject.into())
}

#[derive(Debug)]
enum ProjectionInputError {
    Invalid(String),
    EvidenceIntegrity(String),
}

impl ProjectionInputError {
    fn into_failure(self) -> Failure {
        match self {
            Self::Invalid(reason) => invalid(&reason),
            Self::EvidenceIntegrity(reason) => Failure::new(
                "evidence_integrity_mismatch",
                "integrity_mismatch",
                reason.clone(),
                false,
                "Supply an unchanged, authenticated inventory Evidence record.".into(),
                BTreeMap::from([
                    ("operation", Detail::Text(OPERATION.into())),
                    ("reason", Detail::Text(reason)),
                ]),
            ),
        }
    }
}

impl std::fmt::Display for ProjectionInputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) | Self::EvidenceIntegrity(reason) => formatter.write_str(reason),
        }
    }
}

impl From<EvidenceRecordError> for ProjectionInputError {
    fn from(error: EvidenceRecordError) -> Self {
        let reason = error.to_string();
        match error {
            EvidenceRecordError::SemanticIdMismatch => Self::EvidenceIntegrity(reason),
            _ => Self::Invalid(reason),
        }
    }
}

struct Inventory {
    root_sha256: String,
    root_format: String,
    nodes: HashMap<String, Json>,
    occurrences: Vec<Json>,
    coverage_complete: bool,
    complete: bool,
    limitations: Vec<String>,
}

impl Inventory {
    fn assemble(pages: &[Page]) -> Result<Self, String> {
        let (manifest, coverage) = shared_inventory_context(pages)?;
        let nodes = merge_inventory_members(pages, "nodes", "artifact_id", "node")?;
        let occurrences =
            merge_inventory_members(pages, "occurrences", "occurrence_id", "occurrence")?;
        let edges = merge_inventory_members(pages, "edges", "edge_id", "edge")?;
        let mut limitations = collect_limitations(pages);

        let root_sha256 = manifest
            .get("root_sha256")
            .and_then(Json::as_str)
            .ok_or("inventory manifest has no root_sha256")?
            .to_owned();
        let root_format = manifest
            .get("root_format")
            .and_then(Json::as_str)
            .ok_or("inventory manifest has no root_format")?
            .to_owned();
        let node_count = manifest_count(&manifest, "node_count", "nodes")?;
        let occurrence_count = manifest_count(&manifest, "occurrence_count", "occurrences")?;
        let edge_count = manifest_count(&manifest, "edge_count", "edges")?;
        let coverage_complete = coverage.get("scope").and_then(Json::as_str)
            == Some("container-entries")
            && coverage.get("status").and_then(Json::as_str) == Some("complete");
        let mut occurrences: Vec<Json> = occurrences.into_values().collect();
        occurrences.sort_by(|a, b| {
            a.at("logical_path")
                .text()
                .compare_code_points(b.at("logical_path").text())
        });
        let complete = nodes.len() as u64 == node_count
            && occurrences.len() as u64 == occurrence_count
            && edges.len() as u64 == edge_count;
        limitations.sort_by(|a, b| cmp_unicode_codepoints(a, b));
        Ok(Self {
            root_sha256,
            root_format,
            nodes,
            occurrences,
            coverage_complete,
            complete,
            limitations,
        })
    }

    fn entries(&self) -> Result<Vec<Entry>, String> {
        self.occurrences
            .iter()
            .filter(|occurrence| occurrence.at("logical_path").as_str() != Some("."))
            .map(|occurrence| self.entry(occurrence))
            .collect()
    }

    fn entry(&self, occurrence: &Json) -> Result<Entry, String> {
        let path = occurrence
            .get("logical_path")
            .and_then(Json::as_js_string)
            .ok_or("inventory occurrence has no logical_path")?
            .clone();
        let kind = occurrence
            .get("entry_kind")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let format = occurrence
            .get("artifact_format")
            .and_then(Json::as_str)
            .unwrap_or("unknown")
            .to_owned();

        let unavailable = if occurrence.at("artifact_id").is_null() {
            Some(
                Obj::new()
                    .with("path", path.clone())
                    .with("artifact_id", Json::Null)
                    .with("sha256", Json::Null)
                    .with("format", format.clone())
                    .with(
                        "encrypted",
                        occurrence.at("encrypted").as_bool().unwrap_or(false),
                    )
                    .with("limitations", occurrence.at("limitations").clone())
                    .into(),
            )
        } else {
            None
        };
        let component = if unavailable.is_none() {
            Some(self.component(occurrence, &path, &format)?)
        } else {
            None
        };

        Ok(Entry {
            path,
            kind,
            component,
            unavailable,
        })
    }

    fn component(&self, occurrence: &Json, path: &JsString, format: &str) -> Result<Json, String> {
        let id = occurrence
            .get("artifact_id")
            .and_then(Json::as_str)
            .ok_or("inventory occurrence has invalid artifact_id")?;
        let node = self
            .nodes
            .get(id)
            .ok_or("Application projection occurrence has no artifact node")?;
        let sha256 = node
            .get("sha256")
            .cloned()
            .ok_or("inventory node has no sha256")?;

        Ok(Obj::new()
            .with("path", path)
            .with("artifact_id", id)
            .with("sha256", sha256)
            .with("format", format)
            .into())
    }
}

fn shared_inventory_context(pages: &[Page]) -> Result<(Json, Json), String> {
    let first = pages.first().ok_or("inventory requires Evidence pages")?;
    let manifest = first
        .result
        .get("manifest")
        .cloned()
        .ok_or("inventory has no manifest")?;
    let coverage = first
        .result
        .get("coverage")
        .cloned()
        .ok_or("inventory result has no coverage")?;

    for page in pages.iter().skip(1) {
        if page.result.get("manifest") != Some(&manifest) {
            return Err("inventory pages do not share one manifest".into());
        }
        if page.result.get("coverage") != Some(&coverage) {
            return Err("inventory pages do not share one coverage declaration".into());
        }
    }

    Ok((manifest, coverage))
}

fn merge_inventory_members(
    pages: &[Page],
    collection_name: &str,
    identity_field: &str,
    member_name: &str,
) -> Result<HashMap<String, Json>, String> {
    let mut members = HashMap::new();

    for page in pages {
        let items = page
            .result
            .get(collection_name)
            .and_then(|value| match value {
                Json::Array(items) => Some(items.as_slice()),
                _ => None,
            })
            .ok_or_else(|| format!("inventory result {collection_name} must be an array"))?;

        for item in items {
            let id = item
                .get(identity_field)
                .and_then(Json::as_str)
                .ok_or_else(|| format!("inventory {member_name} has no {identity_field}"))?;
            merge_value(&mut members, id, item)?;
        }
    }

    Ok(members)
}

fn manifest_count(manifest: &Json, field: &str, member_name: &str) -> Result<u64, String> {
    manifest
        .get(field)
        .and_then(Json::as_f64)
        .and_then(|value| {
            (value.is_finite() && value >= 0.0 && value.fract() == 0.0).then_some(value as u64)
        })
        .ok_or_else(|| format!("inventory manifest has no valid {member_name} count"))
}

fn collect_limitations(pages: &[Page]) -> Vec<String> {
    let mut limitations = HashSet::new();

    for page in pages {
        let Some(values) = page
            .result
            .get("limitations")
            .and_then(|value| match value {
                Json::Array(items) => Some(items.as_slice()),
                _ => None,
            })
        else {
            continue;
        };
        limitations.extend(values.iter().filter_map(Json::as_str).map(str::to_owned));
    }

    limitations.into_iter().collect()
}

struct Entry {
    path: JsString,
    kind: String,
    component: Option<Json>,
    unavailable: Option<Json>,
}

fn merge_value(map: &mut HashMap<String, Json>, id: &str, value: &Json) -> Result<(), String> {
    if let Some(existing) = map.get(id) {
        if existing != value {
            return Err(format!("inventory member {id} differs across pages"));
        }
    } else {
        map.insert(id.to_owned(), value.clone());
    }
    Ok(())
}

fn classify(entries: &[Entry]) -> Obj {
    let names = [
        "manifests",
        "resources",
        "dex",
        "jvm_classes",
        "native_libraries",
        "javascript",
        "signing",
    ];
    let mut output = Obj::new();
    for name in names {
        let values = entries
            .iter()
            .filter_map(|entry| {
                if !matches!(entry.kind.as_str(), "file" | "slice") {
                    return None;
                }

                let component = entry.component.as_ref()?;
                let path = entry.path.as_str().unwrap_or("");
                let format = component.get("format").and_then(Json::as_str).unwrap_or("");
                let matched = match name {
                    "manifests" => path_segment_suffix(path, "AndroidManifest.xml"),
                    "resources" => path_segment_suffix(path, "resources.arsc"),
                    "dex" => path_segment_with_extension(path, ".dex"),
                    "jvm_classes" => path_segment_with_extension(path, ".class"),
                    "native_libraries" => format == "elf" || android_native_library_path(path),
                    "javascript" => format == "javascript-bundle",
                    "signing" => android_signing_path(path),
                    _ => false,
                };
                matched.then(|| component.clone())
            })
            .collect::<Vec<_>>();
        output.set(name, Json::array(values));
    }
    output
}

fn runtime_families(entries: &[Entry], components: &Obj) -> Json {
    let mut families = HashSet::new();
    if !component_items(components, "dex").is_empty() {
        families.insert("dalvik-art");
    }
    if !component_items(components, "jvm_classes").is_empty() {
        families.insert("java-kotlin");
    }
    if entries
        .iter()
        .filter(|entry| matches!(entry.kind.as_str(), "file" | "slice"))
        .any(|entry| {
            entry
                .component
                .as_ref()
                .and_then(|v| v.get("format"))
                .and_then(Json::as_str)
                == Some("elf")
        })
    {
        families.insert("native");
    }
    if entries
        .iter()
        .filter(|entry| matches!(entry.kind.as_str(), "file" | "slice"))
        .any(|entry| {
            entry
                .component
                .as_ref()
                .and_then(|v| v.get("format"))
                .and_then(Json::as_str)
                == Some("javascript-bundle")
        })
    {
        families.insert("javascript");
    }
    for entry in entries
        .iter()
        .filter(|entry| matches!(entry.kind.as_str(), "file" | "slice"))
    {
        if let Some(family) = entry.path.as_str().and_then(native_convention) {
            families.insert(family);
        }
    }
    let mut values: Vec<_> = families.into_iter().collect();
    values.sort_by(|a, b| cmp_unicode_codepoints(a, b));
    Json::array(values.into_iter().map(Json::from).collect())
}

fn component_items<'a>(components: &'a Obj, name: &str) -> Vec<&'a Json> {
    components
        .get(name)
        .and_then(|value| match value {
            Json::Array(items) => Some(items.iter().collect()),
            _ => None,
        })
        .unwrap_or_default()
}

fn bridge_candidates(managed: &[&Json], native: &[&Json]) -> (Json, Json) {
    let total = managed.len().saturating_mul(native.len());
    let mut candidates = Vec::new();
    let mut estimated = 2usize;
    'outer: for left in managed {
        for right in native {
            let managed_path = left.at("path").text();
            let native_path = right.at("path").text();
            let basis = native_path
                .as_str()
                .map(bridge_basis)
                .unwrap_or("managed-and-native-content");
            let candidate: Json = Obj::new()
                .with("managed_path", managed_path)
                .with("native_path", native_path)
                .with("basis", basis)
                .into();
            let bytes = candidate.stringify().len();
            let additional = bytes + usize::from(!candidates.is_empty());
            if total > 0 && estimated.saturating_add(additional) > MAX_BRIDGE_CANDIDATE_BYTES {
                break 'outer;
            }
            estimated += additional;
            candidates.push(candidate);
        }
    }
    let emitted = candidates.len();
    (
        Json::array(candidates),
        Obj::new()
            .with(
                "status",
                if emitted == total {
                    "complete"
                } else {
                    "partial"
                },
            )
            .with("total_candidates", total)
            .with("emitted_candidates", emitted)
            .with("omitted_candidates", total - emitted)
            .into(),
    )
}

fn native_convention(path: &str) -> Option<&'static str> {
    for segment in path.split('/').map(|segment| segment.to_ascii_lowercase()) {
        match segment.as_str() {
            "react.framework"
            | "reactnative.framework"
            | "libreactnative.so"
            | "libreactnativejni.so"
            | "libhermes_executor.so"
            | "libhermes.so"
            | "hermes.framework" => return Some("react-native"),
            "libflutter.so" | "flutter.framework" => return Some("flutter"),
            "libunity.so" | "unityframework.framework" => return Some("unity"),
            _ => {}
        }
    }
    None
}

fn bridge_basis(path: &str) -> &'static str {
    match native_convention(path) {
        Some("react-native") => "react-native-convention",
        Some("flutter") => "flutter-convention",
        Some("unity") => "unity-convention",
        _ if android_native_library_path(path) => "jni-library-convention",
        _ => "managed-and-native-content",
    }
}

/// Match a filename only when it occupies a complete path segment.
///
/// The TypeScript projector's regular expressions require either the root or
/// a slash before the filename. A plain suffix check would classify names such
/// as `backupAndroidManifest.xml` as Android components.
fn path_segment_suffix(path: &str, suffix: &str) -> bool {
    path == suffix
        || path
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('/'))
}

/// Match a non-empty, case-insensitive filename segment with the given suffix.
fn path_segment_with_extension(path: &str, extension: &str) -> bool {
    let Some(filename) = path.rsplit('/').next() else {
        return false;
    };
    let folded = filename.to_ascii_lowercase();
    folded.len() > extension.len() && folded.ends_with(&extension.to_ascii_lowercase())
}

/// Android native libraries require the `lib/<abi>/<name>.so` layout.
fn android_native_library_path(path: &str) -> bool {
    let mut segments = path.split('/');
    let Some(first) = segments.next() else {
        return false;
    };
    let Some(abi) = segments.next() else {
        return false;
    };
    let Some(filename) = segments.next() else {
        return false;
    };
    first.eq_ignore_ascii_case("lib")
        && !abi.is_empty()
        && segments.next().is_none()
        && path_segment_with_extension(filename, ".so")
}

/// Signing records are files directly below the `META-INF` directory.
fn android_signing_path(path: &str) -> bool {
    let mut segments = path.split('/');
    let Some(directory) = segments.next() else {
        return false;
    };
    let Some(filename) = segments.next() else {
        return false;
    };
    directory.eq_ignore_ascii_case("META-INF")
        && segments.next().is_none()
        && [".mf", ".rsa", ".dsa", ".ec", ".sf"]
            .iter()
            .any(|suffix| path_segment_with_extension(filename, suffix))
}

fn sorted_strings<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut result: Vec<_> = values.map(str::to_owned).collect();
    result.sort_by(|a, b| cmp_unicode_codepoints(a, b));
    result
}
fn cmp_unicode_codepoints(left: impl AsRef<str>, right: impl AsRef<str>) -> std::cmp::Ordering {
    left.as_ref().chars().cmp(right.as_ref().chars())
}

fn invalid(reason: &str) -> Failure {
    Failure::new("invalid_request", "invalid_input", reason.to_owned(), false, "Provide one or more authenticated APK inventory Evidence records for execution-free projection.".into(), BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]))
}

fn protocol_failure(reason: &str) -> Failure {
    Failure::new(
        "provider_protocol_error",
        "provider_protocol_error",
        "Android application projection could not commit valid Evidence.".into(),
        false,
        "Check the retained inventory Evidence and retry the projection.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn graph(value: &Value) -> Json {
        json::parse(&serde_json::to_string(value).expect("fixture JSON")).expect("graph JSON")
    }

    fn inventory_fixture() -> Value {
        serde_json::json!({
            "inventory_evidence": [{
                "evidence_id": "ev_1111111111111111111111111111111111111111111111111111111111111111",
                "operation": "inventory_artifact",
                "normalized_result": {
                    "manifest": {
                        "manifest_id": "agm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "root_artifact_id": "art_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "root_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "root_format": "apk",
                        "graph_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                        "node_count": 2,
                        "occurrence_count": 2,
                        "edge_count": 0
                    },
                    "nodes": [
                        {
                            "artifact_id": "art_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "format": "zip",
                            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "size": 100,
                            "media_type": null,
                            "architecture": null,
                            "content_state": "materialized",
                            "limitations": []
                        },
                        {
                            "artifact_id": "art_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "format": "file",
                            "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "size": 1,
                            "media_type": null,
                            "architecture": null,
                            "content_state": "materialized",
                            "limitations": []
                        }
                    ],
                    "occurrences": [
                        {
                            "occurrence_id": "occ_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "artifact_id": "art_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "parent_occurrence_id": null,
                            "logical_path": ".",
                            "entry_kind": "file",
                            "artifact_kind": "container",
                            "artifact_format": "apk",
                            "declared_size": 100,
                            "compressed_size": null,
                            "executable": false,
                            "encrypted": false,
                            "hash_status": "verified",
                            "source_location": null,
                            "limitations": []
                        },
                        {
                            "occurrence_id": "occ_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "artifact_id": "art_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "parent_occurrence_id": "occ_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "logical_path": "classes.dex",
                            "entry_kind": "file",
                            "artifact_kind": "resource",
                            "artifact_format": "file",
                            "declared_size": 1,
                            "compressed_size": null,
                            "executable": false,
                            "encrypted": false,
                            "hash_status": "verified",
                            "source_location": null,
                            "limitations": []
                        }
                    ],
                    "edges": [],
                    "provenance": [],
                    "integrity_contradictions": [],
                    "coverage": {"scope": "container-entries", "status": "complete"},
                    "limitations": []
                }
            }]
        })
    }

    fn input() -> Value {
        let fixture = inventory_fixture();
        let result = fixture["inventory_evidence"][0]["normalized_result"].clone();
        input_with_result(result)
    }

    fn input_with_result(result: Value) -> Value {
        let unsigned = serde_json::json!({
            "subject": {
                "name": "fixture.apk",
                "digest": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                "format": "apk",
                "architecture": null,
                "local_path": "/tmp/fixture.apk"
            },
            "provider": {"id": "rea-artifact-inventory", "name": "REA artifact inventory", "version": "1"},
            "analysis_profile": null,
            "predicate_type": "rea.artifact-inventory",
            "operation": INVENTORY_OPERATION,
            "parameters": {"path": "/tmp/fixture.apk"},
            "raw_result": null,
            "normalized_result": result,
            "confidence": "observed",
            "authority": "shipped-artifact",
            "environment": null,
            "limitations": [],
            "relationship_coverage": null,
            "locations": [],
            "evidence_links": []
        });
        let raw = serde_json::value::to_raw_value(&unsigned).expect("unsigned Evidence JSON");
        let record =
            EvidenceRecord::create_unsigned(&raw).expect("authenticated inventory Evidence");
        let evidence: Value = serde_json::from_str(record.raw().get()).expect("Evidence JSON");
        serde_json::json!({"inventory_evidence": [evidence]})
    }

    #[test]
    fn accepts_inventory_evidence() {
        validate_input(&graph(&input())).expect("valid Android graph input");
        assert!(project(&graph(&input())).is_ok());
    }

    #[test]
    fn rejects_occurrence_without_producer_artifact_kind() {
        let mut inventory =
            inventory_fixture()["inventory_evidence"][0]["normalized_result"].clone();
        inventory["occurrences"][0]
            .as_object_mut()
            .expect("occurrence object")
            .remove("artifact_kind");
        let failure = validate_input(&graph(&input_with_result(inventory)))
            .expect_err("artifact_kind is required by the producer contract");

        assert_eq!(failure.code(), "invalid_request");
    }

    #[test]
    fn excludes_non_file_occurrences_from_components_and_runtime_families() {
        let mut inventory =
            inventory_fixture()["inventory_evidence"][0]["normalized_result"].clone();
        inventory["occurrences"][1]["entry_kind"] = Value::String("directory".into());
        let fixture = input_with_result(inventory);

        let projection: Value = serde_json::from_str(
            &project(&graph(&fixture))
                .expect("valid directory occurrence")
                .stringify(),
        )
        .expect("projection JSON");

        assert!(
            projection["components"]["dex"]
                .as_array()
                .expect("component list")
                .is_empty()
        );
        assert!(
            projection["runtime_families"]
                .as_array()
                .expect("runtime families")
                .is_empty()
        );
    }

    #[test]
    fn inventory_completeness_includes_manifest_edge_counts() {
        let mut inventory =
            inventory_fixture()["inventory_evidence"][0]["normalized_result"].clone();
        inventory["manifest"]["edge_count"] = Value::from(1);
        let fixture = input_with_result(inventory);

        let projection: Value = serde_json::from_str(
            &project(&graph(&fixture))
                .expect("inventory with omitted edge remains usable")
                .stringify(),
        )
        .expect("projection JSON");

        assert_eq!(projection["coverage"]["inventory_complete"], false);
    }

    #[test]
    fn rejects_inventory_evidence_with_a_forged_semantic_id() {
        let mut fixture = input();
        fixture["inventory_evidence"][0]["normalized_result"]["limitations"] =
            serde_json::json!(["changed after the evidence id was committed"]);

        let failure = validate_input(&graph(&fixture)).expect_err("modified Evidence is rejected");

        assert_eq!(failure.code(), "evidence_integrity_mismatch");
    }

    #[test]
    fn emits_derived_evidence_linked_to_authenticated_inventory_sources() {
        let fixture = input();
        let source_id = fixture["inventory_evidence"][0]["evidence_id"]
            .as_str()
            .expect("source id")
            .to_owned();

        let projected = project_evidence(&graph(&fixture)).expect("derived Evidence");
        let record = EvidenceRecord::parse(&projected).expect("authenticated derived Evidence");
        let subject: Value = serde_json::from_str(record.subject().get()).expect("subject JSON");
        let evidence: Value = serde_json::from_str(record.raw().get()).expect("Evidence JSON");

        assert_eq!(
            record.operation().get(),
            "\"project_android_application_graph\""
        );
        assert_eq!(record.authority().get(), "\"analyst-inference\"");
        assert_eq!(subject["format"], "apk");
        assert_eq!(subject["local_path"], "/tmp/fixture.apk");
        assert_eq!(evidence["evidence_links"][0], source_id);
    }
    #[test]
    fn rejects_empty_inventory() {
        assert!(validate_input(&graph(&serde_json::json!({"inventory_evidence": []}))).is_err());
    }
    #[test]
    fn rejects_inventory_without_identity() {
        assert!(validate_input(&graph(&serde_json::json!({"inventory_evidence": [{}]}))).is_err());
    }
}
