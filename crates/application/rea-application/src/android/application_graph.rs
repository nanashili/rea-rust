//! Execution-free projection of authenticated Android artifact inventory Evidence.

use crate::artifacts;
use rea_core::{
    canonical_json,
    evidence::record::{EvidenceRecord, EvidenceRecordError},
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const OPERATION: &str = "project_android_application_graph";
const INVENTORY_OPERATION: &str = "inventory_artifact";
const MAX_BRIDGE_CANDIDATE_BYTES: usize = 2 * 1024 * 1024;

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    parse_pages(input)
        .map(|_| ())
        .map_err(ProjectionInputError::into_failure)
}

/// Project authenticated inventory pages without decoding or executing APK contents.
pub fn project(input: &Value) -> Result<Value, String> {
    let pages = parse_pages(input).map_err(|error| error.to_string())?;
    project_pages(&pages)
}

/// Project authenticated inventory pages into the derived Evidence shape used by REA.
pub fn project_evidence(input: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let pages = parse_pages(input).map_err(ProjectionInputError::into_failure)?;
    let result = project_pages(&pages).map_err(|reason| invalid(&reason))?;
    let source_evidence_ids = sorted_strings(pages.iter().map(|page| page.record.evidence_id()));
    let subject = projected_subject(
        pages.first().expect("parse_pages rejects empty input"),
        &result["root_sha256"],
    )?;
    let limitations = result["limitations"].clone();

    let unsigned = json!({
        "subject": subject,
        "provider": {
            "id": "rea-android-application",
            "name": "REA Android application workflows",
            "version": "1"
        },
        "analysis_profile": null,
        "predicate_type": "rea.android-application-graph",
        "operation": OPERATION,
        "parameters": {"inventory_evidence_ids": source_evidence_ids.clone()},
        "raw_result": null,
        "normalized_result": result,
        "confidence": "inferred",
        "authority": "analyst-inference",
        "environment": null,
        "limitations": limitations,
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": source_evidence_ids
    });
    let raw = serde_json::value::to_raw_value(&unsigned)
        .map_err(|error| protocol_failure(&error.to_string()))?;
    let evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| protocol_failure(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(evidence.raw().get().to_owned())
            .expect("validated Evidence is valid JSON"),
    )
}

fn project_pages(pages: &[Page]) -> Result<Value, String> {
    let inventory = Inventory::assemble(pages)?;
    if inventory.root_format != "apk" {
        return Err(format!(
            "Android application projection requires APK inventory Evidence; the inventory root format is {}",
            inventory.root_format
        ));
    }

    let entries = inventory.entries()?;
    let components = classify(&entries);
    let unavailable: Vec<Value> = entries
        .iter()
        .filter_map(|entry| entry.unavailable.clone())
        .collect();
    let managed = components["dex"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(components["jvm_classes"].as_array().into_iter().flatten())
        .collect::<Vec<_>>();
    let native = components["native_libraries"]
        .as_array()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let (bridges, bridge_coverage) = bridge_candidates(&managed, &native);
    let runtime_families = runtime_families(&entries, &components);
    let inventory_complete = inventory.complete;
    let budget_complete = bridge_coverage["status"] == "complete";
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
        .any(|entry| entry.path == "AndroidManifest.xml")
    {
        limitations.push("No root AndroidManifest.xml occurrence was observed. The APK family comes from the .apk suffix of a ZIP archive, so these bytes may not be an APK.".into());
    }
    if bridge_coverage["status"] == "partial" {
        limitations.push(format!("Bridge candidate pairs exceeded the projection safety budget; {} hypotheses are omitted. Component arrays still include every component from the supplied inventory pages.", bridge_coverage["omitted_candidates"]));
    }
    if !unavailable.is_empty() {
        limitations.push("Some inventoried occurrences have no authenticated content identity. Their paths and limitations are retained in unavailable_components; component absence is unknown.".into());
    }

    let mut result = json!({
        "root_sha256": inventory.root_sha256,
        "root_format": "apk",
        "source_evidence_ids": sorted_strings(
            pages
                .iter()
                .map(|page| page.record.evidence_id()),
        ),
        "components": components,
        "unavailable_components": unavailable,
        "runtime_families": runtime_families,
        "bridge_candidates": bridges,
        "bridge_candidate_coverage": bridge_coverage,
        "coverage": {
            "status": if inventory.coverage_complete && inventory_complete && budget_complete && unavailable.is_empty() { "complete-within-inventory" } else { "partial" },
            "inventory_complete": inventory_complete,
        },
        "limitations": limitations,
    });
    let digest = canonical_json::digest(&result).map_err(|error| error.to_string())?;
    result["projection_id"] = Value::String(format!("adp_{digest}"));
    Ok(result)
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid(
            "Android application graph result must be an object",
        ));
    }
    Ok(result)
}

struct Page {
    record: EvidenceRecord,
    result: Value,
}

fn parse_pages(input: &Value) -> Result<Vec<Page>, ProjectionInputError> {
    let object = input
        .as_object()
        .ok_or_else(|| ProjectionInputError::Invalid("input must be an object".into()))?;
    if object.len() != 1 || !object.contains_key("inventory_evidence") {
        return Err(ProjectionInputError::Invalid(
            "input must contain only inventory_evidence".into(),
        ));
    }

    let pages = object
        .get("inventory_evidence")
        .and_then(Value::as_array)
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
        parsed_pages.push(parse_page(page, &mut ids)?);
    }
    Ok(parsed_pages)
}

fn parse_page(
    page: &Value,
    evidence_ids: &mut HashSet<String>,
) -> Result<Page, ProjectionInputError> {
    if !page.is_object() {
        return Err(ProjectionInputError::Invalid(
            "inventory Evidence must be an object".into(),
        ));
    }

    let raw = serde_json::value::to_raw_value(page)
        .map_err(|error| ProjectionInputError::Invalid(error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(ProjectionInputError::from)?;
    if !record.operation_matches(INVENTORY_OPERATION) {
        return Err(ProjectionInputError::Invalid(format!(
            "inventory Evidence operation is {}, expected {INVENTORY_OPERATION:?}",
            record.operation().get()
        )));
    }
    if !evidence_ids.insert(record.evidence_id().to_owned()) {
        return Err(ProjectionInputError::Invalid(
            "inventory Evidence IDs must be unique".into(),
        ));
    }
    let result = serde_json::from_str(record.normalized_result().get()).map_err(|error| {
        ProjectionInputError::Invalid(format!(
            "inventory Evidence normalized_result is invalid: {error}"
        ))
    })?;
    let result = artifacts::inventory_evidence::normalize_result(result)
        .map_err(ProjectionInputError::Invalid)?;

    Ok(Page { record, result })
}

fn projected_subject(page: &Page, root_sha256: &Value) -> Result<Value, Failure> {
    if page.record.subject().get() == "null" {
        return Ok(Value::Null);
    }

    let mut subject: Value = serde_json::from_str(page.record.subject().get())
        .map_err(|error| protocol_failure(&error.to_string()))?;
    let Some(subject) = subject.as_object_mut() else {
        return Err(protocol_failure(
            "authenticated Evidence subject is not an object",
        ));
    };
    let Some(digest) = subject.get_mut("digest").and_then(Value::as_object_mut) else {
        return Err(protocol_failure(
            "authenticated Evidence subject has no digest object",
        ));
    };
    digest.insert("sha256".into(), root_sha256.clone());
    subject.insert("format".into(), Value::String("apk".into()));

    Ok(Value::Object(subject.clone()))
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
    nodes: HashMap<String, Value>,
    occurrences: Vec<Value>,
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
            .and_then(Value::as_str)
            .ok_or("inventory manifest has no root_sha256")?
            .to_owned();
        let root_format = manifest
            .get("root_format")
            .and_then(Value::as_str)
            .ok_or("inventory manifest has no root_format")?
            .to_owned();
        let node_count = manifest_count(&manifest, "node_count", "nodes")?;
        let occurrence_count = manifest_count(&manifest, "occurrence_count", "occurrences")?;
        let edge_count = manifest_count(&manifest, "edge_count", "edges")?;
        let coverage_complete = coverage.get("scope").and_then(Value::as_str)
            == Some("container-entries")
            && coverage.get("status").and_then(Value::as_str) == Some("complete");
        let mut occurrences: Vec<Value> = occurrences.into_values().collect();
        occurrences.sort_by(|a, b| {
            cmp_unicode_codepoints(
                a.get("logical_path").and_then(Value::as_str).unwrap_or(""),
                b.get("logical_path").and_then(Value::as_str).unwrap_or(""),
            )
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
            .filter(|occurrence| {
                occurrence.get("logical_path").and_then(Value::as_str) != Some(".")
            })
            .map(|occurrence| self.entry(occurrence))
            .collect()
    }

    fn entry(&self, occurrence: &Value) -> Result<Entry, String> {
        let path = occurrence
            .get("logical_path")
            .and_then(Value::as_str)
            .ok_or("inventory occurrence has no logical_path")?
            .to_owned();
        let kind = occurrence
            .get("entry_kind")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let format = occurrence
            .get("artifact_format")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();

        let unavailable = if occurrence.get("artifact_id").is_some_and(Value::is_null) {
            Some(json!({
                "path": path,
                "artifact_id": null,
                "sha256": null,
                "format": format,
                "encrypted": occurrence.get("encrypted").and_then(Value::as_bool).unwrap_or(false),
                "limitations": occurrence.get("limitations").cloned().unwrap_or_else(|| json!([]))
            }))
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

    fn component(&self, occurrence: &Value, path: &str, format: &str) -> Result<Value, String> {
        let id = occurrence
            .get("artifact_id")
            .and_then(Value::as_str)
            .ok_or("inventory occurrence has invalid artifact_id")?;
        let node = self
            .nodes
            .get(id)
            .ok_or("Application projection occurrence has no artifact node")?;
        let sha256 = node
            .get("sha256")
            .cloned()
            .ok_or("inventory node has no sha256")?;

        Ok(json!({
            "path": path,
            "artifact_id": id,
            "sha256": sha256,
            "format": format
        }))
    }
}

fn shared_inventory_context(pages: &[Page]) -> Result<(Value, Value), String> {
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
) -> Result<HashMap<String, Value>, String> {
    let mut members = HashMap::new();

    for page in pages {
        let items = page
            .result
            .get(collection_name)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("inventory result {collection_name} must be an array"))?;

        for item in items {
            let id = item
                .get(identity_field)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("inventory {member_name} has no {identity_field}"))?;
            merge_value(&mut members, id, item)?;
        }
    }

    Ok(members)
}

fn manifest_count(manifest: &Value, field: &str, member_name: &str) -> Result<u64, String> {
    manifest
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("inventory manifest has no valid {member_name} count"))
}

fn collect_limitations(pages: &[Page]) -> Vec<String> {
    let mut limitations = HashSet::new();

    for page in pages {
        let Some(values) = page.result.get("limitations").and_then(Value::as_array) else {
            continue;
        };
        limitations.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
    }

    limitations.into_iter().collect()
}

struct Entry {
    path: String,
    kind: String,
    component: Option<Value>,
    unavailable: Option<Value>,
}

fn merge_value(map: &mut HashMap<String, Value>, id: &str, value: &Value) -> Result<(), String> {
    if let Some(existing) = map.get(id) {
        if existing != value {
            return Err(format!("inventory member {id} differs across pages"));
        }
    } else {
        map.insert(id.to_owned(), value.clone());
    }
    Ok(())
}

fn classify(entries: &[Entry]) -> Map<String, Value> {
    let names = [
        "manifests",
        "resources",
        "dex",
        "jvm_classes",
        "native_libraries",
        "javascript",
        "signing",
    ];
    let mut output = Map::new();
    for name in names {
        let values = entries
            .iter()
            .filter_map(|entry| {
                if !matches!(entry.kind.as_str(), "file" | "slice") {
                    return None;
                }

                let component = entry.component.as_ref()?;
                let path = entry.path.as_str();
                let format = component
                    .get("format")
                    .and_then(Value::as_str)
                    .unwrap_or("");
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
        output.insert(name.into(), Value::Array(values));
    }
    output
}

fn runtime_families(entries: &[Entry], components: &Map<String, Value>) -> Value {
    let mut families = HashSet::new();
    if !components["dex"].as_array().unwrap().is_empty() {
        families.insert("dalvik-art");
    }
    if !components["jvm_classes"].as_array().unwrap().is_empty() {
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
                .and_then(Value::as_str)
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
                .and_then(Value::as_str)
                == Some("javascript-bundle")
        })
    {
        families.insert("javascript");
    }
    for entry in entries
        .iter()
        .filter(|entry| matches!(entry.kind.as_str(), "file" | "slice"))
    {
        if let Some(family) = native_convention(&entry.path) {
            families.insert(family);
        }
    }
    let mut values: Vec<_> = families.into_iter().collect();
    values.sort_by(|a, b| cmp_unicode_codepoints(a, b));
    Value::Array(values.into_iter().map(Value::from).collect())
}

fn bridge_candidates(managed: &[&Value], native: &[&Value]) -> (Value, Value) {
    let total = managed.len().saturating_mul(native.len());
    let mut candidates = Vec::new();
    let mut estimated = 2usize;
    'outer: for left in managed {
        for right in native {
            let managed_path = left["path"].as_str().unwrap_or("");
            let native_path = right["path"].as_str().unwrap_or("");
            let candidate = json!({"managed_path": managed_path, "native_path": native_path, "basis": bridge_basis(native_path)});
            let bytes = serde_json::to_vec(&candidate)
                .map(|value| value.len())
                .unwrap_or(usize::MAX);
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
        Value::Array(candidates),
        json!({"status": if emitted == total { "complete" } else { "partial" }, "total_candidates": total, "emitted_candidates": emitted, "omitted_candidates": total - emitted}),
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
fn cmp_unicode_codepoints(left: &str, right: &str) -> std::cmp::Ordering {
    left.chars().cmp(right.chars())
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
        validate_input(&input()).expect("valid Android graph input");
        assert!(project(&input()).is_ok());
    }

    #[test]
    fn rejects_occurrence_without_producer_artifact_kind() {
        let mut inventory =
            inventory_fixture()["inventory_evidence"][0]["normalized_result"].clone();
        inventory["occurrences"][0]
            .as_object_mut()
            .expect("occurrence object")
            .remove("artifact_kind");
        let failure = validate_input(&input_with_result(inventory))
            .expect_err("artifact_kind is required by the producer contract");

        assert_eq!(failure.code(), "invalid_request");
    }

    #[test]
    fn excludes_non_file_occurrences_from_components_and_runtime_families() {
        let mut inventory =
            inventory_fixture()["inventory_evidence"][0]["normalized_result"].clone();
        inventory["occurrences"][1]["entry_kind"] = Value::String("directory".into());
        let fixture = input_with_result(inventory);

        let projection = project(&fixture).expect("valid directory occurrence");

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

        let projection = project(&fixture).expect("inventory with omitted edge remains usable");

        assert_eq!(projection["coverage"]["inventory_complete"], false);
    }

    #[test]
    fn rejects_inventory_evidence_with_a_forged_semantic_id() {
        let mut fixture = input();
        fixture["inventory_evidence"][0]["normalized_result"]["limitations"] =
            serde_json::json!(["changed after the evidence id was committed"]);

        let failure = validate_input(&fixture).expect_err("modified Evidence is rejected");

        assert_eq!(failure.code(), "evidence_integrity_mismatch");
    }

    #[test]
    fn emits_derived_evidence_linked_to_authenticated_inventory_sources() {
        let fixture = input();
        let source_id = fixture["inventory_evidence"][0]["evidence_id"]
            .as_str()
            .expect("source id")
            .to_owned();

        let projected = project_evidence(&fixture).expect("derived Evidence");
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
        assert!(validate_input(&serde_json::json!({"inventory_evidence": []})).is_err());
    }
    #[test]
    fn rejects_inventory_without_identity() {
        assert!(validate_input(&serde_json::json!({"inventory_evidence": [{}]})).is_err());
    }
}
