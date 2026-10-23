//! The validated, immutable analysis-snapshot value and its construction.
//!
//! Compatibility owner: `src/domain/analysisSnapshot.ts`. The TypeScript file
//! uses Zod schemas plus a cross-entry/Evidence authentication pass
//! (`restoreSnapshot`). This port validates the same invariants while keeping
//! the snapshot as owned JSON so the caller-visible bytes match the TS
//! object-literal order and the canonical digests stay order-independent.
use super::canonical::{
    canonical_json_string, compare_unicode_code_points, composite_key, content_digest,
};
use super::domain::{analysis_profiles_equal, snapshot_matches_profile, snapshot_matches_target};
use super::evidence::evidence_bundle_for_target;
use rea_analysis::BinaryTarget;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

/// A validated and immutable analysis snapshot (TS `AnalysisSnapshot`).
#[derive(Clone, Debug)]
pub(crate) struct AnalysisSnapshot {
    /// Canonical snapshot value: `{ target, binding, entries,
    /// workflow_entries, evidence_bundle }` with full execution payloads.
    value: Value,
}

impl AnalysisSnapshot {
    /// Parse and authenticate a snapshot value (TS `parseAnalysisSnapshot`
    /// followed by `sealSnapshot`).
    ///
    /// # Errors
    /// Returns the TS `TypeError` message when validation fails.
    pub(crate) fn parse(input: &Value) -> Result<Self, String> {
        let value = parse_analysis_snapshot(input)?;
        Ok(Self { value })
    }

    /// The canonical snapshot value.
    pub(crate) fn value(&self) -> &Value {
        &self.value
    }

    /// Target identity (`{ sha256, kind, architecture, format, entry_point? }`).
    pub(crate) fn target(&self) -> &Value {
        &self.value["target"]
    }

    /// Provider/profile binding (`{ provider, analysis_profile }`).
    pub(crate) fn binding(&self) -> &Value {
        &self.value["binding"]
    }

    /// The scoped evidence bundle (TS `evidence_bundle`).
    pub(crate) fn evidence_bundle(&self) -> &Value {
        &self.value["evidence_bundle"]
    }

    /// Provider entries in canonical query order.
    pub(crate) fn entries(&self) -> &[Value] {
        self.value["entries"].as_array().map_or(&[], Vec::as_slice)
    }

    /// Derived workflow entries in canonical query order.
    pub(crate) fn workflow_entries(&self) -> &[Value] {
        self.value["workflow_entries"]
            .as_array()
            .map_or(&[], Vec::as_slice)
    }

    /// Count of provider entries.
    pub(crate) fn entry_count(&self) -> usize {
        self.entries().len()
    }

    /// Count of derived workflow entries.
    pub(crate) fn workflow_entry_count(&self) -> usize {
        self.workflow_entries().len()
    }

    /// Count of retained Evidence records in the scoped bundle.
    pub(crate) fn evidence_record_count(&self) -> usize {
        self.evidence_bundle()
            .get("records")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    }

    /// Serialize with byte-stable canonical ordering (TS
    /// `serializeAnalysisSnapshot` = canonical JSON + "\n").
    ///
    /// # Errors
    /// Returns the TS validation message when canonicalization fails.
    pub(crate) fn serialize(&self) -> Result<String, String> {
        Ok(format!("{}\n", canonical_json_string(&self.value)?))
    }
}

/// Compute the stable lookup key for one provider/profile query (TS
/// `analysisQueryId`).
///
/// # Errors
/// Fails only when the inputs cannot be canonicalized.
pub(crate) fn analysis_query_id(
    target: &Value,
    binding: &Value,
    operation: &str,
    parameters: &Value,
) -> Result<String, String> {
    let digest = content_digest(&json!({
        "target": target,
        "binding": binding,
        "operation": operation,
        "parameters": parameters,
    }))?;
    Ok(format!("query_{digest}"))
}

/// Require an exact target and selected provider/profile cache partition (TS
/// `snapshotMatchesBinding`).
pub(crate) fn snapshot_matches_binding(
    snapshot: &AnalysisSnapshot,
    target: &BinaryTarget,
    profile: &Value,
) -> bool {
    snapshot_matches_target(snapshot.target(), target)
        && snapshot_matches_profile(snapshot.binding(), profile)
}

/// Content digest of an entry/execution's metadata and payload (TS
/// `snapshotContentDigest`). `execution` is the entry's execution object.
fn snapshot_content_digest(
    result: &Value,
    raw_result: &Value,
    execution: &Value,
) -> Result<String, String> {
    let subject = match execution.get("subject") {
        Some(Value::Null) | None => Value::Null,
        Some(subject) => json!({
            "local_path": subject.get("path").cloned().unwrap_or(Value::Null),
            "sha256": subject.get("sha256").cloned().unwrap_or(Value::Null),
            "format": subject.get("format").cloned().unwrap_or(Value::Null),
            "architecture": subject.get("architecture").cloned().unwrap_or(Value::Null),
        }),
    };
    content_digest(&json!({
        "limitations": execution.get("limitations").cloned().unwrap_or(Value::Array(Vec::new())),
        "locations": execution.get("locations").cloned().unwrap_or(Value::Array(Vec::new())),
        "subject": subject,
        "relationship_coverage": execution
            .get("relationship_coverage")
            .cloned()
            .unwrap_or(Value::Null),
        "normalized_result": result,
        "raw_result": raw_result,
    }))
}

/// Content digest of an Evidence record (TS `evidenceContentDigest`).
fn evidence_content_digest(evidence: &Value) -> Result<String, String> {
    let subject = match evidence.get("subject") {
        Some(Value::Null) | None => Value::Null,
        Some(subject) => json!({
            "local_path": subject.get("local_path").cloned().unwrap_or(Value::Null),
            "sha256": subject
                .get("digest")
                .and_then(|digest| digest.get("sha256"))
                .cloned()
                .unwrap_or(Value::Null),
            "format": subject.get("format").cloned().unwrap_or(Value::Null),
            "architecture": subject.get("architecture").cloned().unwrap_or(Value::Null),
        }),
    };
    content_digest(&json!({
        "limitations": evidence.get("limitations").cloned().unwrap_or(Value::Array(Vec::new())),
        "relationship_coverage": evidence.get("relationship_coverage").cloned().unwrap_or(Value::Null),
        "locations": evidence.get("locations").cloned().unwrap_or(Value::Array(Vec::new())),
        "subject": subject,
        "normalized_result": evidence.get("normalized_result").cloned().unwrap_or(Value::Null),
        "raw_result": evidence.get("raw_result").cloned().unwrap_or(Value::Null),
    }))
}

/// TS `evidenceQueryKey`.
fn evidence_query_key(evidence: &Value) -> Result<String, String> {
    content_digest(&json!({
        "operation": evidence.get("operation").cloned().unwrap_or(Value::Null),
        "parameters": evidence.get("parameters").cloned().unwrap_or(Value::Null),
        "provider": evidence.get("provider").cloned().unwrap_or(Value::Null),
        "analysis_profile": evidence.get("analysis_profile").cloned().unwrap_or(Value::Null),
    }))
}

/// TS `entryQueryKey` (provider entry + binding profile).
fn entry_query_key(entry: &Value, binding: &Value) -> Result<String, String> {
    content_digest(&json!({
        "operation": entry.get("operation").cloned().unwrap_or(Value::Null),
        "parameters": entry.get("parameters").cloned().unwrap_or(Value::Null),
        "provider": entry
            .get("execution")
            .and_then(|execution| execution.get("provider"))
            .cloned()
            .unwrap_or(Value::Null),
        "analysis_profile": binding.get("analysis_profile").cloned().unwrap_or(Value::Null),
    }))
}

/// TS `workflowEntryQueryKey`.
fn workflow_entry_query_key(entry: &Value) -> Result<String, String> {
    let execution = entry.get("execution");
    content_digest(&json!({
        "operation": entry.get("operation").cloned().unwrap_or(Value::Null),
        "parameters": entry.get("parameters").cloned().unwrap_or(Value::Null),
        "provider": execution
            .and_then(|execution| execution.get("provider"))
            .cloned()
            .unwrap_or(Value::Null),
        "analysis_profile": execution
            .and_then(|execution| execution.get("analysis_profile"))
            .cloned()
            .unwrap_or(Value::Null),
    }))
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn provider_matches(provider: &Value, other: &Value) -> bool {
    provider.get("id") == other.get("id")
        && provider.get("name") == other.get("name")
        && provider.get("version") == other.get("version")
}

/// TS `isCorrespondingEvidence`.
fn is_corresponding_evidence(evidence: &Value, target_sha: &str, binding: &Value) -> bool {
    evidence.get("predicate_type").and_then(Value::as_str) == Some("rea.analysis")
        && evidence.get("confidence").and_then(Value::as_str) == Some("observed")
        && evidence.get("authority").and_then(Value::as_str) == Some("shipped-artifact")
        && evidence_subject_sha(evidence) == Some(target_sha)
        && evidence
            .get("analysis_profile")
            .is_some_and(|profile| !profile.is_null())
        && evidence.get("analysis_profile").is_some_and(|profile| {
            binding
                .get("analysis_profile")
                .is_some_and(|binding_profile| analysis_profiles_equal(profile, binding_profile))
        })
}

fn evidence_subject_sha(evidence: &Value) -> Option<&str> {
    evidence
        .get("subject")
        .filter(|value| !value.is_null())
        .and_then(|subject| subject.get("digest"))
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str)
}

/// Check canonical ascending query-id order (TS `hasCanonicalQueryOrder`).
fn has_canonical_query_order(entries: &[Value]) -> bool {
    let mut previous: Option<&str> = None;
    for entry in entries {
        let query_id = str_field(entry, "query_id");
        if let Some(previous) = previous
            && compare_unicode_code_points(previous, query_id) == std::cmp::Ordering::Greater
        {
            return false;
        }
        previous = Some(query_id);
    }
    true
}

/// Parse a snapshot value and authenticate entries against Evidence (TS
/// `parseAnalysisSnapshot` + `restoreSnapshot`). Returns the canonical value.
fn parse_analysis_snapshot(input: &Value) -> Result<Value, String> {
    let object = input
        .as_object()
        .ok_or_else(|| "Analysis snapshot validation failed".to_owned())?;
    let target = object
        .get("target")
        .cloned()
        .ok_or_else(|| "Analysis snapshot target is missing".to_owned())?;
    let binding = object
        .get("binding")
        .cloned()
        .ok_or_else(|| "Analysis snapshot binding is missing".to_owned())?;
    let entries: Vec<Value> = object
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "Analysis snapshot entries is missing".to_owned())?;
    let workflow_entries: Vec<Value> = object
        .get("workflow_entries")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "Analysis snapshot workflow_entries is missing".to_owned())?;
    let bundle = object
        .get("evidence_bundle")
        .cloned()
        .ok_or_else(|| "Analysis snapshot evidence_bundle is missing".to_owned())?;

    validate_binding(&binding)?;

    restore_snapshot(&target, &binding, &bundle, &entries, &workflow_entries)
}

/// TS binding `superRefine`: binding provider must equal its profile provider.
fn validate_binding(binding: &Value) -> Result<(), String> {
    let provider = binding
        .get("provider")
        .ok_or_else(|| "Analysis snapshot binding is missing".to_owned())?;
    let profile_provider = binding
        .get("analysis_profile")
        .and_then(|profile| profile.get("provider"))
        .ok_or_else(|| "Analysis snapshot binding is missing".to_owned())?;
    if !provider_matches(provider, profile_provider) {
        return Err("Snapshot binding provider does not match analysis profile".to_owned());
    }
    Ok(())
}

/// Authenticate entries and Evidence, returning the restored snapshot value
/// (TS `restoreSnapshot`).
fn restore_snapshot(
    target: &Value,
    binding: &Value,
    bundle: &Value,
    entries: &[Value],
    workflow_entries: &[Value],
) -> Result<Value, String> {
    let target_sha = target
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "Analysis snapshot validation failed".to_owned())?;

    // Evidence in the bundle must all belong to this target.
    let scoped = evidence_bundle_for_target(bundle, target_sha);
    let bundle_records = bundle
        .get("records")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let bundle_unknowns = bundle
        .get("unknowns")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let scoped_records = scoped
        .get("records")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let scoped_unknowns = scoped
        .get("unknowns")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if scoped_records != bundle_records || scoped_unknowns != bundle_unknowns {
        return Err("Analysis snapshot evidence contains records for another target".to_owned());
    }

    if !has_canonical_query_order(entries) {
        return Err("Analysis snapshot entries are not canonical".to_owned());
    }
    if !has_canonical_query_order(workflow_entries) {
        return Err("Analysis snapshot workflow entries are not canonical".to_owned());
    }

    let records: Vec<Value> = bundle
        .get("records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // Build the corresponding/matching evidence maps (TS loop).
    let mut corresponding: HashSet<String> = HashSet::new();
    let mut matching: HashMap<String, Value> = HashMap::new();
    for evidence in &records {
        let predicate = evidence.get("predicate_type").and_then(Value::as_str);
        let authority = evidence.get("authority").and_then(Value::as_str);
        let confidence = evidence.get("confidence").and_then(Value::as_str);
        let profile_null = evidence
            .get("analysis_profile")
            .map(Value::is_null)
            .unwrap_or(true);
        if predicate != Some("rea.analysis")
            || authority != Some("shipped-artifact")
            || evidence_subject_sha(evidence) != Some(target_sha)
            || profile_null
            || (confidence != Some("observed") && confidence != Some("derived"))
        {
            continue;
        }
        if confidence == Some("observed")
            && !is_corresponding_evidence(evidence, target_sha, binding)
        {
            continue;
        }
        let query = composite_key(&[confidence.unwrap_or(""), &evidence_query_key(evidence)?]);
        corresponding.insert(query.clone());
        matching.insert(
            composite_key(&[&query, &evidence_content_digest(evidence)?]),
            evidence.clone(),
        );
    }

    let mut ids: HashSet<String> = HashSet::new();

    // Provider entries.
    let mut restored_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let execution = entry
            .get("execution")
            .ok_or_else(|| "Analysis snapshot validation failed".to_owned())?;
        let entry_provider = execution
            .get("provider")
            .ok_or_else(|| "Analysis snapshot validation failed".to_owned())?;
        let binding_provider = binding
            .get("provider")
            .ok_or_else(|| "Analysis snapshot validation failed".to_owned())?;
        if !provider_matches(entry_provider, binding_provider) {
            return Err("Analysis snapshot entry provider does not match".to_owned());
        }
        check_id(entry, target, binding, false, &mut ids)?;
        let digest = snapshot_content_digest(
            execution.get("result").unwrap_or(&Value::Null),
            execution.get("raw_result").unwrap_or(&Value::Null),
            execution,
        )?;
        let query = composite_key(&["observed", &entry_query_key(entry, binding)?]);
        let evidence = find_evidence(
            &matching,
            &corresponding,
            &query,
            &digest,
            "entry",
            str_field(entry, "operation"),
        )?;
        restored_entries.push(rebuild_entry(entry, &evidence));
    }

    // Workflow entries.
    let mut restored_workflows = Vec::with_capacity(workflow_entries.len());
    for entry in workflow_entries {
        let execution = entry
            .get("execution")
            .ok_or_else(|| "Analysis snapshot validation failed".to_owned())?;
        let profile_provider = execution
            .get("analysis_profile")
            .and_then(|profile| profile.get("provider"))
            .ok_or_else(|| "Analysis snapshot validation failed".to_owned())?;
        let entry_provider = execution
            .get("provider")
            .ok_or_else(|| "Analysis snapshot validation failed".to_owned())?;
        if !provider_matches(entry_provider, profile_provider) {
            return Err(
                "Analysis snapshot workflow entry provider does not match its profile".to_owned(),
            );
        }
        check_id(entry, target, binding, true, &mut ids)?;
        let digest = snapshot_content_digest(
            execution.get("result").unwrap_or(&Value::Null),
            execution.get("raw_result").unwrap_or(&Value::Null),
            execution,
        )?;
        let query = composite_key(&["derived", &workflow_entry_query_key(entry)?]);
        let evidence = find_evidence(
            &matching,
            &corresponding,
            &query,
            &digest,
            "workflow entry",
            str_field(entry, "operation"),
        )?;
        restored_workflows.push(rebuild_entry(entry, &evidence));
    }

    Ok(json!({
        "target": target,
        "binding": binding,
        "entries": restored_entries,
        "workflow_entries": restored_workflows,
        "evidence_bundle": bundle,
    }))
}

/// TS `find`: locate the authenticated Evidence, else a precise `TypeError`.
fn find_evidence(
    matching: &HashMap<String, Value>,
    corresponding: &HashSet<String>,
    query: &str,
    digest: &str,
    label: &str,
    operation: &str,
) -> Result<Value, String> {
    if let Some(evidence) = matching.get(&composite_key(&[query, digest])) {
        return Ok(evidence.clone());
    }
    if corresponding.contains(query) {
        Err(format!(
            "Analysis snapshot {label} {operation} differs from its Evidence record"
        ))
    } else {
        Err(format!(
            "Analysis snapshot {label} {operation} has no profile-bound Evidence record"
        ))
    }
}

/// TS `checkId`: entry query id must match and be unique.
fn check_id(
    entry: &Value,
    target: &Value,
    binding: &Value,
    workflow: bool,
    ids: &mut HashSet<String>,
) -> Result<(), String> {
    let expected = analysis_query_id(
        target,
        binding,
        str_field(entry, "operation"),
        entry.get("parameters").unwrap_or(&Value::Null),
    )?;
    let query_id = str_field(entry, "query_id");
    if query_id != expected {
        return Err(if workflow {
            "Analysis snapshot workflow query identifier does not match".to_owned()
        } else {
            "Analysis snapshot query identifier does not match".to_owned()
        });
    }
    if !ids.insert(query_id.to_owned()) {
        return Err("Analysis snapshot contains duplicate queries".to_owned());
    }
    Ok(())
}

/// Replace `result`/`raw_result` in an entry's execution with the
/// authenticated Evidence payload (TS spread in `restoreSnapshot`).
fn rebuild_entry(entry: &Value, evidence: &Value) -> Value {
    let mut entry = entry.clone();
    if let Some(execution) = entry
        .as_object_mut()
        .and_then(|object| object.get_mut("execution"))
        .and_then(Value::as_object_mut)
    {
        execution.insert(
            "result".into(),
            evidence
                .get("normalized_result")
                .cloned()
                .unwrap_or(Value::Null),
        );
        execution.insert(
            "raw_result".into(),
            evidence.get("raw_result").cloned().unwrap_or(Value::Null),
        );
    }
    entry
}

/// Create one serializable snapshot entry from a provider call (TS
/// `createAnalysisSnapshotEntry`). `binding`/`target` are projected values.
///
/// # Errors
/// Returns the TS `TypeError` message when the execution does not match the
/// binding, or when canonicalization fails.
pub(crate) fn create_analysis_snapshot_entry(
    target: &Value,
    binding: &Value,
    operation: &str,
    parameters: &Value,
    execution: &ExecutionInput,
) -> Result<Value, String> {
    let analysis_profile = execution.analysis_profile.as_ref().ok_or_else(|| {
        "Snapshot execution does not match its provider/profile binding".to_owned()
    })?;
    let binding_provider = binding.get("provider").ok_or_else(|| {
        "Snapshot execution does not match its provider/profile binding".to_owned()
    })?;
    if !snapshot_matches_profile(binding, analysis_profile)
        || !provider_matches(&execution.provider, binding_provider)
    {
        return Err("Snapshot execution does not match its provider/profile binding".to_owned());
    }
    Ok(json!({
        "query_id": analysis_query_id(target, binding, operation, parameters)?,
        "operation": operation,
        "parameters": parameters,
        "execution": {
            "result": execution.result,
            "raw_result": execution.raw_result,
            "provider": binding_provider,
            "limitations": execution.limitations,
            "relationship_coverage": execution.relationship_coverage,
            "locations": execution.locations,
            "subject": execution.subject_projection(),
        },
    }))
}

/// Create one exact derived workflow replay record (TS
/// `createAnalysisSnapshotWorkflowEntry`).
///
/// # Errors
/// Returns the TS `TypeError` when the provider does not match its profile, or
/// when canonicalization fails.
pub(crate) fn create_analysis_snapshot_workflow_entry(
    target: &Value,
    binding: &Value,
    operation: &str,
    parameters: &Value,
    execution: &ExecutionInput,
) -> Result<Value, String> {
    let analysis_profile = execution.analysis_profile.as_ref().ok_or_else(|| {
        "Workflow snapshot execution provider does not match its profile".to_owned()
    })?;
    let profile_provider = analysis_profile.get("provider").ok_or_else(|| {
        "Workflow snapshot execution provider does not match its profile".to_owned()
    })?;
    if !provider_matches(&execution.provider, profile_provider) {
        return Err("Workflow snapshot execution provider does not match its profile".to_owned());
    }
    Ok(json!({
        "query_id": analysis_query_id(target, binding, operation, parameters)?,
        "operation": operation,
        "parameters": parameters,
        "execution": {
            "result": execution.result,
            "raw_result": execution.raw_result,
            "provider": profile_provider,
            "analysis_profile": analysis_profile,
            "limitations": execution.limitations,
            "relationship_coverage": execution.relationship_coverage,
            "locations": execution.locations,
            "subject": execution.subject_projection(),
        },
    }))
}

/// Normalized execution input shared by entry/workflow construction.
///
/// Mirrors the TS `SnapshotExecution` object the cache passes to the entry
/// constructors: `limitations`/`locations` are cloned arrays, the relationship
/// coverage is `?? null`, and the subject is normalized to
/// `{ path, sha256, format, architecture }` with `architecture ?? null`.
pub(crate) struct ExecutionInput {
    pub(crate) result: Value,
    pub(crate) raw_result: Value,
    pub(crate) provider: Value,
    pub(crate) analysis_profile: Option<Value>,
    pub(crate) limitations: Value,
    pub(crate) relationship_coverage: Value,
    pub(crate) locations: Value,
    /// Subject in the snapshot shape `{ path, sha256, format, architecture }`
    /// or `null`.
    pub(crate) subject: Value,
}

impl ExecutionInput {
    /// TS `subjectSchema.parse({ ...subject, architecture: architecture ?? null })`:
    /// preserve the subject fields and ensure `architecture` is present as
    /// `null` when absent. Key order matches the snapshot subject literal.
    fn subject_projection(&self) -> Value {
        if self.subject.is_null() {
            return Value::Null;
        }
        let source = self.subject.as_object();
        let mut object = Map::new();
        object.insert(
            "path".into(),
            source
                .and_then(|map| map.get("path"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        object.insert(
            "sha256".into(),
            source
                .and_then(|map| map.get("sha256"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        object.insert(
            "format".into(),
            source
                .and_then(|map| map.get("format"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        object.insert(
            "architecture".into(),
            source
                .and_then(|map| map.get("architecture"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        Value::Object(object)
    }
}
