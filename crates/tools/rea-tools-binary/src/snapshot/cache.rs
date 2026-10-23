//! Bounded in-memory analysis-snapshot cache.
//!
//! Compatibility owner: `src/application/binary/AnalysisSnapshotCache.ts`.
use super::canonical::compare_unicode_code_points;
use super::domain::{
    snapshot_binding, snapshot_matches_profile, snapshot_matches_target, snapshot_target,
};
use super::evidence::rebind_evidence_subject_target_path;
use super::model::{
    AnalysisSnapshot, ExecutionInput, analysis_query_id, create_analysis_snapshot_entry,
    create_analysis_snapshot_workflow_entry,
};
use rea_analysis::{AnalysisExecution, BinaryTarget, ProviderIdentity};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Maximum duplicated result bindings retained across direct and workflow
/// queries (TS `SNAPSHOT_CACHE_ENTRY_CEILING`).
pub(crate) const SNAPSHOT_CACHE_ENTRY_CEILING: usize = 10_000;

/// Replay direction operations whose missing coverage becomes `unknown`.
fn is_relationship_operation(operation: &str) -> bool {
    matches!(operation, "procedure_callers" | "procedure_callees")
}

/// Bounded in-memory cache for one immutable binary identity.
#[derive(Default)]
pub(crate) struct SnapshotCache {
    /// Provider entries keyed by `query_id`; a sorted map gives deterministic
    /// export order.
    entries: BTreeMap<String, Value>,
    workflow_entries: BTreeMap<String, Value>,
    target: Option<Value>,
    binding: Option<Value>,
}

impl SnapshotCache {
    /// Whether staged entries belong to the supplied target and profile (TS
    /// `matches`).
    pub(crate) fn matches(&self, target: &BinaryTarget, profile: Option<&Value>) -> bool {
        match (&self.target, &self.binding, profile) {
            (None, None, _) => true,
            (Some(current_target), Some(current_binding), Some(profile)) => {
                snapshot_matches_target(current_target, target)
                    && snapshot_matches_profile(current_binding, profile)
            }
            _ => false,
        }
    }

    /// Replace cache state when the target or selected profile changes (TS
    /// `select`).
    pub(crate) fn select(&mut self, target: &BinaryTarget, profile: &Value) {
        if !self.matches(target, Some(profile)) {
            self.clear_entries();
        }
        self.target = Some(snapshot_target(target));
        self.binding = Some(snapshot_binding(profile));
    }

    /// Merge already-validated entries and return the new-entry count (TS
    /// `stage`).
    pub(crate) fn stage(&mut self, snapshot: &AnalysisSnapshot) -> usize {
        let snapshot_target_value = snapshot.target().clone();
        let snapshot_binding_value = snapshot.binding().clone();
        let target_differs = self
            .target
            .as_ref()
            .is_some_and(|current| current.to_string() != snapshot_target_value.to_string());
        let binding_differs = self.binding.as_ref().is_some_and(|current| {
            snapshot_binding_value
                .get("analysis_profile")
                .map(|profile| !snapshot_matches_profile(current, profile))
                .unwrap_or(true)
        });
        if target_differs || binding_differs {
            self.clear_entries();
        }
        self.target = Some(snapshot_target_value);
        self.binding = Some(snapshot_binding_value);

        let mut imported = 0;
        for entry in snapshot.entries() {
            let query_id = query_id_of(entry);
            let present = self.entries.contains_key(&query_id);
            if !present && !self.has_capacity() {
                continue;
            }
            if !present {
                imported += 1;
            }
            self.entries.insert(query_id, entry.clone());
        }
        for entry in snapshot.workflow_entries() {
            let query_id = query_id_of(entry);
            if !self.workflow_entries.contains_key(&query_id) && !self.has_capacity() {
                continue;
            }
            self.workflow_entries.insert(query_id, entry.clone());
        }
        imported
    }

    /// Build a complete snapshot for an active target (TS `export`).
    ///
    /// # Errors
    /// `no_binary_open` when target or profile is missing; an
    /// `EvidenceIntegrity` failure ("Analysis snapshot validation failed")
    /// when authentication fails.
    pub(crate) fn export(
        &self,
        target: Option<&BinaryTarget>,
        profile: Option<&Value>,
        evidence_bundle: Value,
    ) -> Result<AnalysisSnapshot, AnalysisError> {
        let (Some(target), Some(profile)) = (target, profile) else {
            return Err(AnalysisError::no_binary_open());
        };
        let snapshot_target_identity = snapshot_target(target);
        let binding = snapshot_binding(profile);
        let entries = self.sorted_entries(&self.entries);
        let workflows = self.sorted_entries(&self.workflow_entries);
        let candidate = json!({
            "target": snapshot_target_identity,
            "binding": binding,
            "entries": entries,
            "workflow_entries": workflows,
            "evidence_bundle": evidence_bundle,
        });
        AnalysisSnapshot::parse(&candidate).map_err(validation_failure)
    }

    /// Validate target identity, merge evidence atomically, then stage (TS
    /// `import`). `merge_evidence` receives the snapshot's evidence bundle and
    /// returns the number of records added.
    ///
    /// # Errors
    /// `SnapshotMismatch` when an active binding does not match, or the merge
    /// callback's error.
    pub(crate) fn import(
        &mut self,
        snapshot: &AnalysisSnapshot,
        active: Option<(&BinaryTarget, &Value)>,
        merge_evidence: &mut dyn FnMut(&Value) -> Result<usize, AnalysisError>,
    ) -> Result<usize, AnalysisError> {
        // The snapshot is already authenticated by `AnalysisSnapshot::parse`,
        // so revalidation here is identity (TS re-runs
        // `immutableAnalysisSnapshot` on an already validated value).
        if let Some((active_target, active_profile)) = active
            && (!snapshot_matches_target(snapshot.target(), active_target)
                || !snapshot_matches_profile(snapshot.binding(), active_profile))
        {
            return Err(ErrorKind::SnapshotMismatch {
                message: "Analysis snapshot profile_mismatch: target, provider, or analysis profile does not match the active binary".to_owned(),
            }
            .into());
        }
        merge_evidence(snapshot.evidence_bundle())?;
        Ok(self.stage(snapshot))
    }

    /// Record one exact derived workflow result unless the shared cache is full
    /// (TS `recordWorkflow`).
    ///
    /// # Errors
    /// Returns the TS `TypeError` message when the execution provider does not
    /// match its profile.
    pub(crate) fn record_workflow(
        &mut self,
        target: &BinaryTarget,
        profile: &Value,
        operation: &str,
        parameters: &Map<String, Value>,
        execution: &AnalysisExecution,
    ) -> Result<(), String> {
        self.select(target, profile);
        let target_identity = snapshot_target(target);
        let binding = snapshot_binding(profile);
        let parameters = Value::Object(parameters.clone());
        let query_id = analysis_query_id(&target_identity, &binding, operation, &parameters)?;
        if !self.workflow_entries.contains_key(&query_id) && !self.has_capacity() {
            return Ok(());
        }
        let input = execution_input(execution);
        let entry = create_analysis_snapshot_workflow_entry(
            &target_identity,
            &binding,
            operation,
            &parameters,
            &input,
        )?;
        self.workflow_entries.insert(query_id_of(&entry), entry);
        Ok(())
    }

    /// Replay an exact provider-specific query (TS `lookup`).
    pub(crate) fn lookup(
        &self,
        target: &BinaryTarget,
        profile: &Value,
        operation: &str,
        parameters: &Map<String, Value>,
    ) -> Option<AnalysisExecution> {
        let target_identity = snapshot_target(target);
        let binding = snapshot_binding(profile);
        let parameters = Value::Object(parameters.clone());
        let query_id =
            analysis_query_id(&target_identity, &binding, operation, &parameters).ok()?;
        let cached = self.entries.get(&query_id)?;
        let execution = cached.get("execution")?;

        let subject = match execution.get("subject") {
            Some(Value::Null) | None => None,
            Some(cached_subject) => {
                let mut descriptor = Map::new();
                descriptor.insert(
                    "path".into(),
                    cached_subject.get("path").cloned().unwrap_or(Value::Null),
                );
                descriptor.insert(
                    "sha256".into(),
                    cached_subject.get("sha256").cloned().unwrap_or(Value::Null),
                );
                descriptor.insert(
                    "format".into(),
                    cached_subject.get("format").cloned().unwrap_or(Value::Null),
                );
                if cached_subject
                    .get("architecture")
                    .is_some_and(|value| !value.is_null())
                {
                    descriptor.insert(
                        "architecture".into(),
                        cached_subject
                            .get("architecture")
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                }
                let rebound = rebind_evidence_subject_target_path(
                    &Value::Object(descriptor),
                    &target_descriptor(target),
                );
                Some(subject_target_from_descriptor(&rebound))
            }
        };

        let mut limitations: Vec<String> = execution
            .get("limitations")
            .and_then(Value::as_array)
            .map(|array| {
                array
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        limitations.push(
            "Loaded from a local REA analysis snapshot; this call did not re-run the provider."
                .to_owned(),
        );

        let coverage_value = execution
            .get("relationship_coverage")
            .cloned()
            .unwrap_or(Value::Null);
        let relationship_coverage = if coverage_value.is_null() {
            if is_relationship_operation(operation) {
                Some(json!({
                    "status": "unknown",
                    "reason": "Snapshot entry does not report relationship coverage.",
                }))
            } else {
                None
            }
        } else {
            Some(coverage_value)
        };

        let provider = provider_identity_from_value(execution.get("provider"));
        let mut result_execution = AnalysisExecution::new(
            execution.get("result").cloned().unwrap_or(Value::Null),
            provider,
        );
        result_execution.raw_result = match execution.get("raw_result") {
            Some(Value::Null) | None => None,
            Some(value) => Some(value.clone()),
        };
        result_execution.analysis_profile = Some(profile.clone());
        result_execution.limitations = limitations;
        result_execution.relationship_coverage = relationship_coverage;
        result_execution.locations = execution
            .get("locations")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        result_execution.subject = subject;
        Some(result_execution)
    }

    /// Record one successful immutable call unless the cache is full (TS
    /// `record`). Truncated reads are not recorded.
    pub(crate) fn record(
        &mut self,
        target: &BinaryTarget,
        profile: &Value,
        operation: &str,
        parameters: &Map<String, Value>,
        execution: &AnalysisExecution,
    ) {
        self.select(target, profile);
        if execution.references_truncated == Some(true) {
            return;
        }
        let target_identity = snapshot_target(target);
        let binding = snapshot_binding(profile);
        let parameters = Value::Object(parameters.clone());
        let Ok(query_id) = analysis_query_id(&target_identity, &binding, operation, &parameters)
        else {
            return;
        };
        if !self.entries.contains_key(&query_id) && !self.has_capacity() {
            return;
        }
        let input = execution_input(execution);
        if let Ok(entry) = create_analysis_snapshot_entry(
            &target_identity,
            &binding,
            operation,
            &parameters,
            &input,
        ) {
            self.entries.insert(query_id_of(&entry), entry);
        }
    }

    /// Forget all target-bound entries (TS `clear`).
    pub(crate) fn clear(&mut self) {
        self.clear_entries();
        self.target = None;
        self.binding = None;
    }

    /// Count of provider entries.
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Count of workflow entries.
    pub(crate) fn workflow_entry_count(&self) -> usize {
        self.workflow_entries.len()
    }

    fn clear_entries(&mut self) {
        self.entries.clear();
        self.workflow_entries.clear();
    }

    fn has_capacity(&self) -> bool {
        self.entries.len() + self.workflow_entries.len() < SNAPSHOT_CACHE_ENTRY_CEILING
    }

    /// Entries sorted by `query_id` with code-point ordering (TS sort).
    fn sorted_entries(&self, source: &BTreeMap<String, Value>) -> Vec<Value> {
        let mut entries: Vec<Value> = source.values().cloned().collect();
        entries.sort_by(|left, right| {
            compare_unicode_code_points(&query_id_of(left), &query_id_of(right))
        });
        entries
    }
}

fn query_id_of(entry: &Value) -> String {
    entry
        .get("query_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn validation_failure(_cause: String) -> AnalysisError {
    ErrorKind::EvidenceIntegrity {
        message: "Analysis snapshot validation failed".to_owned(),
        user_message: None,
    }
    .into()
}

/// Display-subject descriptor for a target (`{ path, sha256, format,
/// architecture }`) used by `rebindEvidenceSubjectTargetPath`.
fn target_descriptor(target: &BinaryTarget) -> Value {
    json!({
        "path": target.path,
        "sha256": target.sha256,
        "format": target.format,
        "architecture": target.architecture.clone().map_or(Value::Null, Value::String),
    })
}

/// Project an `AnalysisExecution` into the snapshot execution input (TS
/// `SnapshotExecution`). The subject uses the snapshot shape
/// `{ path, sha256, format, architecture }`.
fn execution_input(execution: &AnalysisExecution) -> ExecutionInput {
    let subject = match &execution.subject {
        None => Value::Null,
        Some(subject) => json!({
            "path": subject.path,
            "sha256": subject.sha256,
            "format": subject.format,
            "architecture": subject.architecture.clone().map_or(Value::Null, Value::String),
        }),
    };
    ExecutionInput {
        result: execution.result.clone(),
        raw_result: execution.raw_result.clone().unwrap_or(Value::Null),
        provider: execution.provider.to_json(),
        analysis_profile: execution.analysis_profile.clone(),
        limitations: Value::Array(
            execution
                .limitations
                .iter()
                .map(|limitation| Value::String(limitation.clone()))
                .collect(),
        ),
        relationship_coverage: execution
            .relationship_coverage
            .clone()
            .unwrap_or(Value::Null),
        locations: Value::Array(execution.locations.clone()),
        subject,
    }
}

fn provider_identity_from_value(value: Option<&Value>) -> ProviderIdentity {
    let value = value.cloned().unwrap_or(Value::Null);
    ProviderIdentity::new(
        value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        value
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
}

fn subject_target_from_descriptor(
    descriptor: &Value,
) -> rea_core::evidence::envelope::SubjectTarget {
    rea_core::evidence::envelope::SubjectTarget {
        path: descriptor
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        sha256: descriptor
            .get("sha256")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        format: descriptor
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        architecture: descriptor
            .get("architecture")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}
