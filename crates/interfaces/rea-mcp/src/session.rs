//! One MCP/CLI session: retained Evidence, residual unknowns and the
//! per-family state that tools own (targets, provider sessions, caches).
use rea_application::ledger::artifact_records::{ArtifactRecords, RecordError};
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::Evidence;
use serde_json::{Value, value::RawValue};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Cleanup owned by a family's session state when the session closes.
pub trait SessionResource: Send + Sync {
    /// Release owned resources; failures stay with their owner for retry.
    fn close(&self) -> Result<(), AnalysisError>;
}

/// Session shared by all tool calls on one connection.
pub struct Session {
    records: Arc<ArtifactRecords>,
    state: Mutex<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
    resources: Mutex<Vec<Arc<dyn SessionResource>>>,
    started_at: SystemTime,
    environment: Arc<HashMap<String, String>>,
    /// Evidence subject of the active target, owned by the binary session.
    active_subject: Mutex<Option<Value>>,
    owned_types: Mutex<std::collections::HashSet<TypeId>>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new(std::env::vars().collect())
    }
}

impl Session {
    /// Bind a session to one immutable environment snapshot.
    pub fn new(environment: HashMap<String, String>) -> Self {
        Self {
            records: Arc::new(ArtifactRecords::default()),
            state: Mutex::new(HashMap::new()),
            resources: Mutex::new(Vec::new()),
            started_at: SystemTime::now(),
            environment: Arc::new(environment),
            active_subject: Mutex::new(None),
            owned_types: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Evidence subject (`name`, `digest`, `local_path`, `format`,
    /// `architecture`) of the active analysis target, if any.
    pub fn active_subject(&self) -> Option<Value> {
        self.active_subject
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the active target subject (binary session ownership only).
    pub fn set_active_subject(&self, subject: Option<Value>) {
        *self
            .active_subject
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = subject;
    }

    /// Retained Evidence ledger and residual-unknown histories.
    pub fn records(&self) -> &Arc<ArtifactRecords> {
        &self.records
    }

    /// Immutable environment snapshot selected when the session started.
    pub fn environment(&self) -> &HashMap<String, String> {
        &self.environment
    }

    /// One environment variable from the session snapshot.
    pub fn env(&self, key: &str) -> Option<&str> {
        self.environment.get(key).map(String::as_str)
    }

    pub fn started_at(&self) -> SystemTime {
        self.started_at
    }

    /// Family-owned state, created on first use.
    pub fn state<T: Any + Send + Sync + Default>(&self) -> Arc<T> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = state
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Arc::new(T::default()) as Arc<dyn Any + Send + Sync>);
        Arc::clone(entry)
            .downcast::<T>()
            .unwrap_or_else(|_| unreachable!("state map is keyed by TypeId"))
    }

    /// Register a resource closed when the session ends.
    pub fn own(&self, resource: Arc<dyn SessionResource>) {
        self.resources
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(resource);
    }

    /// Register a family's state resource once, keyed by its type.
    pub fn own_once<T: SessionResource + 'static>(&self, resource: Arc<T>) {
        let mut owned = self
            .owned_types
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if owned.insert(TypeId::of::<T>()) {
            drop(owned);
            self.own(resource);
        }
    }

    /// Close every owned resource, retaining failed owners for retry.
    pub fn close(&self) -> Result<(), Vec<AnalysisError>> {
        let resources = std::mem::take(
            &mut *self
                .resources
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let mut failures = Vec::new();
        let mut retained = Vec::new();
        for resource in resources {
            if let Err(error) = resource.close() {
                failures.push(error);
                retained.push(resource);
            }
        }
        if !retained.is_empty() {
            self.resources
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend(retained);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }

    /// Authenticate and retain one Evidence record.
    pub fn record(&self, evidence: &Evidence) -> Result<(), AnalysisError> {
        let raw = evidence
            .to_raw()
            .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
        self.record_raw(&raw)
    }

    /// Authenticate and retain one serialized Evidence record.
    pub fn record_raw(&self, raw: &RawValue) -> Result<(), AnalysisError> {
        self.records.record_raw(raw).map_err(record_error)
    }

    /// Exact retained record by identifier.
    pub fn evidence(&self, evidence_id: &str) -> Option<Value> {
        let raw = self.records.find_raw(evidence_id).ok().flatten()?;
        serde_json::from_str(raw.get()).ok()
    }

    /// Exact retained Evidence record for producers whose JSON strings contain
    /// unpaired JavaScript UTF-16 units. Callers that own an exact graph view
    /// must use this rather than [`Session::evidence`], which is limited to
    /// the legacy `serde_json::Value` projection contract.
    pub fn evidence_raw(&self, evidence_id: &str) -> Option<Box<RawValue>> {
        self.records.find_raw(evidence_id).ok().flatten()
    }

    /// Complete canonical bundle of retained records and unknown histories.
    pub fn export_bundle(&self) -> Result<Value, AnalysisError> {
        let snapshot = self.records.snapshot().map_err(record_error)?;
        let mut bytes = Vec::new();
        snapshot.write_canonical(&mut bytes).map_err(record_error)?;
        serde_json::from_slice(&bytes)
            .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))
    }

    /// Every retained record value.
    pub fn retained_records(&self) -> Vec<Value> {
        self.export_bundle()
            .ok()
            .and_then(|bundle| bundle.get("records").and_then(Value::as_array).cloned())
            .unwrap_or_default()
    }
}

/// Map ledger failures into the shared error algebra.
pub fn record_error(error: RecordError) -> AnalysisError {
    match error {
        RecordError::UnknownMutation(reason) => AnalysisError::unknown_registry(reason.to_string()),
        RecordError::Conflict => {
            AnalysisError::evidence_integrity("Conflicting Evidence record or unknown revision")
        }
        other => AnalysisError::evidence_integrity(other.to_string()),
    }
}
