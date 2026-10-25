//! Binary session state (implementation owner of `port`).
//!
//! Compatibility owners: `src/application/binary/BinarySession.ts`,
//! `BinarySessionOpen.ts`, `BinarySessionExecution.ts`,
//! `BinarySessionRecords.ts` and `BinarySessionStatus.ts`.
//!
//! One session owns the single active target shared by CLI and MCP. Target
//! transitions (open, close, external mutation) are serialized in FIFO order
//! and drain the calls admitted before them; calls admitted after a pending
//! transition wait until it settles. Provider work never runs under the state
//! lock.
use crate::errors::{fold_cleanup_failures, provider_adapter, with_cleanup_failure};
use crate::port::{AnalysisPort, WorkflowSnapshot};
use crate::router::{Route, RouteClient, Router};
use crate::snapshot::{
    self, AnalysisSnapshot, SnapshotCache, SnapshotFiles, analysis_profiles_equal,
    evidence_bundle_for_target, is_snapshot_cacheable, snapshot_matches_binding,
    target_identity_matches,
};
use crate::status::provider_capability_sets;
use crate::target::{TargetOptions, binary_target_summary, parse_binary_target};
use rea_analysis::{
    AnalysisExecution, BinaryTarget, CapabilityDescriptor, ExecutionOptions, ProviderIdentity,
};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::bundle::EvidenceBundle;
use rea_core::evidence::envelope::SubjectTarget;
use rea_mcp::{Session, SessionResource};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::time::Duration;

const SNAPSHOT_MUTATION_RECOVERY: &str = "Export session observations through export_evidence_bundle if needed. Close the active target without saving a snapshot, then reopen it before importing or saving a snapshot.";

/// Operations whose results are never replayed from or recorded into the
/// primitive snapshot cache.
const REPLAY_EXCLUDED: [&str; 4] = [
    "decode_interface_builder",
    "inspect_asset_catalog",
    "inspect_keyed_archive",
    "trace_dylib_resolution",
];

/// How often a waiting call re-checks its cancellation.
const ADMISSION_POLL: Duration = Duration::from_millis(20);

/// One started provider run for a target.
pub(crate) struct SessionRun {
    pub client: Arc<RouteClient>,
    pub route: Arc<Route>,
    pub run_id: String,
}

/// The admitted active target binding.
pub(crate) struct ActiveBinding {
    pub target: BinaryTarget,
    pub profile: Option<Value>,
    pub run: Arc<SessionRun>,
}

struct PendingCleanup {
    run: Arc<SessionRun>,
    retain_document: bool,
}

#[derive(Default)]
struct Inner {
    next_ticket: u64,
    completed: u64,
    pending_transitions: usize,
    calls: HashMap<u64, u64>,
    next_call: u64,
    active: Option<Arc<ActiveBinding>>,
    pending_cleanup: Option<PendingCleanup>,
    external_mutation_cleanup_failure: Option<AnalysisError>,
    runtime_unavailability: BTreeMap<String, String>,
    snapshot: SnapshotCache,
    snapshot_invalidated: bool,
    prompt_controllers: HashMap<u64, Cancellation>,
    next_controller: u64,
}

impl Inner {
    fn invalidate_snapshot(&mut self) {
        self.snapshot.clear();
        self.snapshot_invalidated = true;
    }

    fn reset_snapshot_invalidation(&mut self) {
        if !self.snapshot_invalidated {
            return;
        }
        self.snapshot.clear();
        self.snapshot_invalidated = false;
    }

    fn clear_session_records(&mut self) {
        self.snapshot.clear();
        self.snapshot_invalidated = false;
    }
}

/// Per-session binary analysis state.
#[derive(Default)]
pub(crate) struct BinarySession {
    router: OnceLock<Arc<Router>>,
    session: OnceLock<Weak<Session>>,
    inner: Mutex<Inner>,
    changed: Condvar,
    /// Snapshot write resources (`BinarySessionRecords#writeResources`),
    /// locked separately so file I/O never holds the state lock.
    files: Mutex<SnapshotFiles>,
}

/// Options of one `open_binary` request.
#[derive(Clone, Default)]
pub(crate) struct OpenOptions {
    pub format_hint: Option<String>,
    pub architecture: Option<String>,
    pub entry_point: Option<String>,
    pub provider_id: Option<String>,
    /// Read inside the open's turn so later calls cannot overtake it.
    pub snapshot_path: Option<String>,
}

/// Receipt for an atomically saved snapshot followed by provider cleanup.
pub(crate) struct SavedSnapshot {
    pub path: String,
    pub bytes: u64,
    pub primitive_entries: usize,
    pub workflow_entries: usize,
    pub evidence_records: usize,
}

impl SavedSnapshot {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "bytes": self.bytes,
            "primitive_entries": self.primitive_entries,
            "workflow_entries": self.workflow_entries,
            "evidence_records": self.evidence_records,
        })
    }
}

fn empty_router() -> Arc<Router> {
    static EMPTY: OnceLock<Arc<Router>> = OnceLock::new();
    Arc::clone(EMPTY.get_or_init(|| Arc::new(Router::new(Vec::new(), None))))
}

/// The session's binary state, registering its shutdown cleanup once.
pub(crate) fn binary_session(session: &Arc<Session>) -> Arc<BinarySession> {
    let state = session.state::<BinarySession>();
    let _ = state.session.set(Arc::downgrade(session));
    session.own_once(Arc::clone(&state));
    state
}

/// Bind the registered provider router to this session (first binding wins).
pub(crate) fn bind(session: &Arc<Session>, router: impl FnOnce() -> Router) -> Arc<BinarySession> {
    let state = binary_session(session);
    state.router.get_or_init(|| Arc::new(router()));
    state
}

struct TransitionGuard<'a> {
    state: &'a BinarySession,
}

impl Drop for TransitionGuard<'_> {
    fn drop(&mut self) {
        let subject = {
            let mut inner = self.state.lock();
            inner.completed += 1;
            inner.pending_transitions = inner.pending_transitions.saturating_sub(1);
            inner
                .active
                .as_ref()
                .map(|active| active.target.subject_json())
        };
        self.state.changed.notify_all();
        if let Some(session) = self.state.session.get().and_then(Weak::upgrade) {
            session.set_active_subject(subject);
        }
    }
}

struct CallGuard<'a> {
    state: &'a BinarySession,
    id: u64,
}

impl Drop for CallGuard<'_> {
    fn drop(&mut self) {
        self.state.lock().calls.remove(&self.id);
        self.state.changed.notify_all();
    }
}

struct ControllerGuard<'a> {
    state: &'a BinarySession,
    id: u64,
}

impl Drop for ControllerGuard<'_> {
    fn drop(&mut self) {
        self.state.lock().prompt_controllers.remove(&self.id);
    }
}

fn subject_of(target: &BinaryTarget) -> SubjectTarget {
    SubjectTarget {
        path: target.path.clone(),
        sha256: target.sha256.clone(),
        format: target.format.clone(),
        architecture: target.architecture.clone(),
    }
}

fn evidence_integrity(message: &str, user_message: Option<String>) -> AnalysisError {
    ErrorKind::EvidenceIntegrity {
        message: message.to_owned(),
        user_message,
    }
    .into()
}

fn snapshot_mismatch(message: &str) -> AnalysisError {
    ErrorKind::SnapshotMismatch {
        message: message.to_owned(),
    }
    .into()
}

/// `commitExecutionProfile`: attach the selected profile only when the
/// provider identity agrees.
fn commit_execution_profile(
    operation: &str,
    result: Result<AnalysisExecution, AnalysisError>,
    profile: Option<&Value>,
) -> Result<AnalysisExecution, AnalysisError> {
    let mut execution = result?;
    let Some(profile) = profile else {
        return Ok(execution);
    };
    let committed = &profile["provider"];
    let committed_id = committed["id"].as_str().unwrap_or_default();
    if committed["id"].as_str() != Some(execution.provider.id.as_str())
        || committed["name"].as_str() != Some(execution.provider.name.as_str())
        || committed["version"].as_str() != execution.provider.version.as_deref()
    {
        return Err(provider_adapter(
            committed_id,
            &format!("{operation}:profile"),
            None,
        ));
    }
    execution.analysis_profile = Some(profile.clone());
    Ok(execution)
}

/// `bindExecutionTarget`: bind an execution to the selected target,
/// preserving valid artifact-bundle subjects.
fn bind_execution_target(
    result: Result<AnalysisExecution, AnalysisError>,
    operation: &str,
    target: &BinaryTarget,
) -> Result<AnalysisExecution, AnalysisError> {
    let mut execution = result?;
    if let Some(subject) = &execution.subject {
        let artifact_bundle = matches!(
            operation,
            "inventory_artifact" | "inspect_artifact" | "extract_artifact"
        ) && subject.path
            == *target.source_path.as_ref().unwrap_or(&target.path);
        if subject.sha256 != target.sha256 && !artifact_bundle {
            return Err(provider_adapter(
                &execution.provider.id,
                &format!("{operation}:subject"),
                None,
            ));
        }
    }
    if execution.subject.is_none() {
        execution.subject = Some(subject_of(target));
    }
    Ok(execution)
}

/// `sameSessionTarget`: native admission is bound to the requested path,
/// not just its realpath.
fn same_session_target(current: Option<&BinaryTarget>, target: &BinaryTarget) -> bool {
    let Some(current) = current else {
        return false;
    };
    current.path == target.path
        && current.source_path.as_ref().unwrap_or(&current.path)
            == target.source_path.as_ref().unwrap_or(&target.path)
        && target_identity_matches(current, target)
}

/// Merge a snapshot's Evidence bundle into the session ledger.
fn merge_evidence_bundle(session: &Arc<Session>, bundle: &Value) -> Result<usize, AnalysisError> {
    let raw = serde_json::value::to_raw_value(bundle)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    let parsed = EvidenceBundle::parse(&raw)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    let receipt = session
        .records()
        .import(parsed)
        .map_err(rea_mcp::session::record_error)?;
    Ok(receipt.imported)
}

/// Every catalog tool with the given kind.
pub(crate) fn tools_of_kind(kind: &str) -> Vec<&'static str> {
    rea_mcp::catalog()
        .tools
        .iter()
        .filter(|tool| tool.kind == kind)
        .map(|tool| tool.name.as_str())
        .collect()
}

fn is_tool_of_kind(operation: &str, kind: &str) -> bool {
    rea_mcp::catalog()
        .tool(operation)
        .is_some_and(|tool| tool.kind == kind)
}

impl BinarySession {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn router(&self) -> Arc<Router> {
        self.router.get().cloned().unwrap_or_else(empty_router)
    }

    fn files(&self) -> MutexGuard<'_, SnapshotFiles> {
        self.files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The active route, or the router's target-free route.
    pub(crate) fn current_route(&self) -> Arc<Route> {
        let active = self.lock().active.clone();
        match active {
            Some(active) => Arc::clone(&active.run.route),
            None => self.router().initial_route(),
        }
    }

    /// Enter one lifecycle transition after every earlier one settled.
    fn begin_transition(&self) -> (TransitionGuard<'_>, u64) {
        let mut inner = self.lock();
        for controller in inner.prompt_controllers.values() {
            controller.cancel("binary session lifecycle transition");
        }
        inner.pending_transitions += 1;
        let ticket = inner.next_ticket;
        inner.next_ticket += 1;
        while inner.completed < ticket {
            inner = self
                .changed
                .wait(inner)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        drop(inner);
        (TransitionGuard { state: self }, ticket)
    }

    /// Wait for every call admitted before `admitted_through`.
    fn drain(&self, admitted_through: u64) {
        let mut inner = self.lock();
        while inner
            .calls
            .values()
            .any(|generation| *generation <= admitted_through)
        {
            inner = self
                .changed
                .wait(inner)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    /// Register one call and wait for transitions enqueued before it.
    fn admit(
        &self,
        operation: &str,
        cancellation: &Cancellation,
    ) -> Result<CallGuard<'_>, AnalysisError> {
        let id = {
            let mut inner = self.lock();
            let generation = inner.next_ticket;
            let id = inner.next_call;
            inner.next_call += 1;
            inner.calls.insert(id, generation);
            id
        };
        let guard = CallGuard { state: self, id };
        let admitted = {
            let mut inner = self.lock();
            let generation = inner.calls.get(&id).copied().unwrap_or_default();
            loop {
                if cancellation.reason().is_some() {
                    break false;
                }
                if inner.completed >= generation {
                    break true;
                }
                inner = self
                    .changed
                    .wait_timeout(inner, ADMISSION_POLL)
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .0;
            }
        };
        if admitted {
            Ok(guard)
        } else {
            Err(AnalysisError::cancelled(operation))
        }
    }

    /// Hold the active binding through one complete composed operation.
    pub(crate) fn with_admitted_analysis<T>(
        &self,
        session: &Arc<Session>,
        operation: &str,
        cancellation: &Cancellation,
        work: impl FnOnce(&SessionPort<'_>) -> T,
    ) -> Result<T, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let _call = self.admit(operation, cancellation)?;
        let port = SessionPort {
            state: self,
            session,
        };
        Ok(work(&port))
    }

    /// Report availability on the currently selected route without starting it.
    pub(crate) fn supports_operation(&self, operation: &str) -> bool {
        self.current_route()
            .capabilities
            .get(operation)
            .is_some_and(|descriptor| descriptor.available)
    }

    /// Execute one provider operation against the admitted active target.
    fn execute_admitted(
        &self,
        session: &Arc<Session>,
        operation: &str,
        parameters: &Map<String, Value>,
        options: &ExecutionOptions,
    ) -> Result<AnalysisExecution, AnalysisError> {
        if options.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let router = self.router();
        let (active, capability, profile, cacheable) = {
            let inner = self.lock();
            let Some(active) = inner.active.clone() else {
                return Err(AnalysisError::no_binary_open());
            };
            let route = &active.run.route;
            let declared = route.capabilities.get(operation);
            let Some(capability) = declared.filter(|descriptor| descriptor.available).cloned()
            else {
                if let Some(error) = router.unbound_operation_error(operation, route) {
                    return Err(error);
                }
                let provider_id = route.binding.as_ref().map_or_else(
                    || route.identity.id.clone(),
                    |binding| binding.identity.id.clone(),
                );
                let reason = declared
                    .and_then(|descriptor| descriptor.reason.clone())
                    .unwrap_or_else(|| "operation is not declared by this provider".to_owned());
                return Err(AnalysisError::capability_unavailable(
                    provider_id,
                    operation,
                    reason,
                ));
            };
            let profile = active
                .profile
                .as_ref()
                .filter(|profile| {
                    profile["provider"]["id"].as_str() == Some(capability.provider.id.as_str())
                })
                .cloned();
            let cacheable = profile.is_some()
                && is_snapshot_cacheable(operation, Some(&capability), parameters);
            if cacheable
                && !REPLAY_EXCLUDED.contains(&operation)
                && !inner.snapshot_invalidated
                && let Some(profile) = &profile
                && let Some(cached) =
                    inner
                        .snapshot
                        .lookup(&active.target, profile, operation, parameters)
            {
                return Ok(cached);
            }
            (active, capability, profile, cacheable)
        };
        // A failed reply cannot prove that a dispatched metadata write rolled
        // back. Stop replay before dispatch, including overlapping reads.
        if capability.effects.mutates_artifact {
            self.lock().invalidate_snapshot();
        }
        let result = active.run.client.execute(operation, parameters, options);
        let profiled = bind_execution_target(
            commit_execution_profile(operation, result, profile.as_ref()),
            operation,
            &active.target,
        );
        let execution = match profiled {
            Ok(mut execution)
                if (operation == "procedure_callers" || operation == "procedure_callees")
                    && execution.relationship_coverage.is_none() =>
            {
                execution.relationship_coverage = Some(json!({
                    "status": "unknown",
                    "reason": "Provider did not report relationship coverage for this observation.",
                }));
                Ok(execution)
            }
            other => other,
        };
        self.observe_runtime_availability(operation, &execution);
        if let Ok(execution) = &execution
            && cacheable
            && let Some(profile) = &profile
            && !REPLAY_EXCLUDED.contains(&operation)
        {
            let evidence =
                execution.evidence(operation, Value::Object(parameters.clone()), "observed")?;
            session.record(&evidence)?;
            let mut inner = self.lock();
            if !inner.snapshot_invalidated {
                inner
                    .snapshot
                    .record(&active.target, profile, operation, parameters, execution);
            }
        }
        execution
    }

    fn observe_runtime_availability(
        &self,
        operation: &str,
        result: &Result<AnalysisExecution, AnalysisError>,
    ) {
        let mut inner = self.lock();
        let error = match result {
            Ok(_) => {
                inner.runtime_unavailability.remove(operation);
                return;
            }
            Err(error) => error,
        };
        if matches!(error.kind, ErrorKind::CapabilityUnavailable { .. }) {
            inner
                .runtime_unavailability
                .insert(operation.to_owned(), error.message());
            return;
        }
        let tag = error.tag();
        if !matches!(
            tag,
            "ProviderAdapterError" | "HopperProcessError" | "HopperStartError"
        ) {
            return;
        }
        let Some(route) = inner
            .active
            .as_ref()
            .map(|active| Arc::clone(&active.run.route))
        else {
            return;
        };
        let Some(provider_id) = route
            .capabilities
            .get(operation)
            .map(|descriptor| descriptor.provider.id.clone())
        else {
            return;
        };
        let reason = format!("{tag}: {}", error.message());
        for descriptor in route.capabilities.values() {
            if descriptor.provider.id == provider_id {
                inner
                    .runtime_unavailability
                    .insert(descriptor.operation.clone(), reason.clone());
            }
        }
    }

    /// Run a prompt lookup only against an already connected provider child.
    pub(crate) fn execute_if_provider_ready(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
    ) -> Option<Result<AnalysisExecution, AnalysisError>> {
        let controller = Cancellation::default();
        let (active, controller_id, call_id) = {
            let mut inner = self.lock();
            if inner.pending_transitions > 0 {
                return None;
            }
            let active = inner.active.clone()?;
            let controller_id = inner.next_controller;
            inner.next_controller += 1;
            inner
                .prompt_controllers
                .insert(controller_id, controller.clone());
            let generation = inner.next_ticket;
            let call_id = inner.next_call;
            inner.next_call += 1;
            inner.calls.insert(call_id, generation);
            (active, controller_id, call_id)
        };
        let _controller = ControllerGuard {
            state: self,
            id: controller_id,
        };
        let _call = CallGuard {
            state: self,
            id: call_id,
        };
        active.run.client.execute_if_ready(
            operation,
            parameters,
            &ExecutionOptions::new(controller),
        )
    }

    /// The active target, if one is open.
    pub(crate) fn active_target(&self) -> Option<BinaryTarget> {
        self.lock()
            .active
            .as_ref()
            .map(|active| active.target.clone())
    }

    /// `providerIdentity(operation)`.
    pub(crate) fn provider_identity(&self, operation: Option<&str>) -> ProviderIdentity {
        let route = self.current_route();
        let mut selected = route.binding.as_ref().map_or_else(
            || route.identity.clone(),
            |binding| binding.identity.clone(),
        );
        if let Some(operation) = operation {
            if let Some(exact) = route.capabilities.get(operation) {
                selected = exact.provider.clone();
            } else if is_tool_of_kind(operation, "enhanced") {
                let mut providers = BTreeMap::new();
                for descriptor in route.capabilities.values() {
                    if descriptor.available
                        && is_tool_of_kind(&descriptor.operation, "official-proxy")
                    {
                        providers
                            .insert(descriptor.provider.id.clone(), descriptor.provider.clone());
                    }
                }
                if providers.len() == 1
                    && let Some(provider) = providers.into_values().next()
                {
                    selected = provider;
                }
            }
        }
        selected
    }

    /// `analysisProfile(operation)`.
    pub(crate) fn analysis_profile(&self, operation: Option<&str>) -> Option<Value> {
        let profile = self
            .lock()
            .active
            .as_ref()
            .and_then(|active| active.profile.clone())?;
        if let Some(operation) = operation
            && profile["provider"]["id"].as_str()
                != Some(self.provider_identity(Some(operation)).id.as_str())
        {
            return None;
        }
        Some(profile)
    }

    /// `allowsSnapshotReplay(operation)`: external live state cannot be
    /// replayed by a direct or composed workflow.
    pub(crate) fn allows_snapshot_replay(&self, operation: &str) -> bool {
        let active = self.lock().active.clone();
        let Some(active) = active else {
            return true;
        };
        let capabilities = &active.run.route.capabilities;
        match capabilities.get(operation) {
            Some(descriptor) => descriptor.cache_policy.as_deref() != Some("live"),
            None => !capabilities
                .values()
                .any(|descriptor| descriptor.cache_policy.as_deref() == Some("live")),
        }
    }

    /// Invalidate cached Evidence before an external command may mutate the target.
    pub(crate) fn invalidate_snapshot_for_external_mutation(&self) {
        self.lock().invalidate_snapshot();
    }

    /// `recordWorkflowSnapshot`: retain one derived workflow result.
    pub(crate) fn record_workflow_snapshot(
        &self,
        snapshot: WorkflowSnapshot,
    ) -> Result<(), AnalysisError> {
        let mut inner = self.lock();
        let Some((target, profile)) = inner.active.as_ref().and_then(|active| {
            active
                .profile
                .clone()
                .map(|profile| (active.target.clone(), profile))
        }) else {
            return Err(evidence_integrity(
                "Workflow snapshot entries require an active concrete provider profile",
                None,
            ));
        };
        if inner.snapshot_invalidated {
            return Ok(());
        }
        let Some(parameters) = snapshot.parameters.as_object() else {
            return Err(evidence_integrity(
                "Workflow snapshot entry validation failed",
                None,
            ));
        };
        let execution = workflow_execution(&snapshot.evidence);
        inner
            .snapshot
            .record_workflow(
                &target,
                &profile,
                &snapshot.operation,
                parameters,
                &execution,
            )
            .map_err(|message| evidence_integrity(&message, None))
    }

    /// Resolve a known target's route and validate the snapshot binding.
    fn resolve_open(
        &self,
        path: &str,
        options: &OpenOptions,
        snapshot: Option<&AnalysisSnapshot>,
        cancellation: &Cancellation,
    ) -> Result<(BinaryTarget, Arc<Route>, bool), AnalysisError> {
        let target = parse_binary_target(
            path,
            &TargetOptions {
                target_kind: None,
                format_hint: options.format_hint.clone(),
                architecture: options.architecture.clone(),
                entry_point: options.entry_point.clone(),
            },
            cancellation,
        )?;
        let current = self.lock().active.clone();
        let same_target =
            same_session_target(current.as_ref().map(|active| &active.target), &target);
        let route = match (&current, same_target, &options.provider_id) {
            (Some(current), true, None) => Arc::clone(&current.run.route),
            _ => self
                .router()
                .resolve(&target, options.provider_id.as_deref(), cancellation)?,
        };
        if let Some(snapshot) = snapshot
            && route
                .profile
                .as_ref()
                .is_none_or(|profile| !snapshot_matches_binding(snapshot, &target, profile))
        {
            return Err(snapshot_mismatch(
                "Analysis snapshot profile_mismatch: target, provider, or analysis profile does not match the requested binary",
            ));
        }
        if current.is_none()
            && !self
                .lock()
                .snapshot
                .matches(&target, route.profile.as_ref())
        {
            return Err(snapshot_mismatch(
                "Analysis snapshot profile_mismatch: staged target, provider, or analysis profile does not match",
            ));
        }
        Ok((target, route, same_target))
    }

    /// Open or switch targets after draining calls against the current target.
    pub(crate) fn open(
        &self,
        session: &Arc<Session>,
        path: &str,
        options: OpenOptions,
        cancellation: &Cancellation,
    ) -> Result<BinaryTarget, AnalysisError> {
        let (_transition, admitted_through) = self.begin_transition();
        let snapshot = match &options.snapshot_path {
            None => None,
            Some(snapshot_path) => {
                if cancellation.reason().is_some() {
                    return Err(AnalysisError::cancelled("open_binary"));
                }
                Some(load_snapshot(snapshot_path, cancellation)?)
            }
        };
        let external = self.lock().external_mutation_cleanup_failure.clone();
        if let Some(failure) = external.filter(AnalysisError::is_cleanup_incomplete) {
            return Err(failure);
        }
        let cancelled = || AnalysisError::cancelled("open_binary");
        if cancellation.reason().is_some() {
            return Err(cancelled());
        }
        let (target, route, same_target) =
            self.resolve_open(path, &options, snapshot.as_ref(), cancellation)?;
        if cancellation.reason().is_some() {
            return Err(cancelled());
        }
        let current = self.lock().active.clone();
        let same_profile = match current.as_ref().and_then(|active| active.profile.as_ref()) {
            None => route.profile.is_none(),
            Some(active_profile) => route
                .profile
                .as_ref()
                .is_some_and(|profile| analysis_profiles_equal(active_profile, profile)),
        };
        self.drain(admitted_through);
        if cancellation.reason().is_some() {
            return Err(cancelled());
        }
        self.retry_pending_cleanup(None)?;
        if cancellation.reason().is_some() {
            return Err(cancelled());
        }
        if same_target
            && same_profile
            && let Some(retained) = &current
        {
            let live = retained_client_live(&retained.run.client, cancellation);
            if cancellation.reason().is_some() {
                return Err(cancelled());
            }
            if live {
                if let Some(snapshot) = &snapshot {
                    self.import_analysis_snapshot(session, snapshot)?;
                }
                return Ok(target);
            }
        }
        let previous = self.lock().active.take();
        if let Some(previous) = &previous
            && let Err(closed) = self.retire_client(Arc::clone(&previous.run), false)
        {
            // A failed open retires the provider cache, not the investigation.
            let mut inner = self.lock();
            inner.snapshot.clear();
            inner.runtime_unavailability.clear();
            return Err(closed);
        }
        if cancellation.reason().is_some() {
            return Err(self.restore_after_failed_open(previous, cancelled()));
        }
        let run_id = uuid::Uuid::new_v4().to_string();
        let client = Arc::new(route.create_client(&target, &run_id));
        let run = Arc::new(SessionRun {
            client: Arc::clone(&client),
            route: Arc::clone(&route),
            run_id,
        });
        let started = client.execute(
            "health",
            &Map::new(),
            &ExecutionOptions::new(cancellation.clone()),
        );
        if let Err(error) = started {
            return Err(self.failed_open(run, previous, error));
        }
        if cancellation.reason().is_some() {
            return Err(self.failed_open(run, previous, cancelled()));
        }
        {
            let mut inner = self.lock();
            inner.active = Some(Arc::new(ActiveBinding {
                target: target.clone(),
                profile: route.profile.clone(),
                run: Arc::clone(&run),
            }));
            inner.runtime_unavailability.clear();
            inner.reset_snapshot_invalidation();
            if snapshot.is_none() {
                match &route.profile {
                    None => inner.snapshot.clear(),
                    Some(profile) => inner.snapshot.select(&target, profile),
                }
            }
        }
        if let Some(snapshot) = &snapshot
            && let Err(error) = self.import_analysis_snapshot(session, snapshot)
        {
            self.lock().active = None;
            return Err(self.failed_open(run, previous, error));
        }
        Ok(target)
    }

    fn failed_open(
        &self,
        run: Arc<SessionRun>,
        previous: Option<Arc<ActiveBinding>>,
        primary: AnalysisError,
    ) -> AnalysisError {
        if let Err(closed) = self.retire_client(run, false) {
            return with_cleanup_failure(primary, closed, "open_binary");
        }
        self.restore_after_failed_open(previous, primary)
    }

    fn restore_after_failed_open(
        &self,
        previous: Option<Arc<ActiveBinding>>,
        primary: AnalysisError,
    ) -> AnalysisError {
        match self.restore(previous) {
            Ok(()) => primary,
            Err(error) => with_cleanup_failure(primary, error, "open_binary"),
        }
    }

    fn restore(&self, previous: Option<Arc<ActiveBinding>>) -> Result<(), AnalysisError> {
        let Some(previous) = previous else {
            return Ok(());
        };
        let run_id = uuid::Uuid::new_v4().to_string();
        let route = Arc::clone(&previous.run.route);
        let client = Arc::new(route.create_client(&previous.target, &run_id));
        let run = Arc::new(SessionRun {
            client: Arc::clone(&client),
            route,
            run_id,
        });
        match client.execute(
            "health",
            &Map::new(),
            &ExecutionOptions::new(Cancellation::default()),
        ) {
            Ok(_) => {
                let mut inner = self.lock();
                inner.active = Some(Arc::new(ActiveBinding {
                    target: previous.target.clone(),
                    profile: previous.profile.clone(),
                    run,
                }));
                inner.runtime_unavailability.clear();
                Ok(())
            }
            Err(started) => match self.retire_client(run, false) {
                Ok(()) => Ok(()),
                Err(closed) => Err(with_cleanup_failure(started, closed, "open_binary")),
            },
        }
    }

    fn retire_client(
        &self,
        run: Arc<SessionRun>,
        retain_document: bool,
    ) -> Result<(), AnalysisError> {
        self.lock().pending_cleanup = Some(PendingCleanup {
            run,
            retain_document,
        });
        self.retry_pending_cleanup(None)
    }

    fn retry_pending_cleanup(&self, retain_document: Option<bool>) -> Result<(), AnalysisError> {
        let pending = {
            let mut inner = self.lock();
            let Some(pending) = inner.pending_cleanup.as_mut() else {
                return Ok(());
            };
            if let Some(retain) = retain_document {
                pending.retain_document = retain;
            }
            (Arc::clone(&pending.run), pending.retain_document)
        };
        let closed = pending.0.client.close(pending.1);
        if closed.is_ok() {
            let mut inner = self.lock();
            if inner
                .pending_cleanup
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(&current.run, &pending.0))
            {
                inner.pending_cleanup = None;
            }
        }
        closed
    }

    fn close_active(
        &self,
        retain_provider_documents: Option<bool>,
        clear_records: bool,
    ) -> Result<(), AnalysisError> {
        let previous = self.lock().active.take();
        let closed = match previous {
            None => self.retry_pending_cleanup(retain_provider_documents),
            Some(previous) => self.retire_client(
                Arc::clone(&previous.run),
                retain_provider_documents == Some(true),
            ),
        };
        {
            let mut inner = self.lock();
            if clear_records {
                inner.clear_session_records();
            }
            inner.runtime_unavailability.clear();
        }
        let file_resources = self.files().close();
        let candidate_resources = self.router().close_owned_resources();
        let resource_failure = fold_cleanup_failures(
            [file_resources.err(), candidate_resources.err()]
                .into_iter()
                .flatten()
                .collect(),
            "close_binary",
        );
        match (closed, resource_failure) {
            (Err(closed), Some(resources)) => {
                Err(with_cleanup_failure(closed, resources, "close_binary"))
            }
            (Err(closed), None) => Err(closed),
            (Ok(()), Some(resources)) => Err(resources),
            (Ok(()), None) => Ok(()),
        }
    }

    /// Close the active target, if any.
    pub(crate) fn close(
        &self,
        retain_provider_documents: Option<bool>,
    ) -> Result<(), AnalysisError> {
        let (_transition, admitted_through) = self.begin_transition();
        self.drain(admitted_through);
        self.close_active(retain_provider_documents, true)
    }

    /// Drain earlier requests, save an immutable snapshot, and close under
    /// one lifecycle lock.
    pub(crate) fn close_with_snapshot(
        &self,
        session: &Arc<Session>,
        path: &str,
        overwrite: bool,
    ) -> Result<SavedSnapshot, AnalysisError> {
        let (_transition, admitted_through) = self.begin_transition();
        self.drain(admitted_through);
        let snapshot = self.export_analysis_snapshot(session)?;
        // The original write is not bound to the request signal: once the
        // lifecycle transition holds its turn, the save runs to completion.
        let (path, bytes) =
            self.files()
                .write(&snapshot, path, overwrite, &Cancellation::default())?;
        self.close_active(None, true)?;
        Ok(SavedSnapshot {
            path,
            bytes,
            primitive_entries: snapshot.entry_count(),
            workflow_entries: snapshot.workflow_entry_count(),
            evidence_records: snapshot.evidence_record_count(),
        })
    }

    /// `exportAnalysisSnapshot`.
    pub(crate) fn export_analysis_snapshot(
        &self,
        session: &Arc<Session>,
    ) -> Result<AnalysisSnapshot, AnalysisError> {
        let (target, profile) = {
            let inner = self.lock();
            if inner.snapshot_invalidated {
                return Err(evidence_integrity(
                    "Analysis snapshots are unavailable because analysis metadata may have changed",
                    Some(format!(
                        "Analysis snapshots are unavailable because analysis metadata may have changed. {SNAPSHOT_MUTATION_RECOVERY}"
                    )),
                ));
            }
            (
                inner.active.as_ref().map(|active| active.target.clone()),
                inner
                    .active
                    .as_ref()
                    .and_then(|active| active.profile.clone()),
            )
        };
        if target.is_some() && profile.is_none() {
            return Err(evidence_integrity(
                "Analysis snapshots require a concrete provider analysis profile",
                None,
            ));
        }
        let bundle = session.export_bundle()?;
        let bundle = match &target {
            None => bundle,
            Some(target) => evidence_bundle_for_target(&bundle, &target.sha256),
        };
        self.lock()
            .snapshot
            .export(target.as_ref(), profile.as_ref(), bundle)
    }

    /// `importAnalysisSnapshot`.
    pub(crate) fn import_analysis_snapshot(
        &self,
        session: &Arc<Session>,
        snapshot: &AnalysisSnapshot,
    ) -> Result<usize, AnalysisError> {
        let mut inner = self.lock();
        let active = inner.active.clone();
        if active.is_some() && inner.snapshot_invalidated {
            return Err(evidence_integrity(
                "Analysis snapshots cannot be imported because analysis metadata may have changed",
                Some(format!(
                    "Analysis snapshots cannot be imported because analysis metadata may have changed. {SNAPSHOT_MUTATION_RECOVERY}"
                )),
            ));
        }
        if let Some(active) = &active
            && active.profile.is_none()
        {
            return Err(snapshot_mismatch(
                "Analysis snapshot profile_mismatch: the active target has no concrete analysis profile",
            ));
        }
        let binding = active.as_ref().and_then(|active| {
            active
                .profile
                .as_ref()
                .map(|profile| (&active.target, profile))
        });
        let mut merge = |bundle: &Value| merge_evidence_bundle(session, bundle);
        inner.snapshot.import(snapshot, binding, &mut merge)
    }

    /// Serialize an external mutation and retire the potentially stale analysis.
    pub(crate) fn with_admitted_external_mutation<T>(
        &self,
        operation_name: &str,
        cancellation: &Cancellation,
        operation: impl FnOnce() -> Result<T, AnalysisError>,
        retirement_failure: impl FnOnce(&Result<T, AnalysisError>, AnalysisError) -> AnalysisError,
        cleanup_recovery: Option<&dyn Fn(Option<&AnalysisError>) -> Result<(), AnalysisError>>,
    ) -> Result<Result<T, AnalysisError>, AnalysisError> {
        let (_transition, admitted_through) = self.begin_transition();
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation_name));
        }
        self.drain(admitted_through);
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation_name));
        }
        let retained = self.lock().external_mutation_cleanup_failure.clone();
        if let Some(failure) = retained.filter(AnalysisError::is_cleanup_incomplete) {
            let Some(recovery) = cleanup_recovery else {
                return Err(failure);
            };
            recovery(Some(&failure))?;
            // A confirmed recovery releases the retained cleanup owner.
            self.lock().external_mutation_cleanup_failure = None;
        }
        self.retry_pending_cleanup(None)?;
        let active = self.lock().active.clone();
        // A protocol reply does not prove that background writers stopped.
        // Retire the old analysis and require an explicit fresh open.
        let retire_target = active.is_some();
        self.lock().invalidate_snapshot();
        let value = operation();
        self.lock().external_mutation_cleanup_failure = match &value {
            Err(error) if error.is_cleanup_incomplete() => Some(error.clone()),
            _ => None,
        };
        if !retire_target {
            return Ok(value);
        }
        if let Err(error) = self.close_active(None, false) {
            return Err(retirement_failure(&value, error));
        }
        Ok(value)
    }

    /// Describe the active binary session (`binarySessionStatus`).
    pub(crate) fn status(&self, cancellation: &Cancellation) -> Result<Value, AnalysisError> {
        let router = self.router();
        let (target, route, run, unavailability, local_cleanup_pending) = {
            let inner = self.lock();
            let run = inner
                .active
                .as_ref()
                .map(|active| Arc::clone(&active.run))
                .or_else(|| {
                    inner
                        .pending_cleanup
                        .as_ref()
                        .map(|pending| Arc::clone(&pending.run))
                });
            (
                inner.active.as_ref().map(|active| active.target.clone()),
                inner
                    .active
                    .as_ref()
                    .map(|active| Arc::clone(&active.run.route)),
                run,
                inner.runtime_unavailability.clone(),
                inner.pending_cleanup.is_some(),
            )
        };
        let local_cleanup_pending = local_cleanup_pending || self.files().has_pending();
        let route = route.unwrap_or_else(|| router.initial_route());
        let lineage = run
            .as_ref()
            .map(|run| run.client.runtime_lineage())
            .unwrap_or_default();
        let activity = run
            .as_ref()
            .map(|run| run.client.request_activity())
            .unwrap_or_default();
        let health = run.as_ref().and_then(|run| run.client.operation_health());
        let cleanup_pending = local_cleanup_pending || router.has_pending_owned_resources();

        let route_capabilities = route
            .capabilities
            .values()
            .filter(|descriptor| descriptor.operation != "inventory_artifact")
            .map(
                |descriptor| match unavailability.get(&descriptor.operation) {
                    None => descriptor.clone(),
                    Some(reason) => CapabilityDescriptor {
                        available: false,
                        reason: Some(reason.clone()),
                        ..descriptor.clone()
                    },
                },
            )
            .collect::<Vec<_>>();
        let binding = route.binding.as_ref().map_or(Value::Null, |binding| {
            json!({
                "provider": binding.identity.to_json(),
                "selection_source": binding.selection_source,
                "analysis_profile": binding.profile,
            })
        });
        let candidates = router
            .candidate_statuses(&route, cancellation)?
            .into_iter()
            .map(|candidate| {
                let mut capabilities = candidate
                    .capabilities
                    .iter()
                    .filter(|descriptor| descriptor.operation != "inventory_artifact")
                    .cloned()
                    .collect::<Vec<_>>();
                capabilities.sort_by(|left, right| left.operation.cmp(&right.operation));
                json!({
                    "provider": candidate.provider.to_json(),
                    "availability": candidate.availability.to_json(),
                    "target_support": candidate.target_support.to_json(),
                    "selected": candidate.selected,
                    "capabilities": provider_capability_sets(&capabilities),
                })
            })
            .collect::<Vec<_>>();
        let mut status = Map::new();
        status.insert("open".into(), json!(target.is_some()));
        status.insert("cleanup_pending".into(), json!(cleanup_pending));
        status.insert(
            "capabilities".into(),
            provider_capability_sets(&route_capabilities),
        );
        status.insert("analysis_provider_binding".into(), binding);
        status.insert(
            "analysis_provider_candidates".into(),
            Value::Array(candidates),
        );
        status.insert(
            "analysis_run".into(),
            run.as_ref().map_or(Value::Null, |run| {
                json!({ "run_id": run.run_id, "process_lineage": process_lineage_status(&lineage) })
            }),
        );
        status.insert(
            "analysis_activity".into(),
            request_activity_status(&activity),
        );
        status.insert(
            "provider_operation_health".into(),
            health
                .as_ref()
                .map_or(Value::Null, provider_operation_health_status),
        );
        if let Some(target) = &target
            && let Value::Object(summary) = binary_target_summary(target)
        {
            for (key, value) in summary {
                status.insert(key, value);
            }
        }
        Ok(Value::Object(status))
    }
}

/// Read a staged snapshot inside the open's lifecycle turn.
fn load_snapshot(
    path: &str,
    cancellation: &Cancellation,
) -> Result<AnalysisSnapshot, AnalysisError> {
    snapshot::read_analysis_snapshot(path, cancellation)
}

/// Probe whether a retained provider client is still live. Only the
/// known-live states allow the fast path; without a health snapshot the
/// gate falls back to the health admission probe.
fn retained_client_live(client: &RouteClient, cancellation: &Cancellation) -> bool {
    if client.reuse_readiness() == "blocked" {
        return false;
    }
    if let Some(snapshot) = client.operation_health() {
        let state = snapshot["state"].as_str();
        return state == Some("idle") || state == Some("busy");
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client
            .execute(
                "health",
                &Map::new(),
                &ExecutionOptions::new(cancellation.clone()),
            )
            .is_ok()
    }))
    .unwrap_or(false)
}

/// Derive the snapshot execution of a composed workflow from its Evidence.
fn workflow_execution(evidence: &Value) -> AnalysisExecution {
    let provider = &evidence["provider"];
    let mut execution = AnalysisExecution::new(
        evidence
            .get("normalized_result")
            .cloned()
            .unwrap_or(Value::Null),
        ProviderIdentity::new(
            provider["id"].as_str().unwrap_or_default(),
            provider["name"].as_str().unwrap_or_default(),
            provider["version"].as_str().map(str::to_owned),
        ),
    );
    execution.raw_result = evidence
        .get("raw_result")
        .filter(|raw| !raw.is_null())
        .cloned();
    execution.analysis_profile = evidence
        .get("analysis_profile")
        .filter(|profile| !profile.is_null())
        .cloned();
    execution.limitations = evidence["limitations"]
        .as_array()
        .map(|limitations| {
            limitations
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    execution.relationship_coverage = evidence
        .get("relationship_coverage")
        .filter(|coverage| !coverage.is_null())
        .cloned();
    execution.locations = evidence["locations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    execution.subject = evidence
        .get("subject")
        .filter(|subject| !subject.is_null())
        .map(|subject| SubjectTarget {
            path: subject["local_path"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            sha256: subject["digest"]["sha256"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            format: subject["format"].as_str().unwrap_or_default().to_owned(),
            architecture: subject["architecture"].as_str().map(str::to_owned),
        });
    execution
}

fn field<'a>(value: &'a Value, snake: &str, camel: &str) -> Value {
    value
        .get(snake)
        .or_else(|| value.get(camel))
        .cloned()
        .unwrap_or(Value::Null)
}

fn provider_summary(provider: &Value) -> Value {
    json!({
        "id": provider.get("id").cloned().unwrap_or(Value::Null),
        "name": provider.get("name").cloned().unwrap_or(Value::Null),
        "version": provider.get("version").cloned().unwrap_or(Value::Null),
    })
}

fn by_provider_id(snapshots: &[Value]) -> Vec<&Value> {
    let mut sorted = snapshots.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left["provider"]["id"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["provider"]["id"].as_str().unwrap_or_default())
    });
    sorted
}

/// `processLineageStatus` over provider runtime-lineage snapshots.
fn process_lineage_status(snapshots: &[Value]) -> Value {
    if snapshots.is_empty() {
        return json!({ "status": "not_observed" });
    }
    let projected = by_provider_id(snapshots)
        .into_iter()
        .map(|snapshot| {
            let observation = &snapshot["observation"];
            let projected = if observation["status"] == "unavailable" {
                json!({
                    "status": "unavailable",
                    "observed_at": field(observation, "observed_at", "observedAt"),
                    "launcher_pid": field(observation, "launcher_pid", "launcherPid"),
                    "process_group_id": field(observation, "process_group_id", "processGroupId"),
                    "reason": field(observation, "reason", "reason"),
                })
            } else {
                let lineage = observation.get("lineage").unwrap_or(observation);
                let descendants = lineage["descendants"]
                    .as_array()
                    .map(|descendants| {
                        descendants
                            .iter()
                            .map(|descendant| {
                                json!({
                                    "pid": field(descendant, "pid", "pid"),
                                    "parent_pid": field(descendant, "parent_pid", "parentPid"),
                                    "process_group_id": field(descendant, "process_group_id", "processGroupId"),
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                json!({
                    "status": observation.get("status").cloned().unwrap_or(Value::Null),
                    "observed_at": field(observation, "observed_at", "observedAt"),
                    "launcher_pid": field(lineage, "launcher_pid", "launcherPid"),
                    "launcher_parent_pid": field(lineage, "launcher_parent_pid", "launcherParentPid"),
                    "process_group_id": field(lineage, "process_group_id", "processGroupId"),
                    "descendants": descendants,
                })
            };
            json!({ "provider": provider_summary(&snapshot["provider"]), "observation": projected })
        })
        .collect::<Vec<_>>();
    json!({ "status": "snapshots", "snapshots": projected })
}

/// `requestActivityStatus` over provider serial-request activity snapshots.
fn request_activity_status(snapshots: &[Value]) -> Value {
    let providers = by_provider_id(snapshots)
        .into_iter()
        .map(|snapshot| {
            let active = &snapshot["active"];
            json!({
                "provider": provider_summary(&snapshot["provider"]),
                "active": if active.is_object() {
                    json!({
                        "request_id": field(active, "request_id", "requestId"),
                        "operation": field(active, "operation", "operation"),
                        "elapsed_ms": field(active, "elapsed_ms", "elapsedMs"),
                        "caller_state": field(active, "caller_state", "callerState"),
                    })
                } else {
                    Value::Null
                },
                "queued_requests": field(snapshot, "queued_requests", "queuedRequests"),
            })
        })
        .collect::<Vec<_>>();
    let busy = snapshots
        .iter()
        .any(|snapshot| snapshot["active"].is_object());
    json!({
        "status": if snapshots.is_empty() { "not_observed" } else if busy { "busy" } else { "idle" },
        "providers": providers,
    })
}

/// `providerOperationHealthStatus`.
fn provider_operation_health_status(health: &Value) -> Value {
    let requests = health["requests"]
        .as_array()
        .map(|requests| {
            requests
                .iter()
                .map(|request| {
                    json!({
                        "request_id": field(request, "request_id", "requestId"),
                        "operation": field(request, "operation", "operation"),
                        "stage": field(request, "stage", "stage"),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "state": field(health, "state", "state"),
        "stage": field(health, "stage", "stage"),
        "retry_action": field(health, "retry_action", "retryAction"),
        "exit_code": field(health, "exit_code", "exitCode"),
        "requests": requests,
    })
}

/// Port bound to one admitted call.
pub(crate) struct SessionPort<'a> {
    state: &'a BinarySession,
    session: &'a Arc<Session>,
}

impl SessionPort<'_> {
    /// The active target at the time of the call.
    pub(crate) fn active_target(&self) -> Option<BinaryTarget> {
        self.state.active_target()
    }
}

impl AnalysisPort for SessionPort<'_> {
    fn supports_operation(&self, operation: &str) -> bool {
        self.state.supports_operation(operation)
    }

    fn execute(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        options: &ExecutionOptions,
    ) -> Result<AnalysisExecution, AnalysisError> {
        self.state
            .execute_admitted(self.session, operation, parameters, options)
    }
}

impl SessionResource for BinarySession {
    /// Close the active client and candidate resources at session shutdown,
    /// retaining failures for a later retry.
    fn close(&self) -> Result<(), AnalysisError> {
        BinarySession::close(self, None)
    }
}

// ---------------------------------------------------------------------------
// `port` implementation.
// ---------------------------------------------------------------------------

pub(crate) fn with_admitted_analysis<T>(
    session: &Arc<Session>,
    operation: &str,
    cancellation: &Cancellation,
    work: impl FnOnce(&dyn AnalysisPort) -> T,
) -> Result<T, AnalysisError> {
    binary_session(session)
        .with_admitted_analysis(session, operation, cancellation, |port| work(port))
}

pub(crate) fn active_target(session: &Arc<Session>) -> Option<BinaryTarget> {
    binary_session(session).active_target()
}

pub(crate) fn provider_identity(
    session: &Arc<Session>,
    operation: Option<&str>,
) -> Option<ProviderIdentity> {
    Some(binary_session(session).provider_identity(operation))
}

pub(crate) fn analysis_profile(session: &Arc<Session>, operation: Option<&str>) -> Option<Value> {
    binary_session(session).analysis_profile(operation)
}

pub(crate) fn allows_snapshot_replay(session: &Arc<Session>, operation: &str) -> bool {
    binary_session(session).allows_snapshot_replay(operation)
}

pub(crate) fn record_workflow_snapshot(
    session: &Arc<Session>,
    snapshot: WorkflowSnapshot,
) -> Result<(), AnalysisError> {
    binary_session(session).record_workflow_snapshot(snapshot)
}

pub(crate) fn invalidate_snapshot_for_external_mutation(session: &Arc<Session>) {
    binary_session(session).invalidate_snapshot_for_external_mutation();
}

pub(crate) fn supports_operation(session: &Arc<Session>, operation: &str) -> bool {
    binary_session(session).supports_operation(operation)
}

pub(crate) fn with_admitted_external_mutation<T>(
    session: &Arc<Session>,
    operation_name: &str,
    cancellation: &Cancellation,
    operation: impl FnOnce() -> Result<T, AnalysisError>,
    retirement_failure: impl FnOnce(&Result<T, AnalysisError>, AnalysisError) -> AnalysisError,
    cleanup_recovery: Option<&dyn Fn(Option<&AnalysisError>) -> Result<(), AnalysisError>>,
) -> Result<Result<T, AnalysisError>, AnalysisError> {
    binary_session(session).with_admitted_external_mutation(
        operation_name,
        cancellation,
        operation,
        retirement_failure,
        cleanup_recovery,
    )
}
