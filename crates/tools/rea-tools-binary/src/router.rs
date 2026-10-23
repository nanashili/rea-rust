//! Deep-provider discovery, selection and operation routing.
//!
//! Compatibility owners: `src/application/binary/AnalysisProviderRegistry.ts`,
//! `AnalysisProviderEvaluation.ts`, `SessionProviderRouter.ts` and
//! `CompositeProvider.ts`. Providers are discovered and selected without
//! starting their clients; registration order never affects selection or
//! caller-visible output.
use crate::errors::{
    close_analysis_client, is_cancelled, provider_adapter, provider_cleanup_error,
    provider_selection,
};
use rea_analysis::{
    AnalysisClient, AnalysisExecution, AnalysisProvider, BinaryTarget, CapabilityDescriptor,
    ExecutionOptions, ProviderAvailability, ProviderIdentity, TargetSupport,
};
use rea_core::analysis_error::{
    AnalysisError, CleanupObservation, ErrorKind, SelectionRejection, SettingIssue,
};
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// Name of every synthetic composite provider identity.
pub(crate) const COMPOSITE_PROVIDER_NAME: &str = "REA composite analysis provider";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// `analysisProviderIdSchema`: `^[a-z][a-z0-9-]*$`, never `auto`.
pub(crate) fn is_provider_id(value: &str) -> bool {
    let mut characters = value.chars();
    value != "auto"
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// `analysisProviderSelectorSchema`: `auto` or a provider ID.
pub(crate) fn is_provider_selector(value: &str) -> bool {
    value == "auto" || is_provider_id(value)
}

/// Provider readiness as reported in discovery (`unknown` only while
/// candidate ownership finalization is in progress).
#[derive(Clone, Debug)]
pub(crate) enum Availability {
    Unknown {
        reason: String,
        diagnostics: Map<String, Value>,
    },
    Available {
        diagnostics: Map<String, Value>,
    },
    Unavailable {
        code: String,
        reason: String,
        diagnostics: Map<String, Value>,
    },
}

impl Availability {
    fn from_provider(availability: ProviderAvailability) -> Self {
        match availability {
            ProviderAvailability::Available { diagnostics } => Self::Available { diagnostics },
            ProviderAvailability::Unavailable {
                code,
                reason,
                diagnostics,
            } => Self::Unavailable {
                code,
                reason,
                diagnostics,
            },
        }
    }

    pub(crate) fn diagnostics(&self) -> &Map<String, Value> {
        match self {
            Self::Unknown { diagnostics, .. }
            | Self::Available { diagnostics }
            | Self::Unavailable { diagnostics, .. } => diagnostics,
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        match self {
            Self::Unknown {
                reason,
                diagnostics,
            } => {
                json!({ "status": "unknown", "code": null, "reason": reason, "diagnostics": diagnostics })
            }
            Self::Available { diagnostics } => {
                json!({ "status": "available", "code": null, "reason": null, "diagnostics": diagnostics })
            }
            Self::Unavailable {
                code,
                reason,
                diagnostics,
            } => {
                json!({ "status": "unavailable", "code": code, "reason": reason, "diagnostics": diagnostics })
            }
        }
    }
}

/// Provider-owned target support (`unknown` when no target is parsed).
#[derive(Clone, Debug)]
pub(crate) enum Support {
    Unknown {
        reason: String,
        diagnostics: Map<String, Value>,
    },
    Supported {
        diagnostics: Map<String, Value>,
    },
    Unsupported {
        code: String,
        reason: String,
        diagnostics: Map<String, Value>,
    },
}

impl Support {
    fn from_provider(support: TargetSupport) -> Self {
        match support {
            TargetSupport::Supported { diagnostics } => Self::Supported { diagnostics },
            TargetSupport::Unsupported {
                code,
                reason,
                diagnostics,
            } => Self::Unsupported {
                code,
                reason,
                diagnostics,
            },
        }
    }

    fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported { .. })
    }

    pub(crate) fn to_json(&self) -> Value {
        match self {
            Self::Unknown {
                reason,
                diagnostics,
            } => {
                json!({ "status": "unknown", "code": null, "reason": reason, "diagnostics": diagnostics })
            }
            Self::Supported { diagnostics } => {
                json!({ "status": "supported", "code": null, "reason": null, "diagnostics": diagnostics })
            }
            Self::Unsupported {
                code,
                reason,
                diagnostics,
            } => {
                json!({ "status": "unsupported", "code": code, "reason": reason, "diagnostics": diagnostics })
            }
        }
    }
}

/// Deterministic discovery truth for one configured deep provider.
#[derive(Clone)]
pub(crate) struct CandidateStatus {
    pub provider: ProviderIdentity,
    pub availability: Availability,
    pub target_support: Support,
    pub selected: bool,
    pub capabilities: Vec<CapabilityDescriptor>,
}

/// The internal (camelCase) TS capability descriptor JSON.
pub(crate) fn descriptor_internal_json(descriptor: &CapabilityDescriptor) -> Value {
    let mut object = Map::new();
    object.insert("provider".into(), descriptor.provider.to_json());
    object.insert("operation".into(), json!(descriptor.operation));
    object.insert("available".into(), json!(descriptor.available));
    object.insert("reason".into(), json!(descriptor.reason));
    if let Some(code) = &descriptor.availability_code {
        object.insert("availabilityCode".into(), json!(code));
    }
    if let Some(policy) = &descriptor.cache_policy {
        object.insert("cachePolicy".into(), json!(policy));
    }
    object.insert(
        "effects".into(),
        json!({
            "mutatesArtifact": descriptor.effects.mutates_artifact,
            "launchesProcess": descriptor.effects.launches_process,
            "mayShowUi": descriptor.effects.may_show_ui,
            "mayAccessNetwork": descriptor.effects.may_access_network,
            "mayWriteFilesystem": descriptor.effects.may_write_filesystem,
            "changesPermissions": descriptor.effects.changes_permissions,
            "requiresRoot": descriptor.effects.requires_root,
        }),
    );
    object.insert("limitations".into(), json!(descriptor.limitations));
    Value::Object(object)
}

impl CandidateStatus {
    /// The internal TS candidate-status JSON retained in failure diagnostics.
    fn internal_json(&self) -> Value {
        json!({
            "provider": self.provider.to_json(),
            "availability": self.availability.to_json(),
            "targetSupport": self.target_support.to_json(),
            "selected": self.selected,
            "capabilities": self.capabilities.iter().map(descriptor_internal_json).collect::<Vec<_>>(),
        })
    }
}

fn candidates_json(candidates: &[CandidateStatus]) -> Value {
    Value::Array(
        candidates
            .iter()
            .map(CandidateStatus::internal_json)
            .collect(),
    )
}

/// One immutable deep-provider binding selected before client startup.
pub(crate) struct Binding {
    pub provider: Arc<dyn AnalysisProvider>,
    /// Resolved identity (from the profile commitment).
    pub identity: ProviderIdentity,
    /// request, environment or auto-single-candidate.
    pub selection_source: &'static str,
    pub profile: Value,
    /// The provider's capabilities, attributed to its resolved identity.
    pub capabilities: Vec<CapabilityDescriptor>,
}

/// Complete result used for both a bound and an intentionally unbound target.
pub(crate) struct Selection {
    pub requested_provider_id: String,
    pub binding: Option<Arc<Binding>>,
    pub candidates: Vec<CandidateStatus>,
}

/// Immutable operation routes and binding metadata for one target transition.
pub(crate) struct Route {
    pub identity: ProviderIdentity,
    pub capabilities: BTreeMap<String, CapabilityDescriptor>,
    pub profile: Option<Value>,
    pub binding: Option<Arc<Binding>>,
    pub selection: Option<Arc<Selection>>,
}

fn empty_provider_identity() -> ProviderIdentity {
    ProviderIdentity::new("composite:none", COMPOSITE_PROVIDER_NAME, None)
}

/// `compositeProviderIdentity` for a deterministic provider set.
fn composite_identity(identities: &[ProviderIdentity]) -> ProviderIdentity {
    let mut ids = identities
        .iter()
        .map(|identity| identity.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ProviderIdentity::new(
        format!("composite:{}", ids.join("+")),
        COMPOSITE_PROVIDER_NAME,
        None,
    )
}

impl Route {
    /// `selectableRoute` without auxiliary providers: the deep binding (if
    /// any) is wrapped in a composite whose identity names the provider set.
    fn selectable(selection: Option<Arc<Selection>>) -> Self {
        let binding = selection
            .as_ref()
            .and_then(|selection| selection.binding.clone());
        let identity = match &binding {
            Some(binding) => composite_identity(&[binding.provider.identity()]),
            None => empty_provider_identity(),
        };
        let mut capabilities = BTreeMap::new();
        if let Some(binding) = &binding {
            for descriptor in &binding.capabilities {
                capabilities.insert(descriptor.operation.clone(), descriptor.clone());
            }
        }
        Self {
            identity,
            capabilities,
            profile: binding.as_ref().map(|binding| binding.profile.clone()),
            binding,
            selection,
        }
    }

    /// Create the target-bound client for this route without starting the
    /// provider (the child client is created on first non-health execution).
    pub(crate) fn create_client(&self, target: &BinaryTarget, run_id: &str) -> RouteClient {
        let child = self.binding.as_ref().map(|binding| {
            let provider = Arc::clone(&binding.provider);
            let provider_id = provider.identity().id;
            let routes = provider
                .capabilities()
                .into_iter()
                .map(|descriptor| descriptor.operation)
                .collect();
            let profile = (binding.profile["provider"]["id"].as_str()
                == Some(provider_id.as_str()))
            .then(|| binding.profile.clone());
            Child {
                provider,
                provider_id,
                routes,
                target: target.clone(),
                profile,
                run_id: run_id.to_owned(),
                client: Mutex::new(None),
                close_completed: AtomicBool::new(false),
            }
        });
        RouteClient {
            identity: self.identity.clone(),
            child,
            closed: AtomicBool::new(false),
        }
    }
}

struct Child {
    provider: Arc<dyn AnalysisProvider>,
    provider_id: String,
    routes: BTreeSet<String>,
    target: BinaryTarget,
    profile: Option<Value>,
    run_id: String,
    client: Mutex<Option<Arc<dyn AnalysisClient>>>,
    close_completed: AtomicBool,
}

impl Child {
    fn instantiated(&self) -> Option<Arc<dyn AnalysisClient>> {
        lock(&self.client).clone()
    }
}

/// Target-bound client of one route (the original composite or empty client).
pub(crate) struct RouteClient {
    identity: ProviderIdentity,
    child: Option<Child>,
    closed: AtomicBool,
}

fn health_execution(identity: &ProviderIdentity) -> AnalysisExecution {
    AnalysisExecution::new(Value::Null, identity.clone())
}

impl RouteClient {
    /// Execute one operation, starting the child client lazily.
    pub(crate) fn execute(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        options: &ExecutionOptions,
    ) -> Result<AnalysisExecution, AnalysisError> {
        let Some(child) = &self.child else {
            return if operation == "health" {
                Ok(health_execution(&self.identity))
            } else {
                Err(AnalysisError::capability_unavailable(
                    self.identity.id.clone(),
                    operation,
                    "operation is not declared by this provider set",
                ))
            };
        };
        if self.closed.load(Ordering::SeqCst) {
            return Err(client_closed(&self.identity.id, operation));
        }
        if operation == "health" {
            if let Some(client) = child.instantiated() {
                if let Some(health) = client.operation_health() {
                    let state = health["state"].as_str().unwrap_or("unknown");
                    if state != "idle" && state != "busy" {
                        let mut diagnostics = Map::new();
                        diagnostics.insert(
                            "reason".into(),
                            json!(format!("instantiated provider client is {state}")),
                        );
                        return Err(provider_adapter(
                            &child.provider_id,
                            "health",
                            Some(diagnostics),
                        ));
                    }
                }
                client.execute("health", &Map::new(), options)?;
            }
            return Ok(health_execution(&self.identity));
        }
        if !child.routes.contains(operation) {
            return Err(AnalysisError::capability_unavailable(
                self.identity.id.clone(),
                operation,
                "operation is not declared by this provider set",
            ));
        }
        let client = {
            let mut slot = lock(&child.client);
            if self.closed.load(Ordering::SeqCst) {
                return Err(client_closed(&self.identity.id, operation));
            }
            match slot.as_ref() {
                Some(client) => Arc::clone(client),
                None => {
                    let created: Arc<dyn AnalysisClient> =
                        Arc::from(child.provider.create_client(
                            &child.target,
                            child.profile.as_ref(),
                            &child.run_id,
                        )?);
                    *slot = Some(Arc::clone(&created));
                    created
                }
            }
        };
        client.execute(operation, parameters, options)
    }

    /// Execute only against an already-instantiated, ready child client.
    pub(crate) fn execute_if_ready(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        options: &ExecutionOptions,
    ) -> Option<Result<AnalysisExecution, AnalysisError>> {
        let child = self.child.as_ref()?;
        if self.closed.load(Ordering::SeqCst) || !child.routes.contains(operation) {
            return None;
        }
        child
            .instantiated()?
            .execute_if_ready(operation, parameters, options)
    }

    /// Reuse readiness of the composed children (`ready` before any child
    /// exists; children without a readiness probe report `unknown`).
    pub(crate) fn reuse_readiness(&self) -> &'static str {
        if self.child.is_some() && self.closed.load(Ordering::SeqCst) {
            return "blocked";
        }
        match &self.child {
            Some(child) if child.instantiated().is_some() => "unknown",
            _ => "ready",
        }
    }

    /// Operation health of the instantiated child, if any.
    pub(crate) fn operation_health(&self) -> Option<Value> {
        self.child
            .as_ref()
            .and_then(Child::instantiated)
            .and_then(|client| client.operation_health())
    }

    /// Serial-request activity of the instantiated child.
    pub(crate) fn request_activity(&self) -> Vec<Value> {
        self.child
            .as_ref()
            .and_then(Child::instantiated)
            .map(|client| client.request_activity())
            .unwrap_or_default()
    }

    /// Runtime lineage of the instantiated child.
    pub(crate) fn runtime_lineage(&self) -> Vec<Value> {
        self.child
            .as_ref()
            .and_then(Child::instantiated)
            .map(|client| client.runtime_lineage())
            .unwrap_or_default()
    }

    /// Close every instantiated child, retaining failures for retry.
    pub(crate) fn close(&self, retain_document: bool) -> Result<(), AnalysisError> {
        let Some(child) = &self.child else {
            return Ok(());
        };
        self.closed.store(true, Ordering::SeqCst);
        let Some(client) = child.instantiated() else {
            return Ok(());
        };
        if child.close_completed.load(Ordering::SeqCst) {
            return Ok(());
        }
        let closed = close_analysis_client(&child.provider_id, || client.close(retain_document));
        if closed.is_ok() {
            child.close_completed.store(true, Ordering::SeqCst);
        }
        closed
    }
}

fn client_closed(provider_id: &str, operation: &str) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("reason".into(), json!("client_closed"));
    provider_adapter(provider_id, operation, Some(diagnostics))
}

/// Profile resolution truth for one discovered candidate.
struct Evaluation {
    candidate: Arc<dyn AnalysisProvider>,
    status: CandidateStatus,
    profile: Option<Value>,
    profile_error: Option<AnalysisError>,
}

enum InspectionContext<'a> {
    ResolveProfile,
    Discovery {
        operation: &'static str,
        candidates: &'a [CandidateStatus],
    },
}

/// Selection and discovery over the configured deep providers.
pub(crate) struct Router {
    providers: Vec<Arc<dyn AnalysisProvider>>,
    declared_operations: Vec<String>,
    default_selector: Result<String, AnalysisError>,
    initial_route: Arc<Route>,
    selection_cleanup: Mutex<Vec<AnalysisError>>,
    in_flight: AtomicUsize,
    closing: AtomicBool,
}

struct InFlight<'a>(&'a AtomicUsize);
impl<'a> InFlight<'a> {
    fn enter(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Closing<'a>(&'a AtomicBool);
impl Drop for Closing<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn panic_failure(provider_id: &str, operation: &str) -> AnalysisError {
    AnalysisError::provider_adapter(provider_id, operation)
}

impl Router {
    /// Validate provider composition and bind the configured default selector
    /// (`REA_ANALYSIS_PROVIDER`, `auto` when unset).
    ///
    /// # Panics
    /// An invalid composition (invalid or duplicate provider IDs, mismatched
    /// capability provenance, duplicate operations) is a programming error,
    /// exactly as the original constructor's `TypeError`.
    pub(crate) fn new(
        providers: Vec<Arc<dyn AnalysisProvider>>,
        default_selector: Option<&str>,
    ) -> Self {
        let mut ids = BTreeSet::new();
        let mut declared = BTreeSet::new();
        for provider in &providers {
            let identity = provider.identity();
            assert!(
                is_provider_id(&identity.id),
                "Invalid analysis provider ID: {}",
                identity.id
            );
            assert!(
                ids.insert(identity.id.clone()),
                "Duplicate analysis provider ID: {}",
                identity.id
            );
            let mut operations = BTreeSet::new();
            for capability in provider.capabilities() {
                assert!(
                    capability.provider == identity,
                    "Provider {} published mismatched capability provenance for {}",
                    identity.id,
                    capability.operation
                );
                assert!(
                    operations.insert(capability.operation.clone()),
                    "Provider {} declares operation {} more than once",
                    identity.id,
                    capability.operation
                );
                declared.insert(capability.operation);
            }
        }
        let mut providers = providers;
        providers.sort_by_key(|provider| provider.identity().id);
        let default_selector = match default_selector {
            None => Ok("auto".to_owned()),
            Some(selector) if is_provider_selector(selector) => Ok(selector.to_owned()),
            Some(_) => Err(AnalysisError::configuration(
                "Invalid REA environment configuration",
                vec![SettingIssue {
                    setting: "REA_ANALYSIS_PROVIDER".into(),
                    constraint: "Invalid input".into(),
                }],
            )),
        };
        Self {
            providers,
            declared_operations: declared.into_iter().collect(),
            default_selector,
            initial_route: Arc::new(Route::selectable(None)),
            selection_cleanup: Mutex::new(Vec::new()),
            in_flight: AtomicUsize::new(0),
            closing: AtomicBool::new(false),
        }
    }

    /// Target-free routes and discovery metadata.
    pub(crate) fn initial_route(&self) -> Arc<Route> {
        Arc::clone(&self.initial_route)
    }

    /// Configured candidate identities in canonical provider-ID order.
    pub(crate) fn identities(&self) -> Vec<ProviderIdentity> {
        self.providers
            .iter()
            .map(|provider| provider.identity())
            .collect()
    }

    /// The unique deep-operation declarations without probing candidates.
    pub(crate) fn declared_operations(&self) -> &[String] {
        &self.declared_operations
    }

    /// Report retained candidate resources without retrying cleanup.
    pub(crate) fn has_pending_owned_resources(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst) > 0
            || lock(&self.selection_cleanup)
                .iter()
                .any(AnalysisError::is_cleanup_incomplete)
            || self
                .providers
                .iter()
                .any(|provider| provider.has_pending_owned_resources())
    }

    /// Close candidate-owned resources even when no target client was opened.
    pub(crate) fn close_owned_resources(&self) -> Result<(), AnalysisError> {
        self.closing.store(true, Ordering::SeqCst);
        let _closing = Closing(&self.closing);
        let mut failures = Vec::new();
        for provider in &self.providers {
            if let Err(error) = provider.close_owned_resources() {
                failures.push(error);
            }
        }
        {
            let mut retained = lock(&self.selection_cleanup);
            if failures.is_empty() {
                // Every candidate owner confirmed release; the retained
                // selection failures it attributed are resolved.
                retained.clear();
            } else {
                retained.retain(AnalysisError::is_cleanup_incomplete);
                failures.extend(retained.iter().cloned());
            }
        }
        match failures.len() {
            0 => Ok(()),
            1 => Err(failures.remove(0)),
            _ => {
                let mut resources = Vec::new();
                for failure in &failures {
                    for resource in failure.unresolved_resources() {
                        if !resources.contains(&resource) {
                            resources.push(resource);
                        }
                    }
                }
                let reason = failures
                    .iter()
                    .map(AnalysisError::message)
                    .collect::<Vec<_>>()
                    .join("; ");
                let mut diagnostics = Map::new();
                diagnostics.insert("reason".into(), json!(reason));
                Err(provider_cleanup_error(
                    "rea",
                    resources,
                    diagnostics,
                    None,
                    None,
                ))
            }
        }
    }

    fn candidate_status(
        provider: &Arc<dyn AnalysisProvider>,
        target: Option<&BinaryTarget>,
        cancellation: &Cancellation,
        operation: &'static str,
    ) -> Result<CandidateStatus, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let identity = provider.identity();
        let availability = catch_unwind(AssertUnwindSafe(|| {
            provider.inspect_availability(cancellation)
        }))
        .map_err(|_| panic_failure(&identity.id, operation))?;
        let capabilities = provider.capabilities();
        let target_support = match target {
            None => Support::Unknown {
                reason: "No target is open.".into(),
                diagnostics: Map::new(),
            },
            Some(target) => Support::from_provider(
                catch_unwind(AssertUnwindSafe(|| provider.inspect_target_support(target)))
                    .map_err(|_| panic_failure(&identity.id, operation))?,
            ),
        };
        Ok(CandidateStatus {
            provider: identity,
            availability: Availability::from_provider(availability),
            target_support,
            selected: false,
            capabilities,
        })
    }

    fn discover(
        &self,
        target: Option<&BinaryTarget>,
        cancellation: &Cancellation,
        operation: &'static str,
    ) -> Result<Vec<CandidateStatus>, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let results = std::thread::scope(|scope| {
            let handles = self
                .providers
                .iter()
                .map(|provider| {
                    scope.spawn(move || {
                        Self::candidate_status(provider, target, cancellation, operation)
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .zip(&self.providers)
                .map(|(handle, provider)| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(panic_failure(&provider.identity().id, operation)))
                })
                .collect::<Vec<_>>()
        });
        let mut statuses = Vec::new();
        let mut failures = Vec::new();
        for (result, provider) in results.into_iter().zip(&self.providers) {
            match result {
                Ok(status) => statuses.push(status),
                Err(error) => failures.push((provider.identity().id, error)),
            }
        }
        {
            let mut retained = lock(&self.selection_cleanup);
            for (_, error) in &failures {
                if error.is_cleanup_incomplete() {
                    retained.push(error.clone());
                }
            }
        }
        if !failures.is_empty() {
            return Err(provider_inspection_failure(
                &failures,
                InspectionContext::Discovery {
                    operation,
                    candidates: &statuses,
                },
            ));
        }
        Ok(statuses)
    }

    /// Discover candidates for status without resolving profiles or
    /// starting clients.
    pub(crate) fn candidates(
        &self,
        target: Option<&BinaryTarget>,
        cancellation: &Cancellation,
    ) -> Result<Vec<CandidateStatus>, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("binary_session"));
        }
        if self.closing.load(Ordering::SeqCst) {
            return Ok(self
                .providers
                .iter()
                .map(|provider| {
                    let mut diagnostics = Map::new();
                    diagnostics.insert("finalization".into(), json!("in_progress"));
                    CandidateStatus {
                        provider: provider.identity(),
                        availability: Availability::Unknown {
                            reason: "Provider ownership finalization is in progress; readiness has not been re-observed.".into(),
                            diagnostics,
                        },
                        target_support: match target {
                            None => Support::Unknown {
                                reason: "No target is open.".into(),
                                diagnostics: Map::new(),
                            },
                            Some(target) => Support::from_provider(provider.inspect_target_support(target)),
                        },
                        selected: false,
                        capabilities: provider.capabilities(),
                    }
                })
                .collect());
        }
        let _in_flight = InFlight::enter(&self.in_flight);
        let statuses = self.discover(target, cancellation, "binary_session")?;
        if cancellation.reason().is_some() {
            let mut diagnostics = Map::new();
            diagnostics.insert("readiness_candidates".into(), candidates_json(&statuses));
            return Err(AnalysisError::cancelled("binary_session").with_diagnostics(diagnostics));
        }
        Ok(statuses)
    }

    /// Candidate status authoritative for the active or target-free route.
    pub(crate) fn candidate_statuses(
        &self,
        route: &Route,
        cancellation: &Cancellation,
    ) -> Result<Vec<CandidateStatus>, AnalysisError> {
        match &route.selection {
            Some(selection) => Ok(selection.candidates.clone()),
            None => self.candidates(None, cancellation),
        }
    }

    /// Resolve target routes before any provider client is created.
    pub(crate) fn resolve(
        &self,
        target: &BinaryTarget,
        provider_id: Option<&str>,
        cancellation: &Cancellation,
    ) -> Result<Arc<Route>, AnalysisError> {
        let selection = self.select(target, provider_id, cancellation)?;
        Ok(Arc::new(Route::selectable(Some(Arc::new(selection)))))
    }

    /// Produce exact candidate rejections for an intentionally unbound route.
    pub(crate) fn unbound_operation_error(
        &self,
        operation: &str,
        route: &Route,
    ) -> Option<AnalysisError> {
        if route.binding.is_some()
            || !self
                .declared_operations
                .iter()
                .any(|declared| declared == operation)
        {
            return None;
        }
        let selection = route.selection.as_ref()?;
        let reason = if !selection.candidates.is_empty()
            && selection
                .candidates
                .iter()
                .all(|candidate| candidate.target_support.is_unsupported())
        {
            "target_unsupported"
        } else {
            "provider_unavailable"
        };
        Some(selection_error(
            reason,
            &selection.requested_provider_id,
            &selection.candidates,
            operation,
        ))
    }

    /// Select one whole deep-operation family for a parsed target.
    pub(crate) fn select(
        &self,
        target: &BinaryTarget,
        requested: Option<&str>,
        cancellation: &Cancellation,
    ) -> Result<Selection, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("open_binary"));
        }
        let retained = {
            let mut retained = lock(&self.selection_cleanup);
            retained.retain(AnalysisError::is_cleanup_incomplete);
            retained.first().cloned()
        };
        if let Some(retained) = retained {
            // A retry may release retained owners; never stop another live
            // selection merely because a new caller wants admission.
            if self.in_flight.load(Ordering::SeqCst) > 0 {
                return Err(retained);
            }
            self.close_owned_resources()?;
        }
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("open_binary"));
        }
        let selected = {
            let _in_flight = InFlight::enter(&self.in_flight);
            self.select_target(target, requested, cancellation)
        };
        match selected {
            Ok(selection) if cancellation.reason().is_some() => {
                drop(selection);
                Err(AnalysisError::cancelled("open_binary"))
            }
            Ok(selection) => Ok(selection),
            Err(error) => {
                if error.is_cleanup_incomplete() {
                    lock(&self.selection_cleanup).push(error.clone());
                }
                Err(error)
            }
        }
    }

    fn select_target(
        &self,
        target: &BinaryTarget,
        requested: Option<&str>,
        cancellation: &Cancellation,
    ) -> Result<Selection, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("open_binary"));
        }
        let baseline = self.discover(Some(target), cancellation, "open_binary")?;
        if let Some(requested) = requested
            && !is_provider_selector(requested)
        {
            return Err(selection_error(
                "invalid_options",
                requested,
                &baseline,
                "open_binary",
            ));
        }
        let selector = match requested {
            Some(requested) => requested.to_owned(),
            None => self.default_selector.clone()?,
        };
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("open_binary"));
        }
        if requested.is_none()
            && self.provider(&selector).is_some()
            && !baseline.is_empty()
            && baseline
                .iter()
                .all(|candidate| candidate.target_support.is_unsupported())
        {
            return Ok(Selection {
                requested_provider_id: selector,
                binding: None,
                candidates: baseline,
            });
        }
        if selector != "auto" {
            let source = if requested.is_none() {
                "environment"
            } else {
                "request"
            };
            return self.select_concrete(target, baseline, &selector, source, cancellation);
        }
        self.select_automatically(target, baseline, cancellation)
    }

    fn provider(&self, id: &str) -> Option<&Arc<dyn AnalysisProvider>> {
        self.providers
            .iter()
            .find(|provider| provider.identity().id == id)
    }

    fn select_concrete(
        &self,
        target: &BinaryTarget,
        baseline: Vec<CandidateStatus>,
        provider_id: &str,
        source: &'static str,
        cancellation: &Cancellation,
    ) -> Result<Selection, AnalysisError> {
        let Some(provider) = self.provider(provider_id) else {
            return Err(selection_error(
                "unknown_provider",
                provider_id,
                &baseline,
                "open_binary",
            ));
        };
        let initial = baseline
            .iter()
            .find(|candidate| candidate.provider.id == provider_id)
            .cloned()
            .expect("Registered provider is absent from discovery output");
        if !matches!(initial.target_support, Support::Supported { .. }) {
            return Err(selection_error(
                "target_unsupported",
                provider_id,
                &baseline,
                "open_binary",
            ));
        }
        if matches!(initial.availability, Availability::Unavailable { .. }) {
            return Err(selection_error(
                "provider_unavailable",
                provider_id,
                &baseline,
                "open_binary",
            ));
        }
        let evaluated = evaluate(provider, initial, target, cancellation)?;
        if let Some(error) = evaluated.profile_error {
            return Err(error);
        }
        let statuses = replace_candidate(&baseline, &evaluated.status);
        let Some(profile) = evaluated.profile.clone() else {
            return Err(selection_error(
                "provider_unavailable",
                provider_id,
                &statuses,
                "open_binary",
            ));
        };
        Ok(selected_result(
            provider_id,
            source,
            evaluated.candidate,
            evaluated.status,
            profile,
            &statuses,
        ))
    }

    fn select_automatically(
        &self,
        target: &BinaryTarget,
        baseline: Vec<CandidateStatus>,
        cancellation: &Cancellation,
    ) -> Result<Selection, AnalysisError> {
        let results = std::thread::scope(|scope| {
            let handles = self
                .providers
                .iter()
                .map(|provider| {
                    let status = baseline
                        .iter()
                        .find(|candidate| candidate.provider.id == provider.identity().id)
                        .cloned()
                        .expect("Registered provider is absent from discovery output");
                    scope.spawn(move || {
                        if matches!(status.availability, Availability::Available { .. })
                            && matches!(status.target_support, Support::Supported { .. })
                        {
                            evaluate(provider, status, target, cancellation)
                        } else {
                            Ok(Evaluation {
                                candidate: Arc::clone(provider),
                                status,
                                profile: None,
                                profile_error: None,
                            })
                        }
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(AnalysisError::cancelled("open_binary")))
                })
                .collect::<Vec<_>>()
        });
        let mut failures = Vec::new();
        let mut any_cancelled = false;
        for (result, provider) in results.iter().zip(&self.providers) {
            match result {
                Ok(evaluation) => {
                    if let Some(error) = &evaluation.profile_error {
                        failures.push((provider.identity().id, error.clone()));
                    }
                }
                Err(error) => {
                    any_cancelled = true;
                    failures.push((provider.identity().id, error.clone()));
                }
            }
        }
        if any_cancelled
            || failures
                .iter()
                .any(|(_, error)| error.is_cleanup_incomplete())
            || cancellation.reason().is_some()
        {
            return Err(provider_inspection_failure(
                &failures,
                InspectionContext::ResolveProfile,
            ));
        }
        let evaluations = results.into_iter().flatten().collect::<Vec<_>>();
        let statuses = evaluations
            .iter()
            .map(|evaluation| evaluation.status.clone())
            .collect::<Vec<_>>();
        let mut usable = evaluations
            .into_iter()
            .filter(|evaluation| evaluation.profile.is_some())
            .collect::<Vec<_>>();
        if usable.is_empty() {
            return Ok(Selection {
                requested_provider_id: "auto".into(),
                binding: None,
                candidates: statuses,
            });
        }
        if usable.len() > 1 {
            return Err(selection_error(
                "ambiguous",
                "auto",
                &statuses,
                "open_binary",
            ));
        }
        let selected = usable.remove(0);
        let profile = selected.profile.clone().unwrap_or(Value::Null);
        Ok(selected_result(
            "auto",
            "auto-single-candidate",
            selected.candidate,
            selected.status,
            profile,
            &statuses,
        ))
    }
}

/// `evaluateAnalysisProviderCandidate`: resolve and validate one provider
/// profile without starting its client.
fn evaluate(
    provider: &Arc<dyn AnalysisProvider>,
    status: CandidateStatus,
    target: &BinaryTarget,
    cancellation: &Cancellation,
) -> Result<Evaluation, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled("open_binary"));
    }
    let resolved = catch_unwind(AssertUnwindSafe(|| {
        provider.resolve_analysis_profile(target, cancellation)
    }))
    .unwrap_or_else(|_| {
        let mut diagnostics = Map::new();
        diagnostics.insert("reason".into(), json!("Provider profile resolution threw"));
        Err(provider_adapter(
            &status.provider.id,
            "resolve_analysis_profile",
            Some(diagnostics),
        ))
    });
    let profile = match resolved {
        Err(error) if is_cancelled(&error) => return Err(error),
        Err(error) => {
            let rejected = match &error.kind {
                ErrorKind::UnsupportedTarget { path, reason, .. } => {
                    let mut diagnostics = Map::new();
                    diagnostics.insert("path".into(), json!(path));
                    diagnostics.insert("error_tag".into(), json!(error.tag()));
                    CandidateStatus {
                        target_support: Support::Unsupported {
                            code: "target_format_unsupported".into(),
                            reason: reason.clone(),
                            diagnostics,
                        },
                        ..status
                    }
                }
                _ => {
                    let mut diagnostics = Map::new();
                    diagnostics.insert("error_tag".into(), json!(error.tag()));
                    rejected_profile(status, &error.message(), diagnostics)
                }
            };
            return Ok(Evaluation {
                candidate: Arc::clone(provider),
                status: rejected,
                profile: None,
                profile_error: Some(error),
            });
        }
        Ok(profile) => profile,
    };
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled("open_binary"));
    }
    let rejected = |status: CandidateStatus, reason: &str| Evaluation {
        candidate: Arc::clone(provider),
        status: rejected_profile(status, reason, Map::new()),
        profile: None,
        profile_error: None,
    };
    let Some(profile) = profile else {
        return Ok(rejected(
            status,
            "Provider version or analysis profile could not be resolved",
        ));
    };
    let Some(profile) = parse_analysis_profile(&profile) else {
        return Ok(rejected(
            status,
            "Provider returned an invalid analysis profile",
        ));
    };
    let identity = provider.identity();
    let committed = &profile["provider"];
    if committed["id"].as_str() != Some(identity.id.as_str())
        || committed["name"].as_str() != Some(identity.name.as_str())
        || identity
            .version
            .as_deref()
            .is_some_and(|version| committed["version"].as_str() != Some(version))
    {
        return Ok(rejected(
            status,
            "Resolved analysis profile has mismatched provider identity",
        ));
    }
    Ok(Evaluation {
        candidate: Arc::clone(provider),
        status,
        profile: Some(profile),
        profile_error: None,
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn non_empty(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.is_empty())
}

/// `analysisProfileSchema.parse`: strict commitment whose digest equals the
/// RFC 8785 digest of its unsigned projection; keys in schema order.
pub(crate) fn parse_analysis_profile(value: &Value) -> Option<Value> {
    let object = value.as_object()?;
    if object.len() != 3 {
        return None;
    }
    let provider = object.get("provider")?.as_object()?;
    if provider.len() != 3 {
        return None;
    }
    let id = non_empty(provider.get("id")?)?;
    let name = non_empty(provider.get("name")?)?;
    let version = non_empty(provider.get("version")?)?;
    let parameters = object.get("parameters")?.as_object()?;
    let digest = object.get("digest")?.as_str()?;
    if !is_sha256(digest) {
        return None;
    }
    let unsigned = json!({
        "provider": { "id": id, "name": name, "version": version },
        "parameters": parameters,
    });
    if rea_core::canonical_json::digest(&unsigned).ok()? != digest {
        return None;
    }
    Some(json!({
        "provider": { "id": id, "name": name, "version": version },
        "parameters": parameters,
        "digest": digest,
    }))
}

fn rejected_profile(
    status: CandidateStatus,
    reason: &str,
    diagnostics: Map<String, Value>,
) -> CandidateStatus {
    let mut merged = status.availability.diagnostics().clone();
    for (key, value) in diagnostics {
        merged.insert(key, value);
    }
    CandidateStatus {
        availability: Availability::Unavailable {
            code: "version_unresolved".into(),
            reason: reason.to_owned(),
            diagnostics: merged,
        },
        ..status
    }
}

fn replace_candidate(
    statuses: &[CandidateStatus],
    replacement: &CandidateStatus,
) -> Vec<CandidateStatus> {
    statuses
        .iter()
        .map(|status| {
            if status.provider.id == replacement.provider.id {
                replacement.clone()
            } else {
                status.clone()
            }
        })
        .collect()
}

fn selected_result(
    requested_provider_id: &str,
    source: &'static str,
    candidate: Arc<dyn AnalysisProvider>,
    status: CandidateStatus,
    profile: Value,
    statuses: &[CandidateStatus],
) -> Selection {
    let committed = &profile["provider"];
    let identity = ProviderIdentity::new(
        committed["id"].as_str().unwrap_or_default(),
        committed["name"].as_str().unwrap_or_default(),
        committed["version"].as_str().map(str::to_owned),
    );
    let capabilities = status
        .capabilities
        .iter()
        .map(|capability| CapabilityDescriptor {
            provider: identity.clone(),
            ..capability.clone()
        })
        .collect::<Vec<_>>();
    let selected_status = CandidateStatus {
        provider: identity.clone(),
        selected: true,
        capabilities: capabilities.clone(),
        ..status
    };
    Selection {
        requested_provider_id: requested_provider_id.to_owned(),
        binding: Some(Arc::new(Binding {
            provider: candidate,
            identity,
            selection_source: source,
            profile,
            capabilities,
        })),
        candidates: replace_candidate(statuses, &selected_status),
    }
}

fn candidate_rejections(candidates: &[CandidateStatus]) -> Vec<SelectionRejection> {
    let mut rejections = Vec::new();
    for candidate in candidates {
        if let Availability::Unavailable {
            code,
            reason,
            diagnostics,
        } = &candidate.availability
        {
            rejections.push(SelectionRejection {
                provider_id: candidate.provider.id.clone(),
                code: code.clone(),
                reason: reason.clone(),
                diagnostics: Value::Object(diagnostics.clone()),
            });
        }
        if let Support::Unsupported {
            code,
            reason,
            diagnostics,
        } = &candidate.target_support
        {
            rejections.push(SelectionRejection {
                provider_id: candidate.provider.id.clone(),
                code: code.clone(),
                reason: reason.clone(),
                diagnostics: Value::Object(diagnostics.clone()),
            });
        }
    }
    rejections
}

/// `selectionError(reason, requestedProviderId, candidates, operation)`.
fn selection_error(
    reason: &str,
    requested_provider_id: &str,
    candidates: &[CandidateStatus],
    operation: &str,
) -> AnalysisError {
    provider_selection(
        operation,
        reason,
        requested_provider_id,
        candidates
            .iter()
            .map(|candidate| candidate.provider.id.clone())
            .collect(),
        candidate_rejections(candidates),
    )
}

/// `providerInspectionFailure`: every terminal child remains attributed;
/// cleanup is conjunctive across owners.
fn provider_inspection_failure(
    failures: &[(String, AnalysisError)],
    context: InspectionContext<'_>,
) -> AnalysisError {
    let operation = match &context {
        InspectionContext::ResolveProfile => "open_binary",
        InspectionContext::Discovery { operation, .. } => operation,
    };
    let Some((_, primary)) = failures
        .iter()
        .find(|(_, error)| !is_cancelled(error))
        .or_else(|| failures.first())
    else {
        return AnalysisError::cancelled(operation);
    };
    let single = failures.len() == 1
        && match &context {
            InspectionContext::ResolveProfile => true,
            InspectionContext::Discovery { candidates, .. } => candidates.is_empty(),
        };
    if single {
        return primary.clone();
    }
    let cleanup_failures = failures
        .iter()
        .filter(|(_, error)| error.is_cleanup_incomplete())
        .map(|(_, error)| error)
        .collect::<Vec<_>>();
    let mut diagnostics = Map::new();
    let errors = failures
        .iter()
        .map(|(provider_id, error)| json!({ "provider_id": provider_id, "error": error.project() }))
        .collect::<Vec<_>>();
    match &context {
        InspectionContext::ResolveProfile => {
            diagnostics.insert("profile_errors".into(), Value::Array(errors));
        }
        InspectionContext::Discovery { candidates, .. } => {
            diagnostics.insert("readiness_errors".into(), Value::Array(errors));
            diagnostics.insert("readiness_candidates".into(), candidates_json(candidates));
        }
    }
    let mut failure = if is_cancelled(primary) {
        AnalysisError::cancelled(operation)
    } else {
        let adapter_operation = match &context {
            InspectionContext::ResolveProfile => "resolve_analysis_profile",
            InspectionContext::Discovery { operation, .. } => operation,
        };
        AnalysisError::from(ErrorKind::ProviderAdapter {
            provider_id: "rea".into(),
            operation: adapter_operation.to_owned(),
            user_message: primary.project()["message"].as_str().map(str::to_owned),
            remediation_action: None,
        })
    }
    .with_diagnostics(diagnostics);
    failure.captured_output = primary.captured_output.clone();
    failure.partial_observation = primary.partial_observation.clone();
    if !cleanup_failures.is_empty() {
        let mut resources = Vec::new();
        for error in &cleanup_failures {
            for resource in error.unresolved_resources() {
                if !resources.contains(&resource) {
                    resources.push(resource);
                }
            }
        }
        failure.cleanup_primary = Some(Box::new(primary.clone()));
        failure.cleanup = Some(CleanupObservation {
            reason: cleanup_failures
                .iter()
                .map(|error| error.message())
                .collect::<Vec<_>>()
                .join("; "),
            resources,
        });
    }
    failure
}
