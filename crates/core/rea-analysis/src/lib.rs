//! Deep-analysis provider contract shared by the binary session and providers.
//!
//! Compatibility owner: `src/application/AnalysisProvider.ts` and
//! `src/domain/binaryTargetTypes.ts`. The binary session owns selection,
//! admission and lifecycle; each provider crate implements these traits and
//! owns its engine process, protocol and cleanup.
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::SubjectTarget;
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// Provider identity recorded in Evidence (`version` may be unresolved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderIdentity {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
}

impl ProviderIdentity {
    pub fn new(id: impl Into<String>, name: impl Into<String>, version: Option<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({ "id": self.id, "name": self.name, "version": self.version })
    }

    pub fn evidence_provider(&self) -> rea_core::evidence::envelope::EvidenceProvider {
        rea_core::evidence::envelope::EvidenceProvider::new(
            self.id.clone(),
            self.name.clone(),
            self.version.clone(),
        )
    }
}

/// Canonical local target identity and provider-neutral classification.
///
/// `kind`/`format`/`architecture` follow the original BinaryTarget variants;
/// variant-specific facts (ELF family metadata, universal slice, PE role,
/// raw entry point, CodeView, bundle Info.plist) live in `metadata` using the
/// original camelCase field names.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryTarget {
    /// Analyzed file path (bundle executables resolve to their binary).
    pub path: String,
    /// Caller-selected path when it differs (for example an `.app` bundle).
    pub source_path: Option<String>,
    pub sha256: String,
    /// executable, database, archive or artifact.
    pub kind: String,
    /// mach-o, mach-o-universal, elf, pe, dos-mz, dos-com, raw-binary,
    /// analysis-database, zip/apk/ipa/..., asar, dmg, pkg, plist, nib, ...
    pub format: String,
    pub architecture: Option<String>,
    pub available_architectures: Vec<String>,
    pub metadata: Map<String, Value>,
}

impl BinaryTarget {
    /// Evidence subject identity for this target.
    pub fn subject(&self) -> SubjectTarget {
        SubjectTarget {
            path: self.path.clone(),
            sha256: self.sha256.clone(),
            format: self.format.clone(),
            architecture: self.architecture.clone(),
        }
    }

    /// Evidence subject JSON (`name`, `digest`, `local_path`, `format`, `architecture`).
    pub fn subject_json(&self) -> Value {
        let name = std::path::Path::new(&self.path)
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("artifact");
        json!({
            "name": name,
            "digest": { "sha256": self.sha256 },
            "local_path": self.path,
            "format": self.format,
            "architecture": self.architecture,
        })
    }

    /// The original camelCase BinaryTarget projection.
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("path".into(), json!(self.path));
        if let Some(source) = &self.source_path {
            object.insert("sourcePath".into(), json!(source));
        }
        object.insert("sha256".into(), json!(self.sha256));
        object.insert("kind".into(), json!(self.kind));
        object.insert("format".into(), json!(self.format));
        if let Some(architecture) = &self.architecture {
            object.insert("architecture".into(), json!(architecture));
            object.insert(
                "availableArchitectures".into(),
                json!(self.available_architectures),
            );
        }
        for (key, value) in &self.metadata {
            object.insert(key.clone(), value.clone());
        }
        Value::Object(object)
    }
}

/// Atomic successful provider observation with exact producing provenance.
#[derive(Clone, Debug)]
pub struct AnalysisExecution {
    pub result: Value,
    /// Provider representation distinct from `result`, else None (null).
    pub raw_result: Option<Value>,
    pub provider: ProviderIdentity,
    pub analysis_profile: Option<Value>,
    pub limitations: Vec<String>,
    pub relationship_coverage: Option<Value>,
    /// Whether an `xrefs` read was capped (never part of Evidence).
    pub references_truncated: Option<bool>,
    pub locations: Vec<Value>,
    pub subject: Option<SubjectTarget>,
}

impl AnalysisExecution {
    pub fn new(result: Value, provider: ProviderIdentity) -> Self {
        Self {
            result,
            raw_result: None,
            provider,
            analysis_profile: None,
            limitations: Vec::new(),
            relationship_coverage: None,
            references_truncated: None,
            locations: Vec::new(),
            subject: None,
        }
    }

    /// Caller-visible Evidence, exactly as `createAnalysisExecutionEvidence`.
    pub fn evidence(
        &self,
        operation: &str,
        parameters: Value,
        confidence: &str,
    ) -> Result<rea_core::evidence::envelope::Evidence, AnalysisError> {
        let mut observation = rea_core::evidence::envelope::Observation::new(
            operation,
            parameters,
            self.result.clone(),
        )
        .confidence(confidence)
        .limitations(self.limitations.clone())
        .locations(self.locations.clone());
        if let Some(raw) = &self.raw_result {
            observation = observation.raw(raw.clone());
        }
        if let Some(profile) = &self.analysis_profile {
            observation = observation.profile(profile.clone());
        }
        if let Some(coverage) = &self.relationship_coverage {
            observation = observation.coverage(coverage.clone());
        }
        rea_core::evidence::envelope::Evidence::create(
            self.subject.as_ref(),
            &self.provider.evidence_provider(),
            observation,
        )
        .map_err(|error| AnalysisError::output(operation, error.to_string()))
    }
}

/// Progress callback (`phase`, `message`); providers may ignore it.
pub type ProgressFn = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Per-call execution controls.
#[derive(Clone)]
pub struct ExecutionOptions {
    pub cancellation: Cancellation,
    pub progress: Option<ProgressFn>,
    /// Selector came from provider output rather than the caller.
    pub selector_from_provider: bool,
}

impl ExecutionOptions {
    pub fn new(cancellation: Cancellation) -> Self {
        Self {
            cancellation,
            progress: None,
            selector_from_provider: false,
        }
    }

    pub fn report(&self, phase: &str, message: &str) {
        if let Some(progress) = &self.progress {
            progress(phase, message);
        }
    }
}

/// Side effects declared by one provider capability.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityEffects {
    pub mutates_artifact: bool,
    pub launches_process: bool,
    pub may_show_ui: bool,
    pub may_access_network: bool,
    pub may_write_filesystem: bool,
    pub changes_permissions: bool,
    pub requires_root: bool,
}

/// Availability and effects of one provider operation.
#[derive(Clone, Debug)]
pub struct CapabilityDescriptor {
    pub operation: String,
    pub available: bool,
    /// Present when unavailable.
    pub reason: Option<String>,
    pub availability_code: Option<String>,
    /// `snapshot` (replayable) or `live`.
    pub cache_policy: Option<String>,
    pub provider: ProviderIdentity,
    pub effects: CapabilityEffects,
    pub limitations: Vec<String>,
}

/// Bounded host observation made without starting an analysis process.
#[derive(Clone, Debug)]
pub enum ProviderAvailability {
    Available {
        diagnostics: Map<String, Value>,
    },
    Unavailable {
        /// One of the original ProviderRejectionCode values.
        code: String,
        reason: String,
        diagnostics: Map<String, Value>,
    },
}

/// Provider-owned target support before profile resolution.
#[derive(Clone, Debug)]
pub enum TargetSupport {
    Supported {
        diagnostics: Map<String, Value>,
    },
    Unsupported {
        /// target_kind_unsupported, target_format_unsupported,
        /// architecture_unsupported, target_role_unsupported or
        /// managed_target_unsupported.
        code: String,
        reason: String,
        diagnostics: Map<String, Value>,
    },
}

/// Provider session bound to exactly one parsed artifact.
pub trait AnalysisClient: Send + Sync {
    /// Whether this client's route declares the operation available.
    fn supports_operation(&self, operation: &str) -> bool;
    /// Execute one provider operation with validated public parameters.
    fn execute(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        options: &ExecutionOptions,
    ) -> Result<AnalysisExecution, AnalysisError>;
    /// Execute only if no provider start or load is required.
    fn execute_if_ready(
        &self,
        _operation: &str,
        _parameters: &Map<String, Value>,
        _options: &ExecutionOptions,
    ) -> Option<Result<AnalysisExecution, AnalysisError>> {
        None
    }
    /// Current provider bridge health (`state`, `stage`, `retry_action`, ...).
    fn operation_health(&self) -> Option<Value> {
        None
    }
    /// Current serial-request activity snapshots.
    fn request_activity(&self) -> Vec<Value> {
        Vec::new()
    }
    /// Token-verified runtime lineage snapshots of started engine processes.
    fn runtime_lineage(&self) -> Vec<Value> {
        Vec::new()
    }
    /// Close owned resources, retaining failed cleanup for a later retry.
    fn close(&self, retain_document: bool) -> Result<(), AnalysisError>;
}

/// Factory and capability declaration for one deep-analysis provider.
pub trait AnalysisProvider: Send + Sync {
    fn identity(&self) -> ProviderIdentity;
    fn capabilities(&self) -> Vec<CapabilityDescriptor>;
    /// Observe prerequisites without starting analysis.
    fn inspect_availability(&self, cancellation: &Cancellation) -> ProviderAvailability;
    fn inspect_target_support(&self, target: &BinaryTarget) -> TargetSupport;
    /// Resolve the analysis profile before startup; None means unresolved.
    fn resolve_analysis_profile(
        &self,
        target: &BinaryTarget,
        cancellation: &Cancellation,
    ) -> Result<Option<Value>, AnalysisError>;
    /// Create a client for one target (does not need to start the engine yet).
    fn create_client(
        &self,
        target: &BinaryTarget,
        profile: Option<&Value>,
        run_id: &str,
    ) -> Result<Box<dyn AnalysisClient>, AnalysisError>;
    /// Whether candidate-level resources (independent of clients) remain owned.
    fn has_pending_owned_resources(&self) -> bool {
        false
    }
    /// Release candidate-level resources.
    fn close_owned_resources(&self) -> Result<(), AnalysisError> {
        Ok(())
    }
}

/// Create a validated analysis profile commitment (RFC 8785 digest).
///
/// # Errors
/// Fails only if the parameters cannot be canonicalized.
pub fn create_analysis_profile(
    provider: &ProviderIdentity,
    parameters: Value,
) -> Result<Value, AnalysisError> {
    let unsigned = json!({
        "provider": { "id": provider.id, "name": provider.name, "version": provider.version },
        "parameters": parameters,
    });
    let digest = rea_core::canonical_json::digest(&unsigned)
        .map_err(|error| AnalysisError::output("analysis_profile", error.to_string()))?;
    let mut profile = unsigned;
    if let Some(object) = profile.as_object_mut() {
        object.insert("digest".into(), json!(digest));
    }
    Ok(profile)
}
