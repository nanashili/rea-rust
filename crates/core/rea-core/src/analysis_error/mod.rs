//! Typed analysis-failure algebra and its caller projection.
//!
//! Compatibility owners: `src/domain/analysisErrorBase.ts`,
//! `src/domain/analysisErrorCore.ts`, `src/domain/analysisErrorPresentation.ts`
//! and `src/domain/analysisErrorProjection.ts`. Every migrated workflow returns
//! these typed failures; adapters never invent codes, categories or messages.
#![allow(missing_docs)]
pub mod cleanup;
use serde_json::{Map, Value, json};

/// Retained command output associated with a typed failure.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CapturedOutput {
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub stdout_bytes: Option<u64>,
    pub stderr_bytes: Option<u64>,
    /// `Some(None)` reports an explicit null exit code.
    pub exit_code: Option<Option<i64>>,
    /// `Some(None)` reports an explicit null signal.
    pub signal: Option<Option<String>>,
}

impl CapturedOutput {
    fn project(&self) -> Value {
        let mut object = Map::new();
        object.insert("stdout".into(), Value::String(self.stdout.clone()));
        object.insert("stderr".into(), Value::String(self.stderr.clone()));
        object.insert("truncated".into(), Value::Bool(self.truncated));
        if let Some(bytes) = self.stdout_bytes {
            object.insert("stdout_bytes".into(), json!(bytes));
        }
        if let Some(bytes) = self.stderr_bytes {
            object.insert("stderr_bytes".into(), json!(bytes));
        }
        if let Some(code) = &self.exit_code {
            object.insert("exit_code".into(), json!(code));
        }
        if let Some(signal) = &self.signal {
            object.insert("signal".into(), json!(signal));
        }
        Value::Object(object)
    }
}

/// Cleanup uncertainty attached to the original typed failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupObservation {
    pub reason: String,
    pub resources: Vec<String>,
}

/// One rejected caller argument with correction metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct InputIssue {
    pub path: Vec<Value>,
    /// One of unknown_argument, missing_argument, invalid_type, out_of_range,
    /// invalid_value or invalid_format.
    pub reason: &'static str,
    pub message: Option<String>,
    pub expected: Option<Value>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
}

impl InputIssue {
    /// Issue at a named argument path.
    pub fn new(path: &[&str], reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            path: path
                .iter()
                .map(|part| Value::String((*part).into()))
                .collect(),
            reason,
            message: Some(message.into()),
            expected: None,
            minimum: None,
            maximum: None,
        }
    }

    fn project(&self) -> Value {
        let mut object = Map::new();
        object.insert("path".into(), Value::Array(self.path.clone()));
        object.insert("reason".into(), Value::String(self.reason.into()));
        if let Some(message) = &self.message {
            object.insert("message".into(), Value::String(message.clone()));
        }
        if let Some(expected) = &self.expected {
            object.insert("expected".into(), expected.clone());
        }
        if let Some(minimum) = self.minimum {
            object.insert("minimum".into(), number(minimum));
        }
        if let Some(maximum) = self.maximum {
            object.insert("maximum".into(), number(maximum));
        }
        Value::Object(object)
    }
}

fn number(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        json!(value as i64)
    } else {
        json!(value)
    }
}

/// One rejected provider candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectionRejection {
    pub provider_id: String,
    pub code: String,
    pub reason: String,
    pub diagnostics: Value,
}

/// One rejected configuration setting; values are never retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingIssue {
    pub setting: String,
    pub constraint: String,
}

/// Declared-integrity facts for an artifact entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactDetails {
    pub logical_path: String,
    pub declared_sha256: Option<String>,
    pub calculated_sha256: Option<String>,
    pub unpacked: bool,
}

/// Published Evidence file receipt retained when staging cleanup failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedFile {
    pub path: String,
    pub bytes: u64,
}

/// Exhaustive set of expected analysis failures.
#[derive(Clone, Debug, PartialEq)]
pub enum ErrorKind {
    Protocol {
        message: String,
    },
    Input {
        operation: String,
        issues: Vec<InputIssue>,
        user_message: Option<String>,
    },
    AccessDenied {
        operation: String,
        path: String,
        system_code: String,
    },
    ArtifactChanged {
        operation: String,
        path: String,
        reason: String,
    },
    Output {
        operation: String,
        reason: String,
        user_message: Option<String>,
        remediation_action: Option<String>,
    },
    CapabilityUnavailable {
        provider_id: String,
        operation: String,
        reason: String,
        user_message: Option<String>,
        remediation_action: Option<String>,
        retryable: bool,
    },
    UnsupportedTarget {
        operation: String,
        path: String,
        reason: String,
        remediation_action: Option<String>,
    },
    Cancelled {
        operation: String,
    },
    Timeout {
        operation: String,
        timeout_ms: u64,
        user_message: Option<String>,
        remediation_action: Option<String>,
    },
    ResourceConstraint {
        operation: String,
        /// memory, cpu, file-size, transport or capacity.
        resource: String,
        reason: String,
        reported_limits: Option<Value>,
        remediation_action: Option<String>,
        retryable: Option<bool>,
    },
    ProviderSelection {
        operation: String,
        /// unknown_provider, provider_unavailable, target_unsupported, ambiguous, invalid_options.
        reason: String,
        requested_provider_id: String,
        candidate_ids: Vec<String>,
        rejections: Vec<SelectionRejection>,
        user_message: Option<String>,
    },
    ProviderAdapter {
        provider_id: String,
        operation: String,
        user_message: Option<String>,
        remediation_action: Option<String>,
    },
    BrowserObservation {
        operation: String,
        reason: String,
        detail: Option<String>,
        /// The original cause was itself a cancellation.
        cause_cancelled: bool,
        /// Reason of the first aggregated primary failure, when known.
        primary_reason: Option<String>,
    },
    ArtifactOperation {
        operation: String,
        /// cancelled, format, integrity, limit, path, unavailable or io.
        reason: String,
        artifact_details: Option<ArtifactDetails>,
        detail: Option<String>,
    },
    ProcessCapture {
        message: String,
        user_message: Option<String>,
        cancelled: bool,
        /// capture_failed, cancelled, cleanup_incomplete, ...
        reason: String,
        execution_failure: Option<String>,
        cleanup_report: Option<Value>,
    },
    EvidenceIntegrity {
        message: String,
        user_message: Option<String>,
    },
    SnapshotMismatch {
        message: String,
    },
    EvidenceReference {
        evidence_id: String,
        reason: String,
        expected: String,
        actual: Option<String>,
    },
    EvidenceFile {
        /// read or write.
        operation: String,
        /// not-file, exists, wrong-kind, invalid-json, missing or io.
        reason: String,
        path: Option<String>,
        published: Option<PublishedFile>,
        user_message: Option<String>,
    },
    UnknownRegistry {
        reason: String,
    },
    HopperTimeout {
        timeout_ms: u64,
        operation: Option<String>,
        request_id: Option<u64>,
        provider_state: String,
        stage: String,
        launcher_outcome: Option<Value>,
    },
    HopperCancelled,
    HopperProtocol {
        message: String,
    },
    HopperRemote {
        code: i64,
        safe_message: String,
        diagnostic_type: String,
        operation: Option<String>,
        request_id: Option<u64>,
    },
    HopperProcess {
        exit_code: Option<i64>,
        failure_code: Option<String>,
        user_message: Option<String>,
        provider_state: String,
        stage: String,
        diagnostic: Option<Value>,
        operation: Option<String>,
        request_id: Option<u64>,
        launcher_failure: Option<Value>,
        launcher_signal: Option<String>,
    },
    HopperStart {
        user_message: Option<String>,
        owner_run_id: Option<String>,
        launcher_failure: Option<Value>,
        launch_rejection: Option<Value>,
    },
    Configuration {
        message: String,
        settings: Vec<SettingIssue>,
    },
    NoBinaryOpen,
    BinaryTarget {
        path: String,
        reason: String,
        constraint: Option<String>,
        system_code: Option<String>,
    },
    /// A failure already projected by its producing owner (exact wire shape).
    Projected {
        projection: Value,
    },
}

/// One expected failure with its provider-neutral context.
#[derive(Clone, Debug, PartialEq)]
pub struct AnalysisError {
    pub kind: ErrorKind,
    /// Producer-owned caller-safe facts retained through projection.
    pub diagnostics: Option<Map<String, Value>>,
    pub captured_output: Option<CapturedOutput>,
    pub cleanup: Option<CleanupObservation>,
    /// Explicit live cleanup status; defaults to `cleanup.is_some()`.
    pub cleanup_incomplete: Option<bool>,
    /// Current unresolved resources when not derived from `cleanup`.
    pub cleanup_resources: Option<Vec<String>>,
    pub partial_observation: Option<Value>,
    /// Typed primary retained when a later lifecycle failure composes this error.
    pub cleanup_primary: Option<Box<AnalysisError>>,
    /// Later typed failures retained without replacing the primary.
    pub secondary_failures: Vec<AnalysisError>,
}

impl From<ErrorKind> for AnalysisError {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            diagnostics: None,
            captured_output: None,
            cleanup: None,
            cleanup_incomplete: None,
            cleanup_resources: None,
            partial_observation: None,
            cleanup_primary: None,
            secondary_failures: Vec::new(),
        }
    }
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for AnalysisError {}

/// Common constructors.
impl AnalysisError {
    pub fn input(operation: impl Into<String>, issues: Vec<InputIssue>) -> Self {
        ErrorKind::Input {
            operation: operation.into(),
            issues,
            user_message: None,
        }
        .into()
    }
    pub fn input_message(
        operation: impl Into<String>,
        user_message: impl Into<String>,
        issues: Vec<InputIssue>,
    ) -> Self {
        ErrorKind::Input {
            operation: operation.into(),
            issues,
            user_message: Some(user_message.into()),
        }
        .into()
    }
    pub fn cancelled(operation: impl Into<String>) -> Self {
        ErrorKind::Cancelled {
            operation: operation.into(),
        }
        .into()
    }
    pub fn timeout(operation: impl Into<String>, timeout_ms: u64) -> Self {
        ErrorKind::Timeout {
            operation: operation.into(),
            timeout_ms,
            user_message: None,
            remediation_action: None,
        }
        .into()
    }
    pub fn output(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        ErrorKind::Output {
            operation: operation.into(),
            reason: reason.into(),
            user_message: None,
            remediation_action: None,
        }
        .into()
    }
    pub fn protocol(message: impl Into<String>) -> Self {
        ErrorKind::Protocol {
            message: message.into(),
        }
        .into()
    }
    pub fn capability_unavailable(
        provider_id: impl Into<String>,
        operation: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        ErrorKind::CapabilityUnavailable {
            provider_id: provider_id.into(),
            operation: operation.into(),
            reason: reason.into(),
            user_message: None,
            remediation_action: None,
            retryable: false,
        }
        .into()
    }
    pub fn unsupported_target(
        operation: impl Into<String>,
        path: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        ErrorKind::UnsupportedTarget {
            operation: operation.into(),
            path: path.into(),
            reason: reason.into(),
            remediation_action: None,
        }
        .into()
    }
    pub fn resource_constraint(
        operation: impl Into<String>,
        resource: impl Into<String>,
        reason: impl Into<String>,
        reported_limits: Option<Value>,
    ) -> Self {
        ErrorKind::ResourceConstraint {
            operation: operation.into(),
            resource: resource.into(),
            reason: reason.into(),
            reported_limits,
            remediation_action: None,
            retryable: None,
        }
        .into()
    }
    pub fn provider_adapter(provider_id: impl Into<String>, operation: impl Into<String>) -> Self {
        ErrorKind::ProviderAdapter {
            provider_id: provider_id.into(),
            operation: operation.into(),
            user_message: None,
            remediation_action: None,
        }
        .into()
    }
    pub fn access_denied(
        operation: impl Into<String>,
        path: impl Into<String>,
        system_code: impl Into<String>,
    ) -> Self {
        ErrorKind::AccessDenied {
            operation: operation.into(),
            path: path.into(),
            system_code: system_code.into(),
        }
        .into()
    }
    pub fn artifact_changed(
        operation: impl Into<String>,
        path: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        ErrorKind::ArtifactChanged {
            operation: operation.into(),
            path: path.into(),
            reason: reason.into(),
        }
        .into()
    }
    pub fn evidence_integrity(message: impl Into<String>) -> Self {
        ErrorKind::EvidenceIntegrity {
            message: message.into(),
            user_message: None,
        }
        .into()
    }
    pub fn evidence_reference(
        evidence_id: impl Into<String>,
        reason: impl Into<String>,
        expected: impl Into<String>,
        actual: Option<String>,
    ) -> Self {
        ErrorKind::EvidenceReference {
            evidence_id: evidence_id.into(),
            reason: reason.into(),
            expected: expected.into(),
            actual,
        }
        .into()
    }
    pub fn unknown_registry(reason: impl Into<String>) -> Self {
        ErrorKind::UnknownRegistry {
            reason: reason.into(),
        }
        .into()
    }
    pub fn artifact_operation(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        ErrorKind::ArtifactOperation {
            operation: operation.into(),
            reason: reason.into(),
            artifact_details: None,
            detail: None,
        }
        .into()
    }
    pub fn configuration(message: impl Into<String>, settings: Vec<SettingIssue>) -> Self {
        ErrorKind::Configuration {
            message: message.into(),
            settings,
        }
        .into()
    }
    pub fn no_binary_open() -> Self {
        ErrorKind::NoBinaryOpen.into()
    }
    pub fn binary_target(path: impl Into<String>, reason: impl Into<String>) -> Self {
        ErrorKind::BinaryTarget {
            path: path.into(),
            reason: reason.into(),
            constraint: None,
            system_code: None,
        }
        .into()
    }

    /// Attach producer-owned diagnostics.
    pub fn with_diagnostics(mut self, diagnostics: Map<String, Value>) -> Self {
        self.diagnostics = Some(diagnostics);
        self
    }
    /// Attach retained command output.
    pub fn with_captured_output(mut self, output: CapturedOutput) -> Self {
        self.captured_output = Some(output);
        self
    }
    /// Record incomplete cleanup with the resources that remain owned.
    pub fn with_cleanup(mut self, reason: impl Into<String>, resources: Vec<String>) -> Self {
        self.cleanup = Some(CleanupObservation {
            reason: reason.into(),
            resources,
        });
        self
    }
    /// Retain a completed observation when a later step fails (first wins).
    pub fn retain_partial_observation(mut self, observation: Value) -> Self {
        if self.partial_observation.is_none() {
            self.partial_observation = Some(observation);
        }
        self
    }
    /// Override the user-facing message where the variant supports one.
    pub fn with_user_message(mut self, message: impl Into<String>) -> Self {
        let message = Some(message.into());
        match &mut self.kind {
            ErrorKind::Input { user_message, .. }
            | ErrorKind::Output { user_message, .. }
            | ErrorKind::CapabilityUnavailable { user_message, .. }
            | ErrorKind::Timeout { user_message, .. }
            | ErrorKind::ProviderSelection { user_message, .. }
            | ErrorKind::ProviderAdapter { user_message, .. }
            | ErrorKind::ProcessCapture { user_message, .. }
            | ErrorKind::EvidenceIntegrity { user_message, .. }
            | ErrorKind::EvidenceFile { user_message, .. }
            | ErrorKind::HopperProcess { user_message, .. }
            | ErrorKind::HopperStart { user_message, .. } => *user_message = message,
            ErrorKind::BrowserObservation { detail, .. } => *detail = message,
            _ => {}
        }
        self
    }
    /// Override the remediation action where the variant supports one.
    pub fn with_remediation(mut self, action: impl Into<String>) -> Self {
        let action = Some(action.into());
        match &mut self.kind {
            ErrorKind::Output {
                remediation_action, ..
            }
            | ErrorKind::CapabilityUnavailable {
                remediation_action, ..
            }
            | ErrorKind::UnsupportedTarget {
                remediation_action, ..
            }
            | ErrorKind::Timeout {
                remediation_action, ..
            }
            | ErrorKind::ResourceConstraint {
                remediation_action, ..
            }
            | ErrorKind::ProviderAdapter {
                remediation_action, ..
            } => *remediation_action = action,
            _ => {}
        }
        self
    }

    /// Stable internal tag, matching the original `_tag`.
    pub fn tag(&self) -> &'static str {
        match &self.kind {
            ErrorKind::Protocol { .. } => "AnalysisProtocolError",
            ErrorKind::Input { .. } => "AnalysisInputError",
            ErrorKind::AccessDenied { .. } => "AnalysisAccessDeniedError",
            ErrorKind::ArtifactChanged { .. } => "AnalysisArtifactChangedError",
            ErrorKind::Output { .. } => "AnalysisOutputError",
            ErrorKind::CapabilityUnavailable { .. } => "AnalysisCapabilityUnavailableError",
            ErrorKind::UnsupportedTarget { .. } => "AnalysisUnsupportedTargetError",
            ErrorKind::Cancelled { .. } => "AnalysisCancelledError",
            ErrorKind::Timeout { .. } => "AnalysisTimeoutError",
            ErrorKind::ResourceConstraint { .. } => "AnalysisResourceConstraintError",
            ErrorKind::ProviderSelection { .. } => "ProviderSelectionError",
            ErrorKind::ProviderAdapter { .. } => "ProviderAdapterError",
            ErrorKind::BrowserObservation { .. } => "BrowserObservationError",
            ErrorKind::ArtifactOperation { .. } => "ArtifactOperationError",
            ErrorKind::ProcessCapture { .. } => "ProcessCaptureError",
            ErrorKind::EvidenceIntegrity { .. }
            | ErrorKind::SnapshotMismatch { .. }
            | ErrorKind::EvidenceReference { .. } => "EvidenceIntegrityError",
            ErrorKind::EvidenceFile { .. } => "EvidenceFileError",
            ErrorKind::UnknownRegistry { .. } => "UnknownRegistryError",
            ErrorKind::HopperTimeout { .. } => "HopperTimeoutError",
            ErrorKind::HopperCancelled => "HopperCancelledError",
            ErrorKind::HopperProtocol { .. } => "HopperProtocolError",
            ErrorKind::HopperRemote { .. } => "HopperRemoteError",
            ErrorKind::HopperProcess { .. } => "HopperProcessError",
            ErrorKind::HopperStart { .. } => "HopperStartError",
            ErrorKind::Configuration { .. } => "ConfigurationError",
            ErrorKind::NoBinaryOpen => "NoBinaryOpenError",
            ErrorKind::BinaryTarget { .. } => "BinaryTargetError",
            ErrorKind::Projected { .. } => "ProjectedError",
        }
    }

    /// Internal diagnostic message (the original Error.message).
    pub fn message(&self) -> String {
        match &self.kind {
            ErrorKind::Protocol { message }
            | ErrorKind::HopperProtocol { message }
            | ErrorKind::EvidenceIntegrity { message, .. }
            | ErrorKind::SnapshotMismatch { message }
            | ErrorKind::Configuration { message, .. }
            | ErrorKind::ProcessCapture { message, .. } => message.clone(),
            ErrorKind::Input { operation, .. } => format!("Invalid analysis input for {operation}"),
            ErrorKind::AccessDenied {
                operation,
                path,
                system_code,
            } => format!(
                "Host filesystem read access denied ({system_code}) for {path} during {operation}"
            ),
            ErrorKind::ArtifactChanged { reason, .. } => {
                format!("Selected artifact changed during acquisition: {reason}")
            }
            ErrorKind::Output {
                operation, reason, ..
            } => format!("Invalid analysis output for {operation}: {reason}"),
            ErrorKind::CapabilityUnavailable {
                provider_id,
                operation,
                reason,
                ..
            } => format!("Provider {provider_id} cannot execute {operation}: {reason}"),
            ErrorKind::UnsupportedTarget {
                operation,
                path,
                reason,
                ..
            } => format!("Unsupported target for {operation} at {path}: {reason}"),
            ErrorKind::Cancelled { operation } => {
                format!("Analysis operation was cancelled: {operation}")
            }
            ErrorKind::Timeout {
                operation,
                timeout_ms,
                ..
            } => format!("Analysis operation timed out after {timeout_ms}ms: {operation}"),
            ErrorKind::ResourceConstraint {
                operation, reason, ..
            } => format!("Resource constraint during {operation}: {reason}"),
            ErrorKind::ProviderSelection {
                reason,
                requested_provider_id,
                candidate_ids,
                ..
            } => format!(
                "Analysis provider selection failed ({reason}) for {requested_provider_id}; candidates: {}",
                if candidate_ids.is_empty() {
                    "none".to_owned()
                } else {
                    candidate_ids.join(", ")
                }
            ),
            ErrorKind::ProviderAdapter {
                provider_id,
                operation,
                ..
            } => format!("Provider {provider_id} adapter failed during {operation}"),
            ErrorKind::BrowserObservation {
                operation, reason, ..
            } => format!("Browser observation {operation} failed: {reason}"),
            ErrorKind::ArtifactOperation {
                operation,
                reason,
                artifact_details,
                ..
            } => match artifact_details {
                None => format!("Artifact {operation} failed: {reason}"),
                Some(details) => format!(
                    "Artifact {operation} failed: {reason} at {} (declared_sha256={}, calculated_sha256={}, unpacked={})",
                    details.logical_path,
                    details.declared_sha256.as_deref().unwrap_or("unavailable"),
                    details.calculated_sha256.as_deref().unwrap_or("unavailable"),
                    details.unpacked
                ),
            },
            ErrorKind::EvidenceReference {
                evidence_id,
                reason,
                ..
            } => format!("Evidence reference {reason}: {evidence_id}"),
            ErrorKind::EvidenceFile {
                operation, reason, ..
            } => format!("Evidence bundle {operation} failed: {reason}"),
            ErrorKind::UnknownRegistry { reason } => {
                format!("Residual unknown registry mutation failed: {reason}")
            }
            ErrorKind::HopperTimeout {
                timeout_ms,
                operation,
                ..
            } => format!(
                "Hopper {} timed out after {timeout_ms}ms",
                operation.as_deref().unwrap_or("startup")
            ),
            ErrorKind::HopperCancelled => "Hopper operation was cancelled".into(),
            ErrorKind::HopperRemote {
                code, safe_message, ..
            } => format!("Hopper request failed ({code}): {safe_message}"),
            ErrorKind::HopperProcess { exit_code, .. } => format!(
                "Hopper bridge stopped unexpectedly with code {}",
                exit_code.map_or_else(|| "null".to_owned(), |code| code.to_string())
            ),
            ErrorKind::HopperStart { .. } => {
                "Hopper application bridge could not be started".into()
            }
            ErrorKind::NoBinaryOpen => "No app is open. Ask the user which app to investigate, then call open_binary with its local path.".into(),
            ErrorKind::BinaryTarget { reason, .. } => format!("Cannot open artifact: {reason}"),
            ErrorKind::Projected { projection } => projection["message"]
                .as_str()
                .unwrap_or("Analysis could not complete.")
                .to_owned(),
        }
    }

    /// Adopt a projection produced by an owner that already renders the wire shape.
    pub fn from_projection(projection: Value) -> Self {
        ErrorKind::Projected { projection }.into()
    }

    /// Stable caller-facing code of this failure.
    pub fn code(&self) -> String {
        self.project()["code"]
            .as_str()
            .unwrap_or("execution_failure")
            .to_owned()
    }

    /// Live cleanup status.
    pub fn is_cleanup_incomplete(&self) -> bool {
        if let Some(explicit) = self.cleanup_incomplete {
            return explicit;
        }
        match &self.kind {
            ErrorKind::BrowserObservation { reason, .. } => {
                self.cleanup.is_some() || reason == "cleanup_failed"
            }
            ErrorKind::ProcessCapture { reason, .. } => {
                self.cleanup.is_some() || reason == "cleanup_incomplete"
            }
            _ => self.cleanup.is_some(),
        }
    }

    /// Currently unresolved resources.
    pub fn unresolved_resources(&self) -> Vec<String> {
        if let Some(resources) = &self.cleanup_resources {
            return resources.clone();
        }
        if let Some(cleanup) = &self.cleanup {
            return cleanup.resources.clone();
        }
        match &self.kind {
            ErrorKind::BrowserObservation { reason, .. } if reason == "cleanup_failed" => {
                vec!["browser_transport".into()]
            }
            _ => Vec::new(),
        }
    }

    /// Whether the user-visible category is cancellation.
    fn user_category_cancelled(&self) -> bool {
        match &self.kind {
            ErrorKind::BrowserObservation {
                reason,
                cause_cancelled,
                ..
            } => reason == "cancelled" || *cause_cancelled,
            ErrorKind::ProcessCapture { cancelled, .. } => *cancelled,
            _ => false,
        }
    }

    fn resolved(&self) -> &AnalysisError {
        let mut error = self;
        while !error.is_cleanup_incomplete()
            && let Some(primary) = &error.cleanup_primary
        {
            error = primary;
        }
        error
    }

    /// Caller-facing user message.
    pub fn user_message(&self) -> String {
        user_message(self.resolved())
    }

    /// Project into the exact caller-facing failure shape shared by CLI and MCP.
    pub fn project(&self) -> Value {
        if let ErrorKind::Projected { projection } = &self.kind {
            let mut projection = projection.clone();
            if let Some(partial) = &self.partial_observation
                && let Some(object) = projection.as_object_mut()
            {
                let details = object
                    .entry("details")
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(details) = details.as_object_mut() {
                    details
                        .entry("partial_observation")
                        .or_insert_with(|| partial.clone());
                }
            }
            return projection;
        }
        let composed = self;
        let error = self.resolved();
        let mut diagnostic_source = error;
        while diagnostic_source.diagnostics.is_none()
            && let Some(primary) = &diagnostic_source.cleanup_primary
        {
            diagnostic_source = primary;
        }
        let captured_output = composed
            .captured_output
            .as_ref()
            .or(error.captured_output.as_ref());
        let partial = composed
            .partial_observation
            .as_ref()
            .or(error.partial_observation.as_ref());
        let underlying = underlying_code(error);
        let cleanup_incomplete = error.is_cleanup_incomplete();
        let code = if cleanup_incomplete {
            "cleanup_incomplete"
        } else {
            underlying
        };
        let primary_details = error_details(error);
        let mut details = primary_details.clone().unwrap_or_default();
        let same = std::ptr::eq(composed, error);
        if !same
            && let ErrorKind::ProcessCapture {
                cleanup_report: Some(report),
                ..
            } = &composed.kind
        {
            details.insert("cleanup_report".into(), report.clone());
        }
        if let Some(diagnostics) = &diagnostic_source.diagnostics {
            details.insert("diagnostics".into(), Value::Object(diagnostics.clone()));
        }
        if !same && let Some(history) = &composed.diagnostics {
            details.insert("cleanup_history".into(), Value::Object(history.clone()));
        }
        if cleanup_incomplete {
            details.insert("cleanup".into(), json!("incomplete"));
            details.insert("resources".into(), json!(error.unresolved_resources()));
            if let Some(cleanup) = &error.cleanup {
                details.insert("cleanup_reason".into(), json!(cleanup.reason));
            }
            let execution_failure = primary_details
                .as_ref()
                .and_then(|details| details.get("execution_failure"))
                .cloned()
                .unwrap_or_else(|| json!(underlying));
            details.insert("execution_failure".into(), execution_failure);
        }
        if let Some(output) = captured_output {
            details.insert("captured_output".into(), output.project());
        }
        if let Some(partial) = partial {
            details.insert("partial_observation".into(), partial.clone());
        }
        let retryable = RETRYABLE_CODES.contains(&code)
            || matches!(
                &error.kind,
                ErrorKind::CapabilityUnavailable {
                    retryable: true,
                    ..
                }
            ) && !error.is_cleanup_incomplete()
            || (code == "resource_constraint"
                && matches!(
                    &error.kind,
                    ErrorKind::ResourceConstraint { resource, retryable, .. }
                        if retryable.unwrap_or(resource == "capacity")
                ));
        let mut projection = Map::new();
        projection.insert("code".into(), json!(code));
        projection.insert("category".into(), json!(category(error)));
        projection.insert("message".into(), json!(user_message(error)));
        projection.insert("retryable".into(), json!(retryable));
        projection.insert(
            "remediation".into(),
            json!({ "action": remediation_action(error) }),
        );
        if !details.is_empty() {
            projection.insert("details".into(), Value::Object(details));
        }
        Value::Object(projection)
    }
}

const RETRYABLE_CODES: [&str; 6] = [
    "artifact_changed",
    "invalid_request",
    "provider_timeout",
    "cancelled",
    "revision_conflict",
    "provider_unavailable",
];

fn capability_retryable(error: &AnalysisError) -> bool {
    matches!(
        &error.kind,
        ErrorKind::CapabilityUnavailable {
            retryable: true,
            ..
        }
    ) && !error.is_cleanup_incomplete()
}

fn underlying_code(error: &AnalysisError) -> &'static str {
    match &error.kind {
        ErrorKind::HopperRemote {
            diagnostic_type, ..
        } if diagnostic_type == "invalid_request" => "invalid_request",
        ErrorKind::ProviderSelection { reason, .. } => {
            if reason == "provider_unavailable" {
                "provider_unavailable"
            } else {
                "capability_unavailable"
            }
        }
        ErrorKind::BrowserObservation { reason, .. } => {
            if error.user_category_cancelled() {
                "cancelled"
            } else {
                browser_code(reason)
            }
        }
        ErrorKind::ArtifactOperation {
            reason,
            artifact_details,
            ..
        } => {
            if reason == "integrity" && artifact_details.is_some() {
                "artifact_integrity_mismatch"
            } else if reason == "limit" {
                "truncated"
            } else if reason == "cancelled" {
                "cancelled"
            } else {
                "artifact_operation_failed"
            }
        }
        ErrorKind::BinaryTarget {
            constraint,
            system_code,
            ..
        } => {
            if constraint.as_deref() == Some("load_selection_rejected") {
                "invalid_request"
            } else if system_code.is_none() {
                "target_unavailable"
            } else {
                "access_denied"
            }
        }
        ErrorKind::EvidenceFile { reason, .. } => match reason.as_str() {
            "invalid-json" => "evidence_integrity_mismatch",
            "io" => "execution_failure",
            _ => "invalid_request",
        },
        ErrorKind::UnknownRegistry { reason } => match reason.as_str() {
            "revision-conflict" | "already-exists" => "revision_conflict",
            "limit" => "truncated",
            "integrity" => "evidence_integrity_mismatch",
            _ => "execution_failure",
        },
        ErrorKind::ProcessCapture { .. } => {
            if error.is_cleanup_incomplete() {
                "cleanup_incomplete"
            } else if error.user_category_cancelled() {
                "cancelled"
            } else {
                "process_capture_failed"
            }
        }
        ErrorKind::Protocol { .. }
        | ErrorKind::Output { .. }
        | ErrorKind::HopperProtocol { .. } => "unreadable_output",
        ErrorKind::Input { .. } => "invalid_request",
        ErrorKind::AccessDenied { .. } => "access_denied",
        ErrorKind::ArtifactChanged { .. } => "artifact_changed",
        ErrorKind::CapabilityUnavailable { .. } => "capability_unavailable",
        ErrorKind::UnsupportedTarget { .. } => "unsupported_target",
        ErrorKind::Cancelled { .. } | ErrorKind::HopperCancelled => "cancelled",
        ErrorKind::Timeout { .. } | ErrorKind::HopperTimeout { .. } => "provider_timeout",
        ErrorKind::ResourceConstraint { .. } => "resource_constraint",
        ErrorKind::HopperProcess { .. } | ErrorKind::HopperStart { .. } => "provider_unavailable",
        ErrorKind::Configuration { .. } => "configuration_invalid",
        ErrorKind::NoBinaryOpen => "target_unavailable",
        ErrorKind::EvidenceIntegrity { .. }
        | ErrorKind::SnapshotMismatch { .. }
        | ErrorKind::EvidenceReference { .. } => "evidence_integrity_mismatch",
        ErrorKind::ProviderAdapter { .. }
        | ErrorKind::HopperRemote { .. }
        | ErrorKind::Projected { .. } => "execution_failure",
    }
}

fn browser_code(reason: &str) -> &'static str {
    match reason {
        "endpoint_unreachable" | "disconnected" => "provider_unavailable",
        "invalid_endpoint_response"
        | "protocol_error"
        | "window_not_found"
        | "window_metadata_missing"
        | "process_ownership_unavailable"
        | "secret_unavailable" => "unreadable_output",
        "target_not_found" | "target_not_allowed" | "service_worker_blocked" | "target_changed" => {
            "target_unavailable"
        }
        "payload_limit" => "truncated",
        "cleanup_failed" => "execution_failure",
        "cancelled" => "cancelled",
        "timeout" => "provider_timeout",
        _ => "execution_failure",
    }
}

fn error_details(error: &AnalysisError) -> Option<Map<String, Value>> {
    let object = |value: Value| match value {
        Value::Object(map) => Some(map),
        _ => None,
    };
    match &error.kind {
        ErrorKind::UnsupportedTarget {
            operation,
            path,
            reason,
            ..
        } => object(json!({ "operation": operation, "path": path, "reason": reason })),
        ErrorKind::ResourceConstraint {
            operation,
            resource,
            reason,
            reported_limits,
            ..
        } => object(json!({
            "operation": operation,
            "resource": resource,
            "reason": reason,
            "reported_limits": reported_limits,
        })),
        ErrorKind::ArtifactChanged {
            operation,
            path,
            reason,
        } => object(json!({
            "operation": operation,
            "path": path,
            "reason": reason,
            "boundary": "stable-artifact-read",
        })),
        ErrorKind::AccessDenied {
            operation,
            path,
            system_code,
        } => object(json!({
            "operation": operation,
            "path": path,
            "system_code": system_code,
            "boundary": "filesystem-read",
        })),
        ErrorKind::Output {
            operation, reason, ..
        } => {
            let mut map = Map::new();
            map.insert("operation".into(), json!(operation));
            map.insert("reason".into(), json!(reason));
            if let Some(diagnostics) = &error.diagnostics {
                map.insert("diagnostics".into(), Value::Object(diagnostics.clone()));
            }
            Some(map)
        }
        ErrorKind::Input {
            operation, issues, ..
        } if !issues.is_empty() => object(json!({
            "operation": operation,
            "issues": issues.iter().map(InputIssue::project).collect::<Vec<_>>(),
        })),
        ErrorKind::EvidenceReference {
            evidence_id,
            reason,
            expected,
            actual,
        } => object(json!({
            "evidence_id": evidence_id,
            "reason": reason,
            "expected": expected,
            "actual": actual,
        })),
        ErrorKind::EvidenceIntegrity { message, .. } | ErrorKind::SnapshotMismatch { message } => {
            object(json!({ "reason": message }))
        }
        ErrorKind::ArtifactOperation {
            artifact_details: Some(details),
            ..
        } => object(json!({
            "logical_path": details.logical_path,
            "declared_sha256": details.declared_sha256,
            "calculated_sha256": details.calculated_sha256,
            "unpacked": details.unpacked,
        })),
        ErrorKind::ArtifactOperation {
            operation,
            reason,
            detail,
            ..
        } => {
            let mut map = Map::new();
            map.insert("operation".into(), json!(operation));
            map.insert("reason".into(), json!(reason));
            if reason == "limit" {
                map.insert("truncated".into(), json!(true));
            }
            if let Some(detail) = detail {
                map.insert("detail".into(), json!(detail));
            }
            Some(map)
        }
        ErrorKind::UnknownRegistry { reason } => object(json!({ "reason": reason })),
        ErrorKind::EvidenceFile {
            operation,
            reason,
            path,
            published,
            ..
        } => {
            let mut map = Map::new();
            map.insert("operation".into(), json!(operation));
            map.insert("reason".into(), json!(reason));
            if let Some(path) = path {
                map.insert("path".into(), json!(path));
            }
            if let Some(published) = published {
                map.insert("published".into(), json!(true));
                map.insert("bytes".into(), json!(published.bytes));
                map.insert("published_path".into(), json!(published.path));
            }
            Some(map)
        }
        ErrorKind::CapabilityUnavailable {
            provider_id,
            operation,
            reason,
            ..
        } => object(json!({
            "provider_id": provider_id,
            "operation": operation,
            "reason": reason,
        })),
        ErrorKind::ProviderSelection {
            operation,
            reason,
            requested_provider_id,
            candidate_ids,
            rejections,
            ..
        } => object(json!({
            "operation": operation,
            "selection_reason": reason,
            "requested_provider_id": requested_provider_id,
            "candidate_ids": candidate_ids,
            "rejections": rejections.iter().map(|rejection| json!({
                "provider_id": rejection.provider_id,
                "code": rejection.code,
                "reason": rejection.reason,
                "diagnostics": rejection.diagnostics,
            })).collect::<Vec<_>>(),
        })),
        ErrorKind::ProviderAdapter {
            provider_id,
            operation,
            ..
        } => {
            let mut map = Map::new();
            map.insert("provider_id".into(), json!(provider_id));
            map.insert("operation".into(), json!(operation));
            if error.is_cleanup_incomplete() {
                map.insert("cleanup".into(), json!("incomplete"));
                map.insert("resources".into(), json!(error.unresolved_resources()));
            }
            Some(map)
        }
        ErrorKind::BrowserObservation {
            operation,
            reason,
            primary_reason,
            ..
        } => {
            let mut map = Map::new();
            map.insert("operation".into(), json!(operation));
            map.insert("reason".into(), json!(reason));
            if error.is_cleanup_incomplete() {
                map.insert("cleanup".into(), json!("incomplete"));
                map.insert("resources".into(), json!(error.unresolved_resources()));
                if let Some(primary) = primary_reason {
                    map.insert("primary_reason".into(), json!(primary));
                }
            }
            Some(map)
        }
        ErrorKind::HopperRemote {
            code,
            diagnostic_type,
            operation,
            request_id,
            ..
        } => {
            let mut map = Map::new();
            map.insert("stage".into(), json!("analysis"));
            map.insert("provider_code".into(), json!(code));
            map.insert("diagnostic_type".into(), json!(diagnostic_type));
            if let Some(operation) = operation {
                map.insert("operation".into(), json!(operation));
            }
            if let Some(request_id) = request_id {
                map.insert("request_id".into(), json!(request_id));
            }
            Some(map)
        }
        ErrorKind::HopperProcess {
            exit_code,
            failure_code,
            provider_state,
            stage,
            diagnostic,
            operation,
            request_id,
            launcher_failure,
            ..
        } => {
            let mut map = Map::new();
            map.insert("exit_code".into(), json!(exit_code));
            map.insert("stage".into(), json!(stage));
            map.insert("provider_state".into(), json!(provider_state));
            map.insert(
                "retry_action".into(),
                json!(provider_retry_action(
                    provider_state,
                    failure_code.is_some() || stage == "launch"
                )),
            );
            if let Some(code) = failure_code {
                map.insert("failure_code".into(), json!(code));
            }
            if let Some(operation) = operation {
                map.insert("operation".into(), json!(operation));
            }
            if let Some(request_id) = request_id {
                map.insert("request_id".into(), json!(request_id));
            }
            if let Some(diagnostic) = diagnostic {
                map.insert("diagnostics".into(), diagnostic.clone());
            }
            if let Some(launcher) = launcher_failure {
                map.insert("launcher".into(), launcher.clone());
            }
            Some(map)
        }
        ErrorKind::HopperStart {
            owner_run_id,
            launcher_failure,
            launch_rejection,
            ..
        } => {
            let mut map = Map::new();
            map.insert("stage".into(), json!("launch"));
            map.insert("provider_state".into(), json!("unknown"));
            if let Some(rejection) = launch_rejection {
                map.insert("launch_rejection".into(), rejection.clone());
            }
            map.insert(
                "retry_action".into(),
                json!(if owner_run_id.is_none() {
                    "retry"
                } else {
                    "unknown"
                }),
            );
            if let Some(owner) = owner_run_id {
                map.insert("owner_run_id".into(), json!(owner));
            }
            if let Some(launcher) = launcher_failure {
                map.insert("launcher".into(), launcher.clone());
            }
            Some(map)
        }
        ErrorKind::Cancelled { operation } => {
            let mut map = Map::new();
            map.insert("operation".into(), json!(operation));
            let incomplete = error.is_cleanup_incomplete();
            map.insert(
                "cleanup".into(),
                json!(if incomplete { "incomplete" } else { "complete" }),
            );
            if incomplete && let Some(cleanup) = &error.cleanup {
                map.insert("cleanup_reason".into(), json!(cleanup.reason));
                map.insert("resources".into(), json!(cleanup.resources));
                map.insert("execution_failure".into(), json!("cancelled"));
            }
            Some(map)
        }
        ErrorKind::HopperCancelled => {
            object(json!({ "operation": "hopper", "cleanup": "complete" }))
        }
        ErrorKind::Timeout {
            operation,
            timeout_ms,
            ..
        } => {
            let mut map = Map::new();
            map.insert("operation".into(), json!(operation));
            map.insert("timeout_ms".into(), json!(timeout_ms));
            if error.is_cleanup_incomplete()
                && let Some(cleanup) = &error.cleanup
            {
                map.insert("cleanup".into(), json!("incomplete"));
                map.insert("cleanup_reason".into(), json!(cleanup.reason));
                map.insert("resources".into(), json!(cleanup.resources));
            }
            Some(map)
        }
        ErrorKind::HopperTimeout {
            timeout_ms,
            operation,
            request_id,
            provider_state,
            stage,
            launcher_outcome,
        } => {
            let mut map = Map::new();
            map.insert(
                "stage".into(),
                json!(if operation.is_none() {
                    "startup"
                } else {
                    stage.as_str()
                }),
            );
            map.insert("timeout_ms".into(), json!(timeout_ms));
            if let Some(launcher) = launcher_outcome {
                map.insert("launcher".into(), launcher.clone());
            }
            map.insert("provider_state".into(), json!(provider_state));
            map.insert(
                "retry_action".into(),
                json!(if provider_state == "busy" {
                    "wait"
                } else {
                    "retry"
                }),
            );
            if let Some(operation) = operation {
                map.insert("operation".into(), json!(operation));
            }
            if let Some(request_id) = request_id {
                map.insert("request_id".into(), json!(request_id));
            }
            Some(map)
        }
        ErrorKind::ProcessCapture {
            cleanup_report,
            execution_failure,
            ..
        } => {
            let mut map = Map::new();
            if error.is_cleanup_incomplete() {
                map.insert("cleanup".into(), json!("incomplete"));
                map.insert("resources".into(), json!(error.unresolved_resources()));
                if let Some(report) = cleanup_report {
                    map.insert("cleanup_report".into(), report.clone());
                }
                if let Some(failure) = execution_failure {
                    map.insert("execution_failure".into(), json!(failure));
                }
                return Some(map);
            }
            if error.user_category_cancelled() {
                map.insert("operation".into(), json!("process_capture"));
                map.insert("cleanup".into(), json!("complete"));
            }
            if let Some(report) = cleanup_report {
                map.insert("cleanup_report".into(), report.clone());
            }
            if let Some(failure) = execution_failure {
                map.insert("execution_failure".into(), json!(failure));
            }
            (!map.is_empty()).then_some(map)
        }
        ErrorKind::Configuration { settings, .. } if !settings.is_empty() => object(json!({
            "settings": settings.iter().map(|issue| json!({
                "setting": issue.setting,
                "constraint": issue.constraint,
            })).collect::<Vec<_>>(),
        })),
        ErrorKind::BinaryTarget {
            path,
            reason,
            constraint,
            system_code,
        } => {
            let mut map = Map::new();
            map.insert("path".into(), json!(path));
            map.insert("reason".into(), json!(reason));
            if let Some(constraint) = constraint {
                map.insert("constraint".into(), json!(constraint));
            }
            if let Some(code) = system_code {
                map.insert("system_code".into(), json!(code));
                map.insert("boundary".into(), json!("filesystem-read"));
            }
            Some(map)
        }
        _ => None,
    }
}

/// Recovery choice for a provider operation failure.
pub fn provider_retry_action(state: &str, startup_failure: bool) -> Option<&'static str> {
    if state == "idle" {
        return None;
    }
    if startup_failure && state == "exited" {
        return Some("retry");
    }
    Some(match state {
        "busy" => "wait",
        "exited" | "unreachable" => "restart_provider",
        "not_started" => "retry",
        _ => "unknown",
    })
}

fn category(error: &AnalysisError) -> &'static str {
    if capability_retryable(error) {
        return "unavailable";
    }
    match &error.kind {
        ErrorKind::BinaryTarget {
            constraint: Some(constraint),
            ..
        } if constraint == "load_selection_rejected" => "invalid_input",
        ErrorKind::BinaryTarget {
            constraint: Some(constraint),
            ..
        } if constraint == "wasm_requires_static_inspection"
            || constraint == "file_format_rejected" =>
        {
            "unsupported_target"
        }
        ErrorKind::ProviderSelection { reason, .. } if reason == "provider_unavailable" => {
            "unavailable"
        }
        ErrorKind::ProcessCapture { .. } => {
            if error.user_category_cancelled() {
                "cancelled"
            } else {
                "execution_failure"
            }
        }
        ErrorKind::BrowserObservation { reason, .. } => {
            if error.user_category_cancelled() {
                "cancelled"
            } else {
                match reason.as_str() {
                    "cancelled" => "cancelled",
                    "timeout" => "timeout",
                    "payload_limit" => "truncated",
                    "target_not_found"
                    | "target_not_allowed"
                    | "service_worker_blocked"
                    | "target_changed"
                    | "endpoint_unreachable"
                    | "disconnected" => "unavailable",
                    _ => "execution_failure",
                }
            }
        }
        ErrorKind::HopperRemote {
            diagnostic_type, ..
        } if diagnostic_type == "invalid_request" => "invalid_input",
        ErrorKind::HopperRemote {
            diagnostic_type, ..
        } if diagnostic_type == "authorization" => "unavailable",
        ErrorKind::HopperProcess { .. } | ErrorKind::HopperStart { .. } => "unavailable",
        ErrorKind::ArtifactOperation { reason, .. } => match reason.as_str() {
            "integrity" => "integrity_mismatch",
            "limit" => "truncated",
            "cancelled" => "cancelled",
            "unavailable" => "unavailable",
            _ => "execution_failure",
        },
        ErrorKind::EvidenceFile { reason, .. }
            if matches!(
                reason.as_str(),
                "missing" | "not-file" | "wrong-kind" | "exists"
            ) =>
        {
            "invalid_input"
        }
        ErrorKind::Configuration { .. } | ErrorKind::Input { .. } => "invalid_input",
        ErrorKind::AccessDenied { .. } => "unavailable",
        ErrorKind::ArtifactChanged { .. } => "integrity_mismatch",
        ErrorKind::CapabilityUnavailable { .. } | ErrorKind::ProviderSelection { .. } => {
            "unsupported_provider"
        }
        ErrorKind::UnsupportedTarget { .. } => "unsupported_target",
        ErrorKind::EvidenceIntegrity { .. }
        | ErrorKind::SnapshotMismatch { .. }
        | ErrorKind::EvidenceReference { .. } => "integrity_mismatch",
        ErrorKind::Cancelled { .. } | ErrorKind::HopperCancelled => "cancelled",
        ErrorKind::Timeout { .. } | ErrorKind::HopperTimeout { .. } => "timeout",
        ErrorKind::ResourceConstraint { .. } => "resource_constraint",
        ErrorKind::NoBinaryOpen | ErrorKind::BinaryTarget { .. } => "unavailable",
        _ => "execution_failure",
    }
}

const RESTART_OWNED_PROVIDER: &str =
    "Restart the owned provider by calling close_binary, then open the target again and retry.";

fn restart_unreachable_hopper() -> String {
    format!(
        "{RESTART_OWNED_PROVIDER} If Hopper may have exited, call export_evidence_bundle before close_binary; closing clears retained records."
    )
}

fn remediation_action(error: &AnalysisError) -> String {
    match &error.kind {
        ErrorKind::ProviderAdapter {
            remediation_action: Some(action),
            ..
        }
        | ErrorKind::CapabilityUnavailable {
            remediation_action: Some(action),
            ..
        } => return action.clone(),
        _ => {}
    }
    match &error.kind {
        ErrorKind::BrowserObservation { reason, .. } if reason == "service_worker_blocked" => {
            return "Set environment.service_workers to allow to permit this capture, or remove the service worker registration through the browser. REA never removes existing registrations.".into();
        }
        _ => {}
    }
    if capability_retryable(error) {
        return "Review details.reason, then retry the same analysis after the condition clears."
            .into();
    }
    match &error.kind {
        ErrorKind::EvidenceFile {
            published: Some(_), ..
        } => "Use the published file at details.published_path and resolve the reported staging cleanup failure.".into(),
        ErrorKind::SnapshotMismatch { .. } => "Run analysis without this snapshot, then save a fresh snapshot using the intended artifact, provider, and analysis profile.".into(),
        ErrorKind::UnsupportedTarget { remediation_action, .. } => remediation_action.clone().unwrap_or_else(|| "Select a target supported by this operation or choose an operation supporting the reported target format.".into()),
        ErrorKind::ResourceConstraint { resource, remediation_action, .. } => remediation_action.clone().unwrap_or_else(|| match resource.as_str() {
            "capacity" => "Wait for an active analysis to complete, then retry within the reported admission limits.".into(),
            "transport" => "Discover retained records with get_evidence_bundle and detail: summary, then inspect compatible records through inspect_analysis_view using an exact Evidence reference. Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable.".into(),
            "cpu" => "Review the reported worker CPU limits and observed signal. Retry with sufficient CPU time or a smaller artifact; REA retains tighter inherited limits.".into(),
            "file-size" => "Review the reported worker file-size limits and write failure. Retry with a sufficient file-size allowance for the evidence reply; REA retains tighter inherited limits.".into(),
            _ => "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits.".into(),
        }),
        ErrorKind::Timeout { remediation_action: Some(action), .. } => action.clone(),
        ErrorKind::HopperTimeout { operation, provider_state, .. } => {
            if operation.is_none() {
                "Review details.launcher and inspect Hopper for ongoing initial analysis or a pending loader, demo, or license dialog. For a large target, increase REA_HOPPER_STARTUP_TIMEOUT_MS in the environment that starts REA and allow at least that long in the MCP client. Resolve retained cleanup before reopening.".into()
            } else if provider_state == "busy" {
                "Check binary_session.analysis_activity, wait for the active Hopper request to finish, then retry.".into()
            } else {
                "Check binary_session for Hopper health, then retry the operation.".into()
            }
        }
        ErrorKind::HopperProcess { failure_code, user_message, stage, provider_state, .. } => {
            if failure_code.is_some() && let Some(message) = user_message {
                message.clone()
            } else if stage == "launch" {
                "Review the captured launcher diagnostics and Hopper setup, then retry opening the target.".into()
            } else if provider_state == "unreachable" {
                restart_unreachable_hopper()
            } else if provider_retry_action(provider_state, false) == Some("restart_provider") {
                RESTART_OWNED_PROVIDER.into()
            } else {
                "Read binary_session.provider_operation_health for this request before retrying or restarting the owned provider.".into()
            }
        }
        ErrorKind::HopperStart { owner_run_id, .. } => match owner_run_id {
            None => "Check the Hopper launcher and target details, then retry opening the target.".into(),
            Some(owner) => format!("Use the active REA session {owner} or close it before opening this target again."),
        },
        ErrorKind::HopperRemote { diagnostic_type, .. } => {
            if diagnostic_type == "invalid_request" {
                "Correct the reported address, document, or arguments and retry.".into()
            } else {
                "Review the Hopper diagnostic details and correct the request or target; run `rea doctor` if the provider itself is failing. Repeating the unchanged request is not expected to succeed.".into()
            }
        }
        ErrorKind::EvidenceReference { .. } => "Use an exact Evidence reference retained by this session, supply the complete inline Evidence, re-run its producer, or import its Evidence bundle. close_binary clears retained records.".into(),
        ErrorKind::BinaryTarget { constraint: Some(constraint), path, .. } if constraint == "directory_requires_file" => {
            let _ = path;
            "For a JavaScript/Electron application directory, call analyze_javascript_application with input_path or run `rea analyze <directory>`. For binary analysis, select its executable file.".into()
        }
        ErrorKind::BinaryTarget { constraint: Some(constraint), .. } if constraint == "load_selection_rejected" => "Correct the reported load argument (--target-format, --architecture, or --entry-point on the CLI; format, architecture, or entry_point through MCP) and retry.".into(),
        ErrorKind::BinaryTarget { constraint: Some(constraint), .. } if constraint == "file_format_rejected" => "Review the reported file-format reason and select a supported, well-formed target.".into(),
        ErrorKind::BinaryTarget { constraint: Some(constraint), path, .. } if constraint == "wasm_requires_static_inspection" => format!(
            "For static inspection, call inspect_wasm_artifact with {} or run `rea inspect-wasm-artifact <path> --format json`. This separate lane requires caller-supplied WABT 1.0.42 via absolute REA_WABT_BIN_DIRECTORY; check its availability in binary_session. REA does not execute WASM or install tools, and the header alone does not establish that the complete module is valid.",
            json!({ "path": path })
        ),
        ErrorKind::AccessDenied { .. } | ErrorKind::BinaryTarget { system_code: Some(_), .. } => "Check the current process's read access to the selected path. Retry with a readable local file.".into(),
        ErrorKind::ArtifactChanged { .. } => "Wait until the selected file is stable. For an active binary session, reopen the target with open_binary before retrying so REA acquires its current identity; for a CLI command or target-free tool, rerun the operation.".into(),
        ErrorKind::Configuration { settings, .. } if !settings.is_empty() => {
            let mut seen = Vec::new();
            for issue in settings {
                if !seen.contains(&issue.setting.as_str()) {
                    seen.push(issue.setting.as_str());
                }
            }
            format!("Correct {} in the environment that starts REA (your shell or the MCP client's registration), then rerun.", seen.join(", "))
        }
        ErrorKind::Input { .. } => "Correct the listed arguments and retry.".into(),
        ErrorKind::Output { remediation_action: Some(action), .. } => action.clone(),
        ErrorKind::UnknownRegistry { reason } if reason == "not-found" => "Check that the unknown_id belongs to this session, then retry.".into(),
        _ => user_message(error),
    }
}

fn user_message(error: &AnalysisError) -> String {
    match &error.kind {
        ErrorKind::SnapshotMismatch { message } => return message.clone(),
        ErrorKind::UnsupportedTarget { .. } => return error.message(),
        ErrorKind::ResourceConstraint { reason, .. } => return reason.clone(),
        ErrorKind::AccessDenied { .. } => {
            return "Host filesystem permissions denied read access to the selected path.".into();
        }
        ErrorKind::ArtifactChanged { .. } => {
            return "The selected artifact changed during acquisition; no stable snapshot was decoded.".into();
        }
        ErrorKind::Input { user_message, .. } => {
            return user_message.clone().unwrap_or_else(|| {
                "Analysis input is invalid. Check the arguments and try again.".into()
            });
        }
        _ => {}
    }
    if let Some(message) = hopper_user_message(error) {
        return message;
    }
    if let Some(message) = explicit_user_message(error) {
        return message;
    }
    if capability_retryable(error) {
        return "Required runtime controls are unavailable for this attempt.".into();
    }
    if let Some(message) = standard_message(error) {
        return message.into();
    }
    match &error.kind {
        ErrorKind::ArtifactOperation { .. } => artifact_message(error),
        ErrorKind::EvidenceReference {
            evidence_id,
            reason,
            ..
        } => {
            if reason == "missing" {
                format!("Evidence {evidence_id} is not retained in this session. Supply complete inline Evidence, re-run its producer, or import its bundle before using this reference.")
            } else {
                format!("Evidence {evidence_id} does not match the requested reference ({reason}). Check the expected and actual identity in the diagnostic details.")
            }
        }
        ErrorKind::EvidenceIntegrity { .. } => {
            "Evidence is invalid or has changed. Recreate or re-import it, then try again.".into()
        }
        ErrorKind::EvidenceFile {
            operation,
            reason,
            published,
            ..
        } => {
            if published.is_some() {
                "The output file was published, but staging cleanup remains incomplete.".into()
            } else {
                match reason.as_str() {
                    "missing" if operation == "read" => "Evidence file does not exist at the selected path. Check the path and try again.".into(),
                    "missing" => "Evidence output directory does not exist. Choose an existing directory and try again.".into(),
                    "not-file" => "Evidence path does not point to a regular file. Choose a file and try again.".into(),
                    "exists" => "Evidence file already exists. Choose another path or allow overwrite.".into(),
                    "invalid-json" => "Evidence file is not valid JSON. Repair or recreate the file and try again.".into(),
                    _ => "Evidence file could not be accessed. Check file permissions and try again.".into(),
                }
            }
        }
        ErrorKind::UnknownRegistry { reason } => {
            if reason == "not-found" {
                "The requested residual unknown does not exist in this session. Check the unknown_id and try again.".into()
            } else {
                "Evidence state changed before the update completed. Refresh the current state and try again.".into()
            }
        }
        ErrorKind::Configuration { settings, .. } => {
            if settings.is_empty() {
                "REA configuration is invalid. Run `rea doctor` and fix the reported setting."
                    .into()
            } else {
                let parts = settings
                    .iter()
                    .map(|issue| {
                        if issue.constraint.contains(&issue.setting) {
                            issue
                                .constraint
                                .strip_suffix('.')
                                .unwrap_or(&issue.constraint)
                                .to_owned()
                        } else {
                            format!("{}: {}", issue.setting, issue.constraint)
                        }
                    })
                    .collect::<Vec<_>>();
                format!("REA configuration is invalid: {}.", parts.join("; "))
            }
        }
        ErrorKind::NoBinaryOpen => error.message(),
        ErrorKind::BinaryTarget { constraint, .. } => match constraint.as_deref() {
            Some("wasm_requires_static_inspection") => format!(
                "{}. Static WebAssembly inspection uses a separate optional WABT lane, not a native analysis engine.",
                error.message()
            ),
            Some("directory_requires_file") => "open_binary accepts files and macOS app bundles. This target is a directory; JavaScript/Electron application directories can be analyzed directly with analyze_javascript_application or `rea analyze <directory>`.".into(),
            Some("file_format_rejected") | Some("load_selection_rejected") => {
                format!("{}.", error.message())
            }
            _ => format!(
                "{}. Check that the path exists, is readable, and points to a supported file.",
                error.message()
            ),
        },
        ErrorKind::ProcessCapture { .. } => "Process capture could not complete. Run `rea doctor`, then review capture policy and try again.".into(),
        _ => "Analysis could not complete. Run `rea doctor`, then try again.".into(),
    }
}

/// Producer-supplied userMessage values (the original base-class field).
fn explicit_user_message(error: &AnalysisError) -> Option<String> {
    match &error.kind {
        ErrorKind::Output { user_message, .. }
        | ErrorKind::CapabilityUnavailable { user_message, .. }
        | ErrorKind::Timeout { user_message, .. }
        | ErrorKind::ProviderAdapter { user_message, .. }
        | ErrorKind::EvidenceIntegrity { user_message, .. }
        | ErrorKind::EvidenceFile { user_message, .. } => user_message.clone(),
        ErrorKind::ProviderSelection {
            user_message,
            reason,
            candidate_ids,
            ..
        } => Some(user_message.clone().unwrap_or_else(|| match reason.as_str() {
            "ambiguous" => "Multiple analysis providers support this target. Choose one with provider_id, --provider, or REA_ANALYSIS_PROVIDER.".into(),
            "unknown_provider" => format!(
                "The requested analysis provider is unknown. Choose one of: {}.",
                if candidate_ids.is_empty() { "no configured providers".to_owned() } else { candidate_ids.join(", ") }
            ),
            "provider_unavailable" => "The selected analysis provider is unavailable. Review the reported local diagnostics or run `rea doctor`, then retry.".into(),
            "target_unsupported" => "The selected analysis provider does not support this target. Choose another provider or open a supported extracted binary.".into(),
            _ => "The analysis provider selection or open options are invalid. Correct them and try again.".into(),
        })),
        ErrorKind::BrowserObservation {
            operation,
            reason,
            detail,
            ..
        } => detail.clone().or_else(|| browser_message(operation, reason)),
        ErrorKind::ProcessCapture {
            user_message,
            message,
            ..
        } => Some(user_message.clone().unwrap_or_else(|| message.clone())),
        _ => None,
    }
}

fn browser_message(operation: &str, reason: &str) -> Option<String> {
    Some(match reason {
        "cancelled" => format!(
            "{operation} was cancelled. Collected observations and cleanup status are reported when available."
        ),
        "timeout" => format!(
            "{operation} exceeded its execution deadline. Review the target's responsiveness and retained observations before retrying."
        ),
        "endpoint_unreachable" => format!(
            "{operation} could not reach the selected loopback debugging endpoint. Verify that the target process is running with debugging enabled and that the endpoint's port matches it, then retry."
        ),
        "target_not_found" => format!(
            "{operation} could not find the selected target at the debugging endpoint. Refresh target discovery for that endpoint and retry with a returned target ID."
        ),
        "service_worker_blocked" => format!(
            "{operation} refused the selected page because it is controlled by or has a registered service worker while the service-worker policy is block. Set environment.service_workers to allow to permit observation, or remove the service worker registration through the browser."
        ),
        "disconnected" => format!(
            "{operation} lost its debugging connection. Verify that the target process is still running, refresh target discovery, and retry the observation."
        ),
        _ => return None,
    })
}

fn hopper_user_message(error: &AnalysisError) -> Option<String> {
    match &error.kind {
        ErrorKind::HopperTimeout {
            operation,
            provider_state,
            ..
        } => Some(match operation {
            None => "REA timed out waiting for Hopper bridge readiness, which includes initial analysis. Hopper may still be analyzing the target or waiting for a loader, demo, or license dialog. Review the captured launcher outcome and resolve retained cleanup before retrying.".into(),
            Some(request) if provider_state == "busy" => format!("Hopper timed out during {request} while the provider remained busy. Check binary_session.analysis_activity, wait for the active request to finish, then retry."),
            Some(request) => format!("Hopper timed out during {request} before it started. Check binary_session for provider health, then retry."),
        }),
        ErrorKind::HopperProcess {
            exit_code,
            failure_code,
            user_message,
            provider_state,
            stage,
            operation,
            request_id,
            launcher_signal,
            ..
        } => {
            let place = operation.as_deref().unwrap_or(stage);
            let request = request_id.map_or_else(String::new, |id| format!(" Request id {id}."));
            let startup = user_message
                .as_ref()
                .map_or_else(String::new, |message| format!(" {message}"));
            Some(if provider_state == "exited" {
                let exit = match exit_code {
                    Some(code) => format!("exit code {code}"),
                    None => match launcher_signal {
                        Some(signal) => format!("signal {signal}"),
                        None => "no exit code was observed".into(),
                    },
                };
                let recovery = if failure_code.is_none() && stage != "launch" {
                    format!(" {RESTART_OWNED_PROVIDER}")
                } else {
                    String::new()
                };
                format!("Hopper exited during {place} ({exit}).{startup}{recovery}{request}")
            } else if provider_state == "unreachable" {
                format!(
                    "Hopper became unreachable during {place}; its process exit was not observed. {}{startup}{request}",
                    restart_unreachable_hopper()
                )
            } else {
                format!("Hopper failed during {place} and REA could not determine whether the provider is busy, exited, or unreachable.{startup} Read binary_session.provider_operation_health for this request before retrying or restarting.{request}")
            })
        }
        ErrorKind::HopperStart { user_message, .. } => Some(user_message.clone().unwrap_or_else(|| {
            "Hopper could not start. Check the launcher and target details, then retry opening the target.".into()
        })),
        ErrorKind::HopperRemote {
            code,
            safe_message,
            diagnostic_type,
            operation,
            ..
        } => Some(format!(
            "Hopper {} failed ({code}, {diagnostic_type}): {safe_message}",
            operation.as_deref().unwrap_or("analysis")
        )),
        _ => None,
    }
}

fn standard_message(error: &AnalysisError) -> Option<&'static str> {
    match &error.kind {
        ErrorKind::Protocol { .. }
        | ErrorKind::Output { .. }
        | ErrorKind::HopperProtocol { .. } => Some(
            "Analysis returned an unreadable result. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.",
        ),
        ErrorKind::CapabilityUnavailable { .. } | ErrorKind::ProviderSelection { .. } => Some(
            "This analysis is unavailable for the current target. Choose another analysis or target.",
        ),
        ErrorKind::Cancelled { .. } | ErrorKind::HopperCancelled => {
            Some("Analysis was cancelled. Start it again when ready.")
        }
        ErrorKind::Timeout { .. } | ErrorKind::HopperTimeout { .. } => Some(
            "Analysis took too long. Try a smaller request, then run `rea doctor` if it continues.",
        ),
        ErrorKind::ProviderAdapter { .. } | ErrorKind::HopperRemote { .. } => Some(
            "Analysis could not complete. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.",
        ),
        ErrorKind::HopperProcess { .. } | ErrorKind::HopperStart { .. } => Some(
            "Analysis could not start or stopped unexpectedly. Run `rea doctor`, then try again.",
        ),
        _ => None,
    }
}

const INTEGRITY_POLICY_OPERATIONS: [&str; 4] = [
    "inventory_artifact",
    "inspect_artifact",
    "extract_artifact",
    "analyze_javascript_application",
];

fn artifact_message(error: &AnalysisError) -> String {
    let ErrorKind::ArtifactOperation {
        operation,
        reason,
        artifact_details,
        detail,
    } = &error.kind
    else {
        return String::new();
    };
    match reason.as_str() {
        "cancelled" => "Artifact operation was cancelled. Start it again when ready.".into(),
        "limit" => "Artifact is too large to process safely. Narrow the requested path or use a smaller artifact.".into(),
        "path" => detail.clone().unwrap_or_else(|| "Artifact contains a conflicting internal path. Inspect the reported path before retrying.".into()),
        "unavailable" if artifact_details.as_ref().is_some_and(|details| details.unpacked) => format!(
            "ASAR unpacked companion bytes are unavailable for {}. Select the archive in place with its .unpacked directory beside it, then retry.",
            artifact_details.as_ref().map(|details| details.logical_path.as_str()).unwrap_or_default()
        ),
        "unavailable" => "Artifact processing is unavailable for the current target or host. Check artifact support and required tools.".into(),
        "integrity" if INTEGRITY_POLICY_OPERATIONS.contains(&operation.as_str()) => {
            let lead = match artifact_details {
                Some(details) if details.unpacked && details.calculated_sha256.is_some() => format!(
                    "Declared ASAR integrity for unpacked entry {} contradicts its companion file; packaging tools commonly sign or strip unpacked native binaries after writing the archive.",
                    details.logical_path
                ),
                _ => "Artifact bytes contradict declared integrity.".into(),
            };
            let rerun = if operation == "inventory_artifact" { "inspect_artifact" } else { operation.as_str() };
            format!("{lead} If expected, rerun {rerun} with integrity_policy=record-and-continue (CLI: --integrity-policy record-and-continue) to retain observed bytes as untrusted; otherwise get a fresh copy.")
        }
        "format" | "integrity" => "Artifact is invalid or has changed. Get a fresh copy and try again.".into(),
        _ => "Artifact could not be read or written. Check file access and try again.".into(),
    }
}

impl From<crate::failure::Failure> for AnalysisError {
    /// Adopt the older owner-projected envelope, which already has the exact
    /// caller-facing shape (`code`, `category`, `message`, ...).
    fn from(failure: crate::failure::Failure) -> Self {
        Self::from(&failure)
    }
}

impl From<&crate::failure::Failure> for AnalysisError {
    fn from(failure: &crate::failure::Failure) -> Self {
        match serde_json::to_value(failure) {
            Ok(mut projection) => {
                // The original projection omits empty details.
                if projection["details"]
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
                    && let Some(object) = projection.as_object_mut()
                {
                    object.remove("details");
                }
                Self::from_projection(projection)
            }
            Err(error) => Self::output("native", error.to_string()),
        }
    }
}
