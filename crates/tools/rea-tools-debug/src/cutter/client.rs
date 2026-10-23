//! Cutter bridge discovery and request client.
//!
//! Port of `CutterBridgeClient` in `src/cutter/CutterBridgeClient.ts`:
//! bridge-directory resolution, POSIX directory/descriptor security checks,
//! descriptor discovery with bounded candidates and concurrency, the typed
//! discovery/command error mapping, and the status/command/ack request flows.
//!
//! This host is POSIX (macOS). The Windows private-directory ACL reader is a
//! bring-your-own native authority in the oracle (`requireWindowsNativeAuthority`)
//! and has no counterpart in this build; on a non-POSIX platform discovery
//! fails closed with `bridge_directory_insecure`, exactly as the oracle does
//! when the Windows reader is absent.

use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::transport::{self, RequestFailure};

const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAX_FRAME_BYTES: u64 = 16 * 1024 * 1024;
/// Bound admitted descriptor candidates (`MAX_FRAME_BYTES / MAX_DESCRIPTOR_BYTES`).
const MAX_DESCRIPTOR_CANDIDATES: usize = (MAX_FRAME_BYTES / MAX_DESCRIPTOR_BYTES) as usize;

/// `CUTTER_PROVIDER_IDENTITY` in `CutterBridgeClient.ts`.
pub(super) const PROVIDER_ID: &str = "cutter.python-plugin";
pub(super) const PROVIDER_NAME: &str = "Cutter Python plugin";

/// A validated descriptor (`descriptorSchema`). The `token` is a transport
/// credential: it is never surfaced, recorded or logged.
#[derive(Clone)]
pub(super) struct Descriptor {
    pub session_id: String,
    pub pid: u64,
    pub port: u16,
    pub token: String,
    pub document_generation: u64,
    pub current_file: Option<String>,
    pub cutter_version: Option<String>,
}

/// Directory security classification (`bridge_directory_security`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Security {
    PrivateVerified,
    NotPrivate,
    UnverifiedPlatformAcl,
    NotChecked,
}

impl Security {
    pub fn as_str(self) -> &'static str {
        match self {
            Security::PrivateVerified => "private_verified",
            Security::NotPrivate => "not_private",
            Security::UnverifiedPlatformAcl => "unverified_platform_acl",
            Security::NotChecked => "not_checked",
        }
    }
}

/// Discovery failure (`discovery_status` other than found/none).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DiscoveryError {
    Unavailable,
    Insecure,
    CapacityExceeded,
}

impl DiscoveryError {
    pub fn as_str(self) -> &'static str {
        match self {
            DiscoveryError::Unavailable => "bridge_directory_unavailable",
            DiscoveryError::Insecure => "bridge_directory_insecure",
            DiscoveryError::CapacityExceeded => "bridge_directory_capacity_exceeded",
        }
    }
}

struct LoadedDescriptors {
    descriptors: Vec<Descriptor>,
    security: Security,
    error: Option<DiscoveryError>,
}

/// A validated bridge session (`CutterBridgeSession`: descriptor without the
/// transport fields).
pub(super) struct Session {
    pub session_id: String,
    pub pid: u64,
    pub document_generation: u64,
    pub current_file: Option<String>,
    pub cutter_version: Option<String>,
}

/// Successful discovery result (`CutterBridgeDiscovery`).
pub(super) struct Discovery {
    pub sessions: Vec<Session>,
    pub bridge_directory: String,
    pub discovery_status: &'static str,
    pub bridge_directory_security: &'static str,
}

/// Client state: the resolved bridge directory and per-session pending
/// acknowledgements (`#pendingAcknowledgements`).
pub(super) struct Client {
    directory: PathBuf,
    is_posix: bool,
    pending_acknowledgements: Mutex<HashMap<String, Vec<String>>>,
}

impl Client {
    /// Resolve the bridge directory from the session environment, mirroring the
    /// `CutterBridgeClient` constructor and `resolveBridgeDirectory`.
    pub fn new(environment: &HashMap<String, String>) -> Self {
        let configured = environment.get("REA_CUTTER_BRIDGE_DIR").map(String::as_str);
        let local_app_data = environment.get("LOCALAPPDATA").map(String::as_str);
        let directory = resolve_bridge_directory(
            configured,
            local_app_data,
            &home_directory_from_environment(environment),
        );
        Self {
            directory,
            is_posix: cfg!(unix),
            pending_acknowledgements: Mutex::new(HashMap::new()),
        }
    }

    pub fn directory_display(&self) -> String {
        self.directory.to_string_lossy().into_owned()
    }

    /// `CutterBridgeClient.listSessions`.
    pub fn list_sessions(&self, cancellation: &Cancellation) -> Result<Discovery, AnalysisError> {
        let loaded = self.load_descriptors(cancellation)?;
        if let Some(error) = loaded.error {
            return Ok(Discovery {
                sessions: Vec::new(),
                bridge_directory: self.directory_display(),
                discovery_status: error.as_str(),
                bridge_directory_security: loaded.security.as_str(),
            });
        }

        let mut sessions = Vec::new();
        for descriptor in &loaded.descriptors {
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled("list_cutter_sessions"));
            }
            // Probe each descriptor with a `status` request and keep only
            // those whose authenticated peer reports a matching session.
            let request_bytes = match transport::serialize_request(
                descriptor,
                serde_json::json!({ "kind": "status", "session_id": descriptor.session_id }),
            ) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let outcome = match transport::request(descriptor, &request_bytes, cancellation) {
                Ok(outcome) => outcome,
                Err(_) => {
                    if cancellation.reason().is_some() {
                        return Err(AnalysisError::cancelled("list_cutter_sessions"));
                    }
                    continue;
                }
            };
            let Some(status) = parse_response(&outcome.response) else {
                continue;
            };
            if !status.ok || status.session_id.as_deref() != Some(descriptor.session_id.as_str()) {
                continue;
            }
            sessions.push(Session {
                session_id: descriptor.session_id.clone(),
                pid: descriptor.pid,
                document_generation: status
                    .document_generation
                    .unwrap_or(descriptor.document_generation),
                current_file: match status.current_file {
                    FieldOption::Absent => descriptor.current_file.clone(),
                    FieldOption::Present(value) => value,
                },
                cutter_version: status
                    .cutter_version
                    .flatten()
                    .or_else(|| descriptor.cutter_version.clone()),
            });
        }

        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("list_cutter_sessions"));
        }
        let discovery_status = if sessions.is_empty() {
            "no_live_bridge_found"
        } else {
            "sessions_found"
        };
        Ok(Discovery {
            sessions,
            bridge_directory: self.directory_display(),
            discovery_status,
            bridge_directory_security: loaded.security.as_str(),
        })
    }

    /// `CutterBridgeClient.execute`. Returns the normalized execution, or a
    /// typed `AnalysisError` for pre-send or input failures.
    pub fn execute(
        &self,
        input: &ExecuteInput,
        cancellation: &Cancellation,
    ) -> Result<Execution, AnalysisError> {
        assert_command_active(cancellation)?;
        let descriptor = self.find(&input.session_id, cancellation)?;
        assert_command_active(cancellation)?;

        let request_id = uuid::Uuid::new_v4().to_string();
        let command_request = transport::serialize_request(
            &descriptor,
            serde_json::json!({
                "kind": "command",
                "request_id": request_id,
                "expected_generation": input.expected_generation,
                "command": input.command,
                "json": input.json,
            }),
        )
        .map_err(|constraint| {
            AnalysisError::resource_constraint(
                "cutter_command",
                "transport",
                "Cutter request exceeds its authenticated frame limit; no command was sent.",
                Some(serde_json::json!({
                    "frame_bytes": constraint.frame_bytes,
                    "max_frame_bytes": constraint.max_frame_bytes,
                })),
            )
        })?;

        self.recover_completed_commands(&descriptor)?;
        self.retry_pending_acknowledgements(&descriptor)?;
        assert_command_active(cancellation)?;

        let outcome = match transport::request(&descriptor, &command_request, cancellation) {
            Ok(outcome) => outcome,
            Err(failure) => {
                let completion_token = None;
                // A failure whose request was sent is an `unknown` (possibly
                // applied) command; a pre-send failure propagates.
                if !failure.request_sent {
                    return Err(self.map_request_failure(failure, cancellation));
                }
                return Ok(Execution::unknown(
                    &request_id,
                    &descriptor,
                    input.expected_generation,
                    "transport-response-missing",
                    format!(
                        "{}; the command may have completed; do not retry automatically",
                        failure.message
                    ),
                    completion_token,
                ));
            }
        };
        // The authenticated connection ordinal is set during the handshake;
        // retain it as the completion token for later confirmation.
        let completion_token = outcome.connection_ordinal.clone();

        let Some(response) = parse_response(&outcome.response) else {
            return Ok(Execution::unknown(
                &request_id,
                &descriptor,
                input.expected_generation,
                "malformed-bridge-response",
                "Cutter may have completed the command, but its response was invalid; do not retry automatically".to_owned(),
                completion_token,
            ));
        };

        let execution_state =
            classify_execution_state(response.ok, response.execution_state.as_deref());

        if execution_state != ExecutionState::Unknown {
            self.acknowledge_completion(&descriptor, &request_id);
        }

        if response.error.as_deref() == Some("active-document-generation-changed") {
            // The TS client throws `new Error("...generation changed")`,
            // which the service maps to a bare `AnalysisInputError`.
            return Err(AnalysisError::input("cutter_command", Vec::new()));
        }

        Ok(Execution {
            request_id,
            output: response.output.unwrap_or(serde_json::Value::Null),
            current_file: match response.current_file {
                FieldOption::Absent => descriptor.current_file.clone(),
                FieldOption::Present(value) => value,
            },
            document_generation: response
                .document_generation
                .unwrap_or(input.expected_generation),
            cutter_version: response
                .cutter_version
                .flatten()
                .or(descriptor.cutter_version.clone()),
            execution_state,
            error: if response.ok {
                None
            } else {
                Some(
                    response
                        .error
                        .unwrap_or_else(|| "cutter-command-failed".to_owned()),
                )
            },
            message: response.message,
            output_truncated: response.output_truncated.unwrap_or(false),
            completion_token,
        })
    }

    /// `CutterBridgeClient.confirmCommandCompletion`.
    pub fn confirm_command_completion(
        &self,
        session_id: &str,
        request_id: &str,
        completion_token: Option<&str>,
    ) -> Result<bool, AnalysisError> {
        let descriptor = self.find(session_id, &Cancellation::default())?;
        let status = self.read_command_status(&descriptor)?;
        let completed = status
            .completed_commands
            .iter()
            .any(|receipt| receipt.request_id == request_id);
        if completed {
            self.acknowledge_completion(&descriptor, request_id);
        }
        Ok(completed
            || match (completion_token, status.completed_connection.as_deref()) {
                (Some(token), Some(watermark)) => watermark >= token,
                _ => false,
            })
    }

    /// `#readCommandStatus`.
    fn read_command_status(
        &self,
        descriptor: &Descriptor,
    ) -> Result<ParsedResponse, AnalysisError> {
        let request_bytes = transport::serialize_request(
            descriptor,
            serde_json::json!({ "kind": "status", "session_id": descriptor.session_id }),
        )
        .map_err(|_| status_output_error())?;
        let outcome = transport::request(descriptor, &request_bytes, &Cancellation::default())
            .map_err(|failure| {
                AnalysisError::capability_unavailable("cutter", "cutter_command", failure.message)
                    .with_diagnostics(status_diagnostics())
            })?;
        let parsed = parse_response(&outcome.response);
        let status = match parsed {
            Some(status)
                if status.ok
                    && status.session_id.as_deref() == Some(descriptor.session_id.as_str()) =>
            {
                status
            }
            _ => return Err(status_output_error()),
        };
        Ok(status)
    }

    /// `#recoverCompletedCommands`.
    fn recover_completed_commands(&self, descriptor: &Descriptor) -> Result<(), AnalysisError> {
        let status = self.read_command_status(descriptor)?;
        if status.completed_connection.is_none() {
            return Err(AnalysisError::output(
                "cutter_command",
                "The bridge did not provide authenticated proof that earlier connections reached a terminal state.",
            )
            .with_diagnostics(status_diagnostics()));
        }
        let mut pending = self.pending_acknowledgements.lock().unwrap();
        let entry = pending.entry(descriptor.session_id.clone()).or_default();
        for receipt in &status.completed_commands {
            if !entry.contains(&receipt.request_id) {
                entry.push(receipt.request_id.clone());
            }
        }
        if entry.is_empty() {
            pending.remove(&descriptor.session_id);
        }
        Ok(())
    }

    /// `#acknowledgeCompletion`. Returns whether the ack was confirmed; on
    /// failure the request id is retained for later retry.
    fn acknowledge_completion(&self, descriptor: &Descriptor, request_id: &str) -> bool {
        let confirmed = (|| {
            let request_bytes = transport::serialize_request(
                descriptor,
                serde_json::json!({ "kind": "ack", "request_id": request_id }),
            )
            .ok()?;
            let outcome =
                transport::request(descriptor, &request_bytes, &Cancellation::default()).ok()?;
            let ok = outcome.response.get("ok")? == &serde_json::Value::Bool(true);
            let acknowledged = outcome.response.get("acknowledged").is_some();
            (ok && acknowledged).then_some(())
        })()
        .is_some();

        let mut pending = self.pending_acknowledgements.lock().unwrap();
        if confirmed {
            if let Some(entry) = pending.get_mut(&descriptor.session_id) {
                entry.retain(|retained| retained != request_id);
                if entry.is_empty() {
                    pending.remove(&descriptor.session_id);
                }
            }
        } else {
            let entry = pending.entry(descriptor.session_id.clone()).or_default();
            if !entry.iter().any(|retained| retained == request_id) {
                entry.push(request_id.to_owned());
            }
        }
        confirmed
    }

    /// `#retryPendingAcknowledgements`.
    fn retry_pending_acknowledgements(&self, descriptor: &Descriptor) -> Result<(), AnalysisError> {
        let pending = {
            let guard = self.pending_acknowledgements.lock().unwrap();
            guard.get(&descriptor.session_id).cloned()
        };
        let Some(pending) = pending else {
            return Ok(());
        };
        for request_id in pending {
            if !self.acknowledge_completion(descriptor, &request_id) {
                return Err(AnalysisError::capability_unavailable(
                    "cutter",
                    "cutter_command",
                    "A retained Cutter completion receipt could not be acknowledged; no new command was sent.",
                ));
            }
        }
        Ok(())
    }

    /// `#find`.
    fn find(
        &self,
        session_id: &str,
        cancellation: &Cancellation,
    ) -> Result<Descriptor, AnalysisError> {
        let loaded = self.load_descriptors(cancellation)?;
        match loaded.error {
            Some(DiscoveryError::CapacityExceeded) => {
                return Err(AnalysisError::resource_constraint(
                    "cutter_command",
                    "transport",
                    "Cutter descriptor discovery exceeded its candidate budget; no command was sent.",
                    Some(serde_json::json!({
                        "max_descriptor_candidates": MAX_DESCRIPTOR_CANDIDATES,
                        "bridge_directory": self.directory_display(),
                    })),
                ));
            }
            Some(error) => {
                return Err(AnalysisError::capability_unavailable(
                    "cutter",
                    "cutter_command",
                    format!("Cutter descriptor discovery failed: {}", error.as_str()),
                ));
            }
            None => {}
        }
        loaded
            .descriptors
            .into_iter()
            .find(|candidate| candidate.session_id == session_id)
            .ok_or_else(|| {
                // Mirrors the TS `throw new Error("...unavailable or stale")`,
                // which the service maps to an input error.
                AnalysisError::input("cutter_command", Vec::new())
            })
    }

    /// `#loadDescriptors`: directory security checks, bounded candidate
    /// enumeration, bounded per-descriptor reads and validation.
    fn load_descriptors(
        &self,
        cancellation: &Cancellation,
    ) -> Result<LoadedDescriptors, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("list_cutter_sessions"));
        }

        let metadata = match std::fs::symlink_metadata(&self.directory) {
            Ok(metadata) => metadata,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LoadedDescriptors {
                    descriptors: Vec::new(),
                    security: Security::NotChecked,
                    error: None,
                });
            }
            Err(_) => {
                return Ok(LoadedDescriptors {
                    descriptors: Vec::new(),
                    security: Security::NotChecked,
                    error: Some(DiscoveryError::Unavailable),
                });
            }
        };

        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Ok(LoadedDescriptors {
                descriptors: Vec::new(),
                security: Security::NotPrivate,
                error: Some(DiscoveryError::Insecure),
            });
        }

        if !self.is_posix {
            // No Windows private-ACL reader in this build: fail closed exactly
            // like the oracle when `windowsPrivateReader` is undefined.
            return Ok(LoadedDescriptors {
                descriptors: Vec::new(),
                security: Security::UnverifiedPlatformAcl,
                error: Some(DiscoveryError::Insecure),
            });
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let current_uid = current_uid();
            if metadata.uid() != current_uid || (metadata.mode() & 0o077) != 0 {
                return Ok(LoadedDescriptors {
                    descriptors: Vec::new(),
                    security: Security::NotPrivate,
                    error: Some(DiscoveryError::Insecure),
                });
            }
            let security = Security::PrivateVerified;

            let candidates = match self.enumerate_candidates(cancellation) {
                Ok(Some(candidates)) => candidates,
                Ok(None) => {
                    return Ok(LoadedDescriptors {
                        descriptors: Vec::new(),
                        security,
                        error: Some(DiscoveryError::CapacityExceeded),
                    });
                }
                Err(Enumeration::Unavailable) => {
                    return Ok(LoadedDescriptors {
                        descriptors: Vec::new(),
                        security: Security::NotChecked,
                        error: Some(DiscoveryError::Unavailable),
                    });
                }
                Err(Enumeration::Cancelled) => {
                    return Err(AnalysisError::cancelled("list_cutter_sessions"));
                }
            };

            let mut descriptors = Vec::new();
            for entry in candidates {
                if cancellation.reason().is_some() {
                    return Err(AnalysisError::cancelled("list_cutter_sessions"));
                }
                if let Some(descriptor) = self.read_descriptor(&entry, current_uid) {
                    descriptors.push(descriptor);
                }
            }
            return Ok(LoadedDescriptors {
                descriptors,
                security,
                error: None,
            });
        }

        #[cfg(not(unix))]
        {
            let _ = cancellation;
            unreachable!("non-posix handled above");
        }
    }

    /// Enumerate descriptor-name candidates. `Ok(None)` signals the candidate
    /// budget was exceeded.
    #[cfg(unix)]
    fn enumerate_candidates(
        &self,
        cancellation: &Cancellation,
    ) -> Result<Option<Vec<PathBuf>>, Enumeration> {
        let reader = std::fs::read_dir(&self.directory).map_err(|_| Enumeration::Unavailable)?;
        let pattern = descriptor_name_pattern();
        let mut entries = Vec::new();
        for entry in reader {
            if cancellation.reason().is_some() {
                return Err(Enumeration::Cancelled);
            }
            let entry = entry.map_err(|_| Enumeration::Unavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !pattern.is_match(name) {
                continue;
            }
            if entries.len() == MAX_DESCRIPTOR_CANDIDATES {
                return Ok(None);
            }
            entries.push(entry.path());
        }
        Ok(Some(entries))
    }

    /// Read, bound, and validate one descriptor file, enforcing its owner/mode
    /// and the `cutter-<pid>-<session_id>.json` name binding.
    #[cfg(unix)]
    fn read_descriptor(&self, path: &Path, current_uid: u32) -> Option<Descriptor> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::symlink_metadata(path).ok()?;
        if !metadata.is_file()
            || metadata.len() > MAX_DESCRIPTOR_BYTES
            || metadata.uid() != current_uid
            || (metadata.mode() & 0o077) != 0
        {
            return None;
        }
        let bytes = read_bounded(path, MAX_DESCRIPTOR_BYTES)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let descriptor = parse_descriptor(&value)?;
        let file_name = path.file_name()?.to_str()?;
        if file_name != format!("cutter-{}-{}.json", descriptor.pid, descriptor.session_id) {
            return None;
        }
        Some(descriptor)
    }

    fn map_request_failure(
        &self,
        failure: RequestFailure,
        cancellation: &Cancellation,
    ) -> AnalysisError {
        if cancellation.reason().is_some() {
            return AnalysisError::cancelled("cutter_command");
        }
        AnalysisError::capability_unavailable("cutter", "cutter_command", failure.message)
    }
}

#[cfg(unix)]
enum Enumeration {
    Unavailable,
    Cancelled,
}

/// Normalized execution result (`CutterBridgeExecution`).
pub(super) struct Execution {
    pub request_id: String,
    pub output: serde_json::Value,
    pub current_file: Option<String>,
    pub document_generation: u64,
    pub cutter_version: Option<String>,
    pub execution_state: ExecutionState,
    pub error: Option<String>,
    pub message: Option<String>,
    pub output_truncated: bool,
    pub completion_token: Option<String>,
}

impl Execution {
    fn unknown(
        request_id: &str,
        descriptor: &Descriptor,
        expected_generation: u64,
        error: &str,
        message: String,
        completion_token: Option<String>,
    ) -> Self {
        Self {
            request_id: request_id.to_owned(),
            output: serde_json::Value::Null,
            current_file: descriptor.current_file.clone(),
            document_generation: expected_generation,
            cutter_version: descriptor.cutter_version.clone(),
            execution_state: ExecutionState::Unknown,
            error: Some(error.to_owned()),
            message: Some(message),
            output_truncated: false,
            completion_token,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecutionState {
    NotStarted,
    Complete,
    Failed,
    Unknown,
}

impl ExecutionState {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionState::NotStarted => "not_started",
            ExecutionState::Complete => "complete",
            ExecutionState::Failed => "failed",
            ExecutionState::Unknown => "unknown",
        }
    }
}

pub(super) struct ExecuteInput {
    pub session_id: String,
    pub expected_generation: u64,
    pub command: String,
    pub json: bool,
}

fn classify_execution_state(ok: bool, execution_state: Option<&str>) -> ExecutionState {
    if ok {
        match execution_state {
            None | Some("complete") => ExecutionState::Complete,
            Some("not_started") => ExecutionState::NotStarted,
            _ => ExecutionState::Unknown,
        }
    } else {
        match execution_state {
            Some("failed") => ExecutionState::Failed,
            Some("not_started") => ExecutionState::NotStarted,
            _ => ExecutionState::Unknown,
        }
    }
}

fn assert_command_active(cancellation: &Cancellation) -> Result<(), AnalysisError> {
    if cancellation.reason().is_some() {
        Err(AnalysisError::cancelled("cutter_command"))
    } else {
        Ok(())
    }
}

fn status_diagnostics() -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "auxiliary_operation".to_owned(),
        serde_json::Value::String("status".to_owned()),
    );
    map
}

fn status_output_error() -> AnalysisError {
    AnalysisError::output(
        "cutter_command",
        "The bridge status response did not contain a valid session identity.",
    )
    .with_diagnostics(status_diagnostics())
}

/// Distinguishes an absent field from a present `null`, matching the TS
/// `response.current_file === undefined ? descriptor : response.current_file`.
enum FieldOption {
    Absent,
    Present(Option<String>),
}

struct CompletedReceipt {
    request_id: String,
}

struct ParsedResponse {
    ok: bool,
    session_id: Option<String>,
    output: Option<serde_json::Value>,
    current_file: FieldOption,
    cutter_version: Option<Option<String>>,
    document_generation: Option<u64>,
    error: Option<String>,
    message: Option<String>,
    execution_state: Option<String>,
    output_truncated: Option<bool>,
    completed_commands: Vec<CompletedReceipt>,
    completed_connection: Option<String>,
}

/// Validate a bridge response against `responseSchema`. Returns `None` on any
/// schema violation (the oracle treats a `safeParse` failure as absent).
fn parse_response(value: &serde_json::Value) -> Option<ParsedResponse> {
    let object = value.as_object()?;
    let ok = object.get("ok")?.as_bool()?;

    let session_id = match object.get("session_id") {
        None => None,
        Some(serde_json::Value::String(text)) if is_uuid(text) => Some(text.clone()),
        Some(_) => return None,
    };
    let output = object.get("output").cloned();
    let current_file = match object.get("current_file") {
        None => FieldOption::Absent,
        Some(serde_json::Value::Null) => FieldOption::Present(None),
        Some(serde_json::Value::String(text)) => FieldOption::Present(Some(text.clone())),
        Some(_) => return None,
    };
    let cutter_version = match object.get("cutter_version") {
        None => None,
        Some(serde_json::Value::Null) => Some(None),
        Some(serde_json::Value::String(text)) => Some(Some(text.clone())),
        Some(_) => return None,
    };
    let document_generation = match object.get("document_generation") {
        None => None,
        Some(value) => Some(non_negative_u64(value)?),
    };
    let error = optional_string(object.get("error"))?;
    let message = optional_string(object.get("message"))?;
    let execution_state = match object.get("execution_state") {
        None => None,
        Some(serde_json::Value::String(text))
            if matches!(
                text.as_str(),
                "not_started" | "running" | "complete" | "failed" | "unknown"
            ) =>
        {
            Some(text.clone())
        }
        Some(_) => return None,
    };
    let output_truncated = match object.get("output_truncated") {
        None => None,
        Some(serde_json::Value::Bool(value)) => Some(*value),
        Some(_) => return None,
    };
    let completed_commands = match object.get("completed_commands") {
        None => Vec::new(),
        Some(serde_json::Value::Array(items)) => {
            if items.len() > 64 {
                return None;
            }
            let mut receipts = Vec::with_capacity(items.len());
            for item in items {
                let item = item.as_object()?;
                let request_id = item.get("request_id")?.as_str()?;
                if !is_uuid(request_id) {
                    return None;
                }
                let state = item.get("execution_state")?.as_str()?;
                if !matches!(state, "not_started" | "complete" | "failed") {
                    return None;
                }
                receipts.push(CompletedReceipt {
                    request_id: request_id.to_owned(),
                });
            }
            receipts
        }
        Some(_) => return None,
    };
    let completed_connection = parse_completed_connection(value);

    Some(ParsedResponse {
        ok,
        session_id,
        output,
        current_file,
        cutter_version,
        document_generation,
        error,
        message,
        execution_state,
        output_truncated,
        completed_commands,
        completed_connection,
    })
}

/// `completed_connection` is `/^[0-9a-f]{16}$/` when present.
fn parse_completed_connection(value: &serde_json::Value) -> Option<String> {
    let text = value.get("completed_connection")?.as_str()?;
    (text.len() == 16
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    .then(|| text.to_owned())
}

fn optional_string(value: Option<&serde_json::Value>) -> Option<Option<String>> {
    match value {
        None => Some(None),
        Some(serde_json::Value::String(text)) => Some(Some(text.clone())),
        Some(_) => None,
    }
}

/// Validate a descriptor file against `descriptorSchema`.
fn parse_descriptor(value: &serde_json::Value) -> Option<Descriptor> {
    let object = value.as_object()?;
    let session_id = object.get("session_id")?.as_str()?;
    if !is_uuid(session_id) {
        return None;
    }
    let pid = positive_u64(object.get("pid")?)?;
    if object.get("host")?.as_str()? != "127.0.0.1" {
        return None;
    }
    let port = object.get("port")?.as_u64()?;
    if !(1..=65535).contains(&port) {
        return None;
    }
    let token = object.get("token")?.as_str()?;
    if token.len() < 20 {
        return None;
    }
    let document_generation = non_negative_u64(object.get("document_generation")?)?;
    let current_file = match object.get("current_file")? {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        _ => return None,
    };
    let cutter_version = match object.get("cutter_version")? {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        _ => return None,
    };
    if object.get("identity_status")?.as_str()? != "partial" {
        return None;
    }
    Some(Descriptor {
        session_id: session_id.to_owned(),
        pid,
        port: port as u16,
        token: token.to_owned(),
        document_generation,
        current_file,
        cutter_version,
    })
}

fn is_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok()
}

fn positive_u64(value: &serde_json::Value) -> Option<u64> {
    let parsed = integer_u64(value)?;
    (parsed > 0).then_some(parsed)
}

fn non_negative_u64(value: &serde_json::Value) -> Option<u64> {
    integer_u64(value)
}

fn integer_u64(value: &serde_json::Value) -> Option<u64> {
    if let Some(unsigned) = value.as_u64() {
        return Some(unsigned);
    }
    // Accept integral floats, rejecting fractional values.
    let float = value.as_f64()?;
    if float.fract() == 0.0 && float >= 0.0 && float <= u64::MAX as f64 {
        Some(float as u64)
    } else {
        None
    }
}

fn read_bounded(path: &Path, max: u64) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).ok()?;
    let mut limited = file.take(max + 1);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > max {
        return None;
    }
    Some(bytes)
}

fn descriptor_name_pattern() -> regex::Regex {
    // `/^cutter-\d+-[0-9a-f-]{36}\.json$/iu`
    regex::Regex::new(r"(?i)^cutter-\d+-[0-9a-f-]{36}\.json$").expect("static pattern compiles")
}

/// `resolveBridgeDirectory`.
fn resolve_bridge_directory(
    configured: Option<&str>,
    local_app_data: Option<&str>,
    home_directory: &str,
) -> PathBuf {
    if let Some(configured) = configured {
        if !configured.is_empty() {
            if configured == "~" {
                return PathBuf::from(home_directory);
            }
            if let Some(rest) = configured.strip_prefix("~/") {
                return Path::new(home_directory).join(rest);
            }
            // The Windows `~\` branch is POSIX-inert; this build is POSIX.
            return PathBuf::from(configured);
        }
    }
    // POSIX default (`~/.cache/rea/cutter-bridge`). The Windows LOCALAPPDATA
    // branch (`LOCALAPPDATA/REA/CutterBridge`) is preserved for completeness.
    if cfg!(windows) {
        if let Some(local_app_data) = local_app_data {
            if !local_app_data.is_empty() {
                return Path::new(local_app_data).join("REA").join("CutterBridge");
            }
        }
    }
    let _ = local_app_data;
    Path::new(home_directory)
        .join(".cache")
        .join("rea")
        .join("cutter-bridge")
}

/// `homeDirectoryFromEnvironment` for POSIX; HOME then USERPROFILE, falling
/// back to the host account's home.
fn home_directory_from_environment(environment: &HashMap<String, String>) -> String {
    let first_nonempty = |keys: &[&str]| -> Option<String> {
        for key in keys {
            if let Some(value) = environment.get(*key) {
                if !value.is_empty() {
                    return Some(value.clone());
                }
            }
        }
        None
    };
    if cfg!(windows) {
        let windows_drive_home = match (environment.get("HOMEDRIVE"), environment.get("HOMEPATH")) {
            (Some(drive), Some(path)) if !drive.is_empty() && !path.is_empty() => {
                Some(format!("{drive}{path}"))
            }
            _ => None,
        };
        if let Some(value) = environment
            .get("USERPROFILE")
            .filter(|value| !value.is_empty())
        {
            return value.clone();
        }
        if let Some(value) = windows_drive_home {
            return value;
        }
        if let Some(value) = first_nonempty(&["HOME"]) {
            return value;
        }
    } else if let Some(value) = first_nonempty(&["HOME", "USERPROFILE"]) {
        return value;
    }
    host_account_home().unwrap_or_default()
}

/// Host account home directory (`os.userInfo().homedir`).
///
/// The oracle's final fallback consults the host account record when neither
/// HOME nor USERPROFILE is set. Resolving the passwd record would require
/// `unsafe` FFI (`getpwuid`), which the workspace lint forbids for this crate;
/// that last-resort branch is therefore not reproduced and discovery with no
/// home environment resolves against an empty base (a benign
/// `no_live_bridge_found`). In every exercised configuration HOME is set, so
/// this branch is unreachable. Reported as a deviation.
fn host_account_home() -> Option<String> {
    None
}

#[cfg(unix)]
fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}
