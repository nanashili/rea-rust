//! Owned Frida sessions and scripts.
//!
//! Port of `src/frida/FridaInstrumentationManager.ts`: ManagedSession/Script
//! state, one coarse lock serializing session operations, startup cleanup on a
//! failed start, remote reference counting with an options digest,
//! resume-after-detach, the close order (release scripts → detach → re-release
//! → resume paused spawn → release remote) and `close_all`.
//!
//! The TS provider is asynchronous and serializes per session with a promise
//! queue; the native handler model runs each call synchronously on a worker
//! thread and the FFI [`ffi::Runtime`] already serializes every frida-core call
//! on its owned thread, so a single `Mutex<State>` reproduces the observable
//! ordering without a per-session queue.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::capture::{
    MAX_BINARY_MESSAGE_BYTES, MAX_MESSAGE_METADATA_BYTES, MAX_MESSAGE_TEXT_BYTES,
    MAX_MESSAGE_TYPE_BYTES, MAX_SESSION_CAPTURE_BYTES, bounded_json_value, bounded_redacted_string,
    serialized_len,
};
use super::ffi::{
    Certificate, Device, DeviceManager, FfiError, RemoteOptions, Runtime, Script, ScriptMessage,
    Session,
};

const DEVICE_LOOKUP_TIMEOUT_MS: i32 = 1_000;
/// Idle gap that ends a post-load message drain; a live script delivers its
/// startup burst within this window.
const DRAIN_IDLE_MS: u64 = 300;
const DRAIN_CAP: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Caller-facing inputs and observations.

/// A remote Frida endpoint and its connection options.
#[derive(Clone, Debug, Default)]
pub(crate) struct Remote {
    pub address: String,
    pub token: Option<String>,
    pub certificate: Option<String>,
    pub origin: Option<String>,
    pub keepalive_interval: Option<i64>,
}

impl Remote {
    fn secrets(&self) -> Vec<String> {
        [self.token.clone(), self.certificate.clone()]
            .into_iter()
            .flatten()
            .filter(|value| !value.is_empty())
            .collect()
    }

    fn options(&self) -> RemoteOptions {
        RemoteOptions {
            token: self.token.clone(),
            certificate: self.certificate.clone().map(|value| {
                if value.contains('\n') {
                    Certificate::Pem(value)
                } else {
                    Certificate::File(value.into())
                }
            }),
            origin: self.origin.clone(),
            keepalive_interval: self.keepalive_interval.and_then(|v| i32::try_from(v).ok()),
        }
    }

    /// `createHash("sha256").update(JSON.stringify(remoteOptions(remote)))`.
    fn options_digest(&self) -> String {
        let mut map = Map::new();
        if let Some(token) = &self.token {
            map.insert("token".into(), json!(token));
        }
        if let Some(cert) = &self.certificate {
            map.insert("certificate".into(), json!(cert));
        }
        if let Some(origin) = &self.origin {
            map.insert("origin".into(), json!(origin));
        }
        if let Some(interval) = self.keepalive_interval {
            map.insert("keepaliveInterval".into(), json!(interval));
        }
        let text = serde_json::to_string(&Value::Object(map)).unwrap_or_default();
        hex(&Sha256::digest(text.as_bytes()))
    }
}

/// A device selector: `device_id` or `remote`.
#[derive(Clone, Debug, Default)]
pub(crate) struct Selector {
    pub device_id: Option<String>,
    pub remote: Option<Remote>,
}

/// `StartFridaSessionInput`.
#[derive(Clone, Debug)]
pub(crate) struct StartInput {
    pub selector: Selector,
    pub mode: Mode,
    pub pid: Option<u32>,
    pub program: Option<String>,
    pub argv: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Attach,
    Spawn,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Spawn => "spawn",
        }
    }
}

/// `FridaScriptSource`.
#[derive(Clone, Debug)]
pub(crate) enum ScriptSource {
    Inline(String),
    File(String),
}

#[derive(Clone, Debug)]
pub(crate) struct SourceRepresentation {
    pub loaded_source_sha256: String,
}

/// `FridaSessionObservation`.
#[derive(Clone, Debug)]
pub(crate) struct SessionObservation {
    pub session_id: String,
    pub device_id: String,
    pub target: String,
    pub pid: u32,
    pub mode: Mode,
    pub state: &'static str,
}

/// `FridaScriptObservation`.
#[derive(Clone, Debug)]
pub(crate) struct ScriptObservation {
    pub script_id: String,
    pub source_kind: &'static str,
    pub source_path: Option<String>,
    pub source_sha256: String,
    pub source_representation: Option<SourceRepresentation>,
    pub messages: Vec<Value>,
    pub messages_truncated: bool,
}

/// `FridaSessionStatus`.
#[derive(Clone, Debug)]
pub(crate) struct SessionStatus {
    pub session: SessionObservation,
    pub target_resume_observed: bool,
    pub scripts: Vec<(String, String)>,
    pub messages: Vec<Value>,
    pub messages_truncated: bool,
}

// ---------------------------------------------------------------------------
// Internal managed state.

#[derive(PartialEq, Eq)]
enum ScriptState {
    Active,
    CleanupPending,
    Released,
}

struct ManagedScript {
    id: String,
    name: String,
    script: Script,
    state: ScriptState,
}

struct ScriptCapture {
    messages: Vec<Value>,
    truncated: bool,
}

struct CapturedMessage {
    observation: Value,
    script_id: String,
    charge: usize,
}

struct ManagedSession {
    id: String,
    device: Arc<Device>,
    device_id: String,
    session: Session,
    target: String,
    pid: u32,
    mode: Mode,
    remote: Option<Remote>,
    remote_reference_held: bool,
    remote_removal_pending: bool,
    scripts: Vec<ManagedScript>,
    script_captures: HashMap<String, ScriptCapture>,
    messages: Vec<CapturedMessage>,
    captured_bytes: usize,
    detached: bool,
    target_resume_observed: bool,
    resume_after_detach_pending: bool,
    messages_truncated: bool,
}

struct RemoteRef {
    references: usize,
    options_digest: String,
    device: Arc<Device>,
    redaction_secrets: Vec<String>,
}

struct Backend {
    rt: Arc<Runtime>,
    dm: Arc<DeviceManager>,
}

/// Resources acquired while session startup is still being rolled back.
///
/// This remains in `State` when an individual rollback call fails so a later
/// shutdown can retry the operation without losing the owner of the resource.
struct PendingStartup {
    session: Option<Session>,
    device: Arc<Device>,
    spawned_pid: Option<u32>,
    remote: Option<Remote>,
    remote_reference_held: bool,
}

#[derive(Default)]
struct State {
    backend: Option<Backend>,
    sessions: HashMap<String, ManagedSession>,
    pending_startups: HashMap<String, PendingStartup>,
    remotes: HashMap<String, RemoteRef>,
    closing: bool,
}

/// `FridaInstrumentationManager`.
#[derive(Default)]
pub(crate) struct Manager {
    state: Mutex<State>,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn uuid() -> String {
    Uuid::new_v4().to_string()
}

/// `sanitizeError`.
fn sanitize(error: &FfiError, secrets: &[String]) -> String {
    bounded_redacted_string(&error.to_string(), 4096, secrets).value
}

/// `providerError`.
fn provider_error(
    operation: &str,
    error: &FfiError,
    secrets: &[String],
    cleanup: Option<String>,
) -> AnalysisError {
    if matches!(error, FfiError::Cancelled) {
        let mut built = AnalysisError::cancelled(operation);
        if let Some(reason) = cleanup {
            built = built.with_cleanup(reason, vec!["Frida provider operation".to_owned()]);
        }
        return built;
    }
    let reason = sanitize(error, secrets);
    let mut built = AnalysisError::capability_unavailable("frida", operation, reason);
    if let Some(reason) = cleanup {
        built = built.with_cleanup(reason, vec!["Frida provider operation".to_owned()]);
    }
    built
}

/// `unknownFridaSession` for handlers that resolve state without the manager.
pub(crate) fn unknown_session_error(operation: &str, session_id: &str) -> AnalysisError {
    unknown_session(operation, session_id)
}

fn unknown_session(operation: &str, session_id: &str) -> AnalysisError {
    AnalysisError::input(
        operation,
        vec![InputIssue::new(
            &["session_id"],
            "invalid_value",
            format!("No open Frida session {session_id}; start one with start_frida_session."),
        )],
    )
}

fn unknown_script(operation: &str, script_id: &str) -> AnalysisError {
    AnalysisError::input(
        operation,
        vec![InputIssue::new(
            &["script_id"],
            "invalid_value",
            format!("No loaded Frida script {script_id} in this session."),
        )],
    )
}

impl Manager {
    fn backend(state: &mut State, operation: &str) -> Result<Backend, AnalysisError> {
        if state.backend.is_none() {
            let rt = Runtime::start().map_err(|error| {
                AnalysisError::capability_unavailable("frida", operation, error.to_string())
            })?;
            let dm = DeviceManager::new(&rt).map_err(|error| {
                AnalysisError::capability_unavailable("frida", operation, error.to_string())
            })?;
            state.backend = Some(Backend {
                rt,
                dm: Arc::new(dm),
            });
        }
        let backend = state.backend.as_ref().expect("backend set above");
        Ok(Backend {
            rt: Arc::clone(&backend.rt),
            dm: Arc::clone(&backend.dm),
        })
    }

    /// `#selectDevice`: a retained remote device, or `getDeviceById`.
    fn select_device(
        state: &mut State,
        operation: &str,
        selector: &Selector,
    ) -> Result<(Arc<Device>, bool), AnalysisError> {
        let backend = Self::backend(state, operation)?;
        if let Some(remote) = &selector.remote {
            let device = Self::retain_remote(state, operation, &backend, remote)?;
            return Ok((device, true));
        }
        let id = selector
            .device_id
            .clone()
            .unwrap_or_else(|| "local".to_owned());
        let cancel = backend
            .rt
            .cancellable()
            .map_err(|error| provider_error(operation, &error, &[], None))?;
        let device = backend
            .dm
            .get_device_by_id(&id, DEVICE_LOOKUP_TIMEOUT_MS, &cancel)
            .map_err(|error| provider_error(operation, &error, &[], None))?;
        Ok((Arc::new(device), false))
    }

    /// `#retainRemote`.
    fn retain_remote(
        state: &mut State,
        operation: &str,
        backend: &Backend,
        remote: &Remote,
    ) -> Result<Arc<Device>, AnalysisError> {
        let digest = remote.options_digest();
        if let Some(reference) = state.remotes.get_mut(&remote.address) {
            if reference.options_digest != digest {
                return Err(AnalysisError::input(
                    "frida_remote_connection",
                    vec![InputIssue::new(
                        &["remote"],
                        "invalid_value",
                        "This endpoint is already retained with different connection options. Reuse the existing options or close its sessions before changing them.",
                    )],
                ));
            }
            reference.references += 1;
            return Ok(Arc::clone(&reference.device));
        }
        let cancel = backend
            .rt
            .cancellable()
            .map_err(|error| provider_error(operation, &error, &remote.secrets(), None))?;
        let device = backend
            .dm
            .add_remote_device(&remote.address, &remote.options(), &cancel)
            .map_err(|error| provider_error(operation, &error, &remote.secrets(), None))?;
        let device = Arc::new(device);
        state.remotes.insert(
            remote.address.clone(),
            RemoteRef {
                references: 1,
                options_digest: digest,
                device: Arc::clone(&device),
                redaction_secrets: remote.secrets(),
            },
        );
        Ok(device)
    }

    /// `#releaseRemote`.
    fn release_remote(
        state: &mut State,
        operation: &str,
        address: &str,
        release_reference: bool,
        secrets: &[String],
    ) -> Result<(), AnalysisError> {
        let backend = Self::backend(state, operation)?;
        let Some(reference) = state.remotes.get_mut(address) else {
            return Ok(());
        };
        if release_reference {
            reference.references = reference.references.saturating_sub(1);
        }
        if reference.references > 0 {
            return Ok(());
        }
        let cancel = backend
            .rt
            .cancellable()
            .map_err(|error| provider_error(operation, &error, secrets, None))?;
        let result = backend.dm.remove_remote_device(address, &cancel);
        match result {
            Ok(()) => {
                state.remotes.remove(address);
                Ok(())
            }
            Err(error) => Err(provider_error(operation, &error, secrets, None)),
        }
    }

    fn release_held_remote(
        state: &mut State,
        operation: &str,
        remote: Option<&Remote>,
        held: bool,
        secrets: &[String],
    ) -> Option<String> {
        if !held {
            return None;
        }
        let Some(remote) = remote else {
            return Some("Frida remote ownership is missing its endpoint".to_owned());
        };
        Self::release_remote(state, operation, &remote.address, true, secrets)
            .err()
            .map(|cause| cause.message())
    }

    // -------------------------------------------------------------------
    // list_frida_devices

    pub(crate) fn list_devices(
        &self,
        remote: Option<Remote>,
    ) -> Result<(Vec<(String, String, String)>, Option<String>), AnalysisError> {
        const OP: &str = "list_frida_devices";
        let mut state = self.lock();
        let backend = Self::backend(&mut state, OP)?;
        let secrets = remote.as_ref().map(Remote::secrets).unwrap_or_default();
        let mut remote_held = false;
        if let Some(remote) = &remote {
            Self::retain_remote(&mut state, OP, &backend, remote)?;
            remote_held = true;
        }
        let cancel = match backend.rt.cancellable() {
            Ok(cancel) => cancel,
            Err(error) => {
                let cleanup = Self::release_held_remote(
                    &mut state,
                    OP,
                    remote.as_ref(),
                    remote_held,
                    &secrets,
                );
                return Err(provider_error(OP, &error, &secrets, cleanup));
            }
        };
        let devices = match backend.dm.enumerate_devices(&cancel) {
            Ok(devices) => devices,
            Err(error) => {
                let cleanup = Self::release_held_remote(
                    &mut state,
                    OP,
                    remote.as_ref(),
                    remote_held,
                    &secrets,
                );
                return Err(provider_error(OP, &error, &secrets, cleanup));
            }
        };
        let mut described = Vec::with_capacity(devices.len());
        for device in &devices {
            match device.describe() {
                Ok(description) => described.push(description),
                Err(error) => {
                    let cleanup = Self::release_held_remote(
                        &mut state,
                        OP,
                        remote.as_ref(),
                        remote_held,
                        &secrets,
                    );
                    return Err(provider_error(OP, &error, &secrets, cleanup));
                }
            }
        }
        let cleanup_error =
            Self::release_held_remote(&mut state, OP, remote.as_ref(), remote_held, &secrets);
        Ok((described, cleanup_error))
    }

    // -------------------------------------------------------------------
    // list_frida_processes

    pub(crate) fn list_processes(
        &self,
        selector: Selector,
    ) -> Result<(String, Vec<(u32, String)>, Option<String>), AnalysisError> {
        const OP: &str = "list_frida_processes";
        let mut state = self.lock();
        let secrets = selector
            .remote
            .as_ref()
            .map(Remote::secrets)
            .unwrap_or_default();
        let (device, remote_held) = Self::select_device(&mut state, OP, &selector)?;
        let device_id = match device.describe() {
            Ok((device_id, _, _)) => device_id,
            Err(error) => {
                let cleanup = Self::release_held_remote(
                    &mut state,
                    OP,
                    selector.remote.as_ref(),
                    remote_held,
                    &secrets,
                );
                return Err(provider_error(OP, &error, &secrets, cleanup));
            }
        };
        let cancel = {
            let backend = match Self::backend(&mut state, OP) {
                Ok(backend) => backend,
                Err(error) => {
                    let cleanup = Self::release_held_remote(
                        &mut state,
                        OP,
                        selector.remote.as_ref(),
                        remote_held,
                        &secrets,
                    );
                    return Err(match cleanup {
                        Some(reason) => error
                            .with_cleanup(reason, vec!["Frida remote device reference".to_owned()]),
                        None => error,
                    });
                }
            };
            match backend.rt.cancellable() {
                Ok(cancel) => cancel,
                Err(error) => {
                    let cleanup = Self::release_held_remote(
                        &mut state,
                        OP,
                        selector.remote.as_ref(),
                        remote_held,
                        &secrets,
                    );
                    return Err(provider_error(OP, &error, &secrets, cleanup));
                }
            }
        };
        let processes = match device.enumerate_processes(&cancel) {
            Ok(processes) => processes,
            Err(error) => {
                let cleanup = Self::release_held_remote(
                    &mut state,
                    OP,
                    selector.remote.as_ref(),
                    remote_held,
                    &secrets,
                );
                return Err(provider_error(OP, &error, &secrets, cleanup));
            }
        };
        let cleanup_error = Self::release_held_remote(
            &mut state,
            OP,
            selector.remote.as_ref(),
            remote_held,
            &secrets,
        );
        let processes = processes
            .into_iter()
            .map(|process| (process.pid, process.name))
            .collect();
        Ok((device_id, processes, cleanup_error))
    }

    // -------------------------------------------------------------------
    // start_frida_session

    pub(crate) fn start_session(
        &self,
        input: StartInput,
    ) -> Result<SessionObservation, AnalysisError> {
        const OP: &str = "start_frida_session";
        let mut state = self.lock();
        let secrets = input
            .selector
            .remote
            .as_ref()
            .map(Remote::secrets)
            .unwrap_or_default();
        let backend = Self::backend(&mut state, OP)?;
        let (device, remote_held) = Self::select_device(&mut state, OP, &input.selector)?;
        let pending_id = uuid();
        let mut pending = PendingStartup {
            session: None,
            device: Arc::clone(&device),
            spawned_pid: None,
            remote: input.selector.remote.clone(),
            remote_reference_held: remote_held,
        };
        let cancel = match backend.rt.cancellable() {
            Ok(cancel) => cancel,
            Err(error) => {
                state.pending_startups.insert(pending_id.clone(), pending);
                let failures = self.retry_pending_startup(&mut state, &pending_id, OP, &secrets);
                let cleanup = (!failures.is_empty()).then(|| failures.join("; "));
                return Err(provider_error(OP, &error, &secrets, cleanup));
            }
        };

        match Self::acquire_session(&mut pending, &input, &cancel) {
            Ok(managed) => {
                let observation = session_observation(&managed);
                state.sessions.insert(managed.id.clone(), managed);
                Ok(observation)
            }
            Err(error) => {
                state.pending_startups.insert(pending_id.clone(), pending);
                let failures = self.retry_pending_startup(&mut state, &pending_id, OP, &secrets);
                let cleanup = (!failures.is_empty()).then(|| failures.join("; "));
                Err(provider_error(OP, &error, &secrets, cleanup))
            }
        }
    }

    fn acquire_session(
        pending: &mut PendingStartup,
        input: &StartInput,
        cancel: &super::ffi::Cancel,
    ) -> Result<ManagedSession, FfiError> {
        let (pid, target) = match input.mode {
            Mode::Attach => {
                let pid = input.pid.unwrap_or(0);
                let target = match pending.device.get_process_by_pid(pid, cancel) {
                    Ok(process) => format!("{} (pid {pid})", process.name),
                    Err(_) => format!("pid {pid}"),
                };
                (pid, target)
            }
            Mode::Spawn => {
                let program = input.program.clone().unwrap_or_default();
                let argv = input.argv.as_ref().map(|argv| {
                    let mut full = Vec::with_capacity(argv.len() + 1);
                    full.push(program.clone());
                    full.extend(argv.iter().cloned());
                    full
                });
                let pid = pending.device.spawn(&program, argv.as_deref(), cancel)?;
                pending.spawned_pid = Some(pid);
                (pid, program)
            }
        };

        pending.session = Some(pending.device.attach(pid, cancel)?);
        let (device_id, _, _) = pending.device.describe()?;
        let detached = pending
            .session
            .as_ref()
            .expect("attached session is retained during startup")
            .is_detached()?;
        Ok(ManagedSession {
            id: uuid(),
            device: Arc::clone(&pending.device),
            device_id,
            session: pending
                .session
                .take()
                .expect("attached session is retained during startup"),
            target,
            pid,
            mode: input.mode,
            remote: pending.remote.clone(),
            remote_reference_held: pending.remote_reference_held,
            remote_removal_pending: false,
            scripts: Vec::new(),
            script_captures: HashMap::new(),
            messages: Vec::new(),
            captured_bytes: 0,
            detached,
            target_resume_observed: false,
            resume_after_detach_pending: false,
            messages_truncated: false,
        })
    }

    fn retry_pending_startup(
        &self,
        state: &mut State,
        pending_id: &str,
        operation: &str,
        secrets: &[String],
    ) -> Vec<String> {
        let mut failures = Vec::new();
        let cancel = match Self::backend(state, operation).and_then(|backend| {
            backend
                .rt
                .cancellable()
                .map_err(|error| provider_error(operation, &error, secrets, None))
        }) {
            Ok(cancel) => Some(cancel),
            Err(error) => {
                failures.push(error.message());
                None
            }
        };

        if let Some(cancel) = cancel {
            let session_present = state
                .pending_startups
                .get(pending_id)
                .and_then(|pending| pending.session.as_ref())
                .is_some();
            if session_present {
                let detached = state
                    .pending_startups
                    .get(pending_id)
                    .and_then(|pending| pending.session.as_ref())
                    .expect("pending startup session is present")
                    .is_detached();
                match &detached {
                    Ok(true) => {
                        state
                            .pending_startups
                            .get_mut(pending_id)
                            .expect("pending startup exists")
                            .session = None;
                    }
                    Ok(false) | Err(_) => {
                        if let Err(error) = state
                            .pending_startups
                            .get(pending_id)
                            .and_then(|pending| pending.session.as_ref())
                            .expect("pending startup session is present")
                            .detach(&cancel)
                        {
                            failures.push(format!(
                                "Unable to detach partial Frida session: {}",
                                sanitize(&error, secrets)
                            ));
                        } else {
                            state
                                .pending_startups
                                .get_mut(pending_id)
                                .expect("pending startup exists")
                                .session = None;
                        }
                    }
                }
                if let Err(error) = &detached {
                    failures.push(format!(
                        "Unable to query partial Frida session state: {}",
                        sanitize(&error, secrets)
                    ));
                }
            }

            let spawned_pid = state
                .pending_startups
                .get(pending_id)
                .and_then(|pending| pending.spawned_pid);
            if let Some(pid) = spawned_pid {
                let device = Arc::clone(
                    &state
                        .pending_startups
                        .get(pending_id)
                        .expect("pending startup exists")
                        .device,
                );
                match device.resume(pid, &cancel) {
                    Ok(()) => {
                        state
                            .pending_startups
                            .get_mut(pending_id)
                            .expect("pending startup exists")
                            .spawned_pid = None;
                    }
                    Err(error) => failures.push(format!(
                        "Unable to resume spawned target: {}",
                        sanitize(&error, secrets)
                    )),
                }
            }
        }

        let release_remote = state
            .pending_startups
            .get(pending_id)
            .is_some_and(|pending| {
                pending.session.is_none()
                    && pending.spawned_pid.is_none()
                    && pending.remote_reference_held
            });
        if release_remote {
            let remote = state
                .pending_startups
                .get(pending_id)
                .and_then(|pending| pending.remote.clone())
                .expect("remote reference has an endpoint");
            match Self::release_remote(state, operation, &remote.address, true, secrets) {
                Ok(()) => {
                    state
                        .pending_startups
                        .get_mut(pending_id)
                        .expect("pending startup exists")
                        .remote_reference_held = false;
                }
                Err(error) => failures.push(error.message()),
            }
        }

        let complete = state
            .pending_startups
            .get(pending_id)
            .is_some_and(|pending| {
                pending.session.is_none()
                    && pending.spawned_pid.is_none()
                    && !pending.remote_reference_held
            });
        if complete {
            state.pending_startups.remove(pending_id);
        }
        failures
    }

    // -------------------------------------------------------------------
    // load_frida_script

    pub(crate) fn load_script(
        &self,
        session_id: &str,
        source: &ScriptSource,
    ) -> Result<ScriptObservation, AnalysisError> {
        const OP: &str = "load_frida_script";
        let mut state = self.lock();
        let rt = {
            let backend = Self::backend(&mut state, OP)?;
            backend.rt
        };
        let secrets = state
            .sessions
            .get(session_id)
            .and_then(|managed| managed.remote.as_ref().map(Remote::secrets))
            .unwrap_or_default();
        let detached = {
            let Some(managed) = state.sessions.get(session_id) else {
                return Err(unknown_session(OP, session_id));
            };
            managed.detached
                || managed
                    .session
                    .is_detached()
                    .map_err(|error| provider_error(OP, &error, &secrets, None))?
        };
        if detached {
            return Err(unknown_session(OP, session_id));
        }

        // Read + decode the source outside the frida boundary.
        let (script_source, source_sha256, source_representation) = match source {
            ScriptSource::Inline(text) => {
                let sha = hex(&Sha256::digest(text.as_bytes()));
                (text.clone(), sha, None)
            }
            ScriptSource::File(path) => match std::fs::read(path) {
                Ok(bytes) => {
                    let source_sha256 = hex(&Sha256::digest(&bytes));
                    match String::from_utf8(bytes.clone()) {
                        Ok(text) => (text, source_sha256, None),
                        Err(_) => {
                            let text = String::from_utf8_lossy(&bytes).into_owned();
                            let loaded = hex(&Sha256::digest(text.as_bytes()));
                            (
                                text,
                                source_sha256,
                                Some(SourceRepresentation {
                                    loaded_source_sha256: loaded,
                                }),
                            )
                        }
                    }
                }
                Err(cause) => {
                    return Err(match cause.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            AnalysisError::access_denied(OP, path, "EACCES")
                        }
                        _ => AnalysisError::input(
                            OP,
                            vec![InputIssue::new(
                                &["path"],
                                "invalid_value",
                                format!("Cannot read Frida script file {path}."),
                            )],
                        ),
                    });
                }
            },
        };

        let script_id = uuid();
        let name = format!("rea-{script_id}");
        let cancel = rt
            .cancellable()
            .map_err(|error| provider_error(OP, &error, &secrets, None))?;

        let create = {
            let managed = state.sessions.get(session_id).expect("checked above");
            managed
                .session
                .create_script(Some(&name), &script_source, &cancel)
        };
        let script = match create {
            Ok(script) => script,
            Err(error) => return Err(provider_error(OP, &error, &secrets, None)),
        };

        // Register before loading so a failed load retains the owner handle
        // and can be retried or explicitly released by close/unload.
        {
            let managed = state.sessions.get_mut(session_id).expect("checked above");
            managed.scripts.push(ManagedScript {
                id: script_id.clone(),
                name: name.clone(),
                script,
                state: ScriptState::CleanupPending,
            });
            managed.script_captures.insert(
                script_id.clone(),
                ScriptCapture {
                    messages: Vec::new(),
                    truncated: false,
                },
            );
        }

        let load_result = {
            let managed = state.sessions.get_mut(session_id).expect("checked above");
            managed
                .scripts
                .last()
                .expect("script was just registered")
                .script
                .load(&cancel)
        };
        if let Err(error) = load_result {
            let cleanup = self.release_script(&mut state, session_id, &script_id, false);
            return Err(provider_error(OP, &error, &secrets, cleanup));
        }
        state
            .sessions
            .get_mut(session_id)
            .expect("checked above")
            .scripts
            .last_mut()
            .expect("script was just registered")
            .state = ScriptState::Active;

        // Settle-drain the script's startup burst.
        self.drain_session(&mut state, session_id, &script_id, true);

        let managed = state.sessions.get(session_id).expect("checked above");
        let capture = managed.script_captures.get(&script_id);
        Ok(ScriptObservation {
            script_id: script_id.clone(),
            source_kind: source_kind(source),
            source_path: match source {
                ScriptSource::File(path) => Some(path.clone()),
                ScriptSource::Inline(_) => None,
            },
            source_sha256,
            source_representation,
            messages: capture.map(|c| c.messages.clone()).unwrap_or_default(),
            messages_truncated: capture.map(|c| c.truncated).unwrap_or(false),
        })
    }

    // -------------------------------------------------------------------
    // resume_frida_session

    pub(crate) fn resume_session(&self, session_id: &str) -> Result<(), AnalysisError> {
        const OP: &str = "resume_frida_session";
        let mut state = self.lock();
        let secrets = state
            .sessions
            .get(session_id)
            .and_then(|managed| managed.remote.as_ref().map(Remote::secrets))
            .unwrap_or_default();
        let detached = {
            let Some(managed) = state.sessions.get(session_id) else {
                return Err(unknown_session(OP, session_id));
            };
            managed.detached
                || managed
                    .session
                    .is_detached()
                    .map_err(|error| provider_error(OP, &error, &secrets, None))?
        };
        if detached {
            return Err(unknown_session(OP, session_id));
        }
        let managed = state.sessions.get(session_id).expect("checked above");
        if managed.mode != Mode::Spawn || managed.target_resume_observed {
            return Err(AnalysisError::capability_unavailable(
                "frida",
                OP,
                "Only a paused process spawned by this session can be resumed.",
            ));
        }
        let mut pending = Vec::new();
        for entry in &managed.scripts {
            if entry.state != ScriptState::CleanupPending {
                continue;
            }

            let destroyed = entry
                .script
                .is_destroyed()
                .map_err(|error| provider_error(OP, &error, &secrets, None))?;
            if !destroyed {
                pending.push(entry.id.clone());
            }
        }
        if !pending.is_empty() {
            let reason = "Frida script cleanup is incomplete; unload the retained scripts or close the session before resuming.";
            return Err(AnalysisError::capability_unavailable("frida", OP, reason)
                .with_cleanup(reason, pending));
        }
        let (pid, device) = (managed.pid, Arc::clone(&managed.device));
        let cancel = {
            let backend = Self::backend(&mut state, OP)?;
            backend
                .rt
                .cancellable()
                .map_err(|error| provider_error(OP, &error, &secrets, None))?
        };
        match device.resume(pid, &cancel) {
            Ok(()) => {
                let managed = state.sessions.get_mut(session_id).expect("checked above");
                managed.target_resume_observed = true;
                managed.resume_after_detach_pending = false;
                Ok(())
            }
            Err(error) => Err(provider_error(OP, &error, &secrets, None)),
        }
    }

    // -------------------------------------------------------------------
    // unload_frida_script

    pub(crate) fn unload_script(
        &self,
        session_id: &str,
        script_id: &str,
    ) -> Result<(), AnalysisError> {
        const OP: &str = "unload_frida_script";
        let mut state = self.lock();
        {
            let Some(managed) = state.sessions.get(session_id) else {
                return Err(unknown_session(OP, session_id));
            };
            if !managed.scripts.iter().any(|entry| entry.id == script_id) {
                return Err(unknown_script(OP, script_id));
            }
        }
        match self.release_script(&mut state, session_id, script_id, false) {
            None => Ok(()),
            Some(reason) => {
                let secrets = state
                    .sessions
                    .get(session_id)
                    .and_then(|m| m.remote.as_ref().map(Remote::secrets))
                    .unwrap_or_default();
                Err(provider_error(
                    OP,
                    &FfiError::Frida {
                        code: -1,
                        message: reason.clone(),
                    },
                    &secrets,
                    Some(reason),
                ))
            }
        }
    }

    // -------------------------------------------------------------------
    // frida_session_status

    pub(crate) fn status(&self, session_id: &str) -> Result<Option<SessionStatus>, AnalysisError> {
        let mut state = self.lock();
        if !state.sessions.contains_key(session_id) {
            return Ok(None);
        }
        let secrets = state.sessions[session_id]
            .remote
            .as_ref()
            .map(Remote::secrets)
            .unwrap_or_default();
        // Drain every script before snapshotting observed state.
        let script_ids: Vec<String> = state.sessions[session_id]
            .scripts
            .iter()
            .map(|entry| entry.id.clone())
            .collect();
        for id in &script_ids {
            self.drain_session(&mut state, session_id, id, false);
        }
        let managed = state.sessions.get_mut(session_id).expect("checked above");
        managed.detached |= managed
            .session
            .is_detached()
            .map_err(|error| provider_error("frida_session_status", &error, &secrets, None))?;
        let managed = state.sessions.get(session_id).expect("checked above");
        Ok(Some(SessionStatus {
            session: session_observation(managed),
            target_resume_observed: managed.target_resume_observed,
            scripts: managed
                .scripts
                .iter()
                .map(|entry| (entry.id.clone(), entry.name.clone()))
                .collect(),
            messages: managed
                .messages
                .iter()
                .map(|m| m.observation.clone())
                .collect(),
            messages_truncated: managed.messages_truncated,
        }))
    }

    // -------------------------------------------------------------------
    // close_frida_session

    pub(crate) fn close_session(&self, session_id: &str) -> Result<bool, AnalysisError> {
        let mut state = self.lock();
        self.close_session_locked(&mut state, session_id)
    }

    fn close_session_locked(
        &self,
        state: &mut State,
        session_id: &str,
    ) -> Result<bool, AnalysisError> {
        const OP: &str = "close_frida_session";
        if !state.sessions.contains_key(session_id) {
            return Err(unknown_session(OP, session_id));
        }
        let secrets = state.sessions[session_id]
            .remote
            .as_ref()
            .map(Remote::secrets)
            .unwrap_or_default();

        let mut cleanup_failures: Vec<String> = Vec::new();
        let (
            mode,
            remote,
            mut target_resume_observed,
            resume_after_detach_pending,
            resume_observed,
        ) = {
            let managed = state.sessions.get_mut(session_id).expect("checked");
            match managed.session.is_detached() {
                Ok(detached) => managed.detached |= detached,
                Err(error) => cleanup_failures.push(format!(
                    "Unable to query Frida session state: {}",
                    sanitize(&error, &secrets)
                )),
            }
            (
                managed.mode,
                managed.remote.clone(),
                managed.target_resume_observed,
                managed.resume_after_detach_pending,
                managed.target_resume_observed,
            )
        };
        let mut parent_released = state.sessions[session_id].detached;
        let should_resume = mode == Mode::Spawn
            && ((!parent_released && !resume_observed) || resume_after_detach_pending);

        let mut script_failures: HashMap<String, String> = HashMap::new();
        let script_ids: Vec<String> = state.sessions[session_id]
            .scripts
            .iter()
            .map(|e| e.id.clone())
            .collect();
        for id in &script_ids {
            if let Some(reason) = self.release_script(state, session_id, id, parent_released) {
                script_failures.insert(id.clone(), reason);
            }
        }

        // Detach the session.
        {
            let managed = state.sessions.get(session_id).expect("checked");
            let detached = match managed.session.is_detached() {
                Ok(detached) => detached,
                Err(error) => {
                    cleanup_failures.push(format!(
                        "Unable to query Frida session state: {}",
                        sanitize(&error, &secrets)
                    ));
                    false
                }
            };
            let device_rt_cancel = Self::backend(state, OP).and_then(|b| {
                b.rt.cancellable()
                    .map_err(|e| provider_error(OP, &e, &secrets, None))
            });
            match device_rt_cancel {
                Ok(cancel) => {
                    let managed = state.sessions.get(session_id).expect("checked");
                    let result = if detached {
                        Ok(())
                    } else {
                        managed.session.detach(&cancel)
                    };
                    match result {
                        Ok(()) => {
                            let managed = state.sessions.get_mut(session_id).expect("checked");
                            managed.detached = true;
                            parent_released = true;
                        }
                        Err(error) => {
                            cleanup_failures.push(format!(
                                "Unable to detach Frida session: {}",
                                sanitize(&error, &secrets)
                            ));
                            let managed = state.sessions.get_mut(session_id).expect("checked");
                            match managed.session.is_detached() {
                                Ok(detached) => managed.detached |= detached,
                                Err(cause) => cleanup_failures.push(format!(
                                    "Unable to query Frida session state after detach failure: {}",
                                    sanitize(&cause, &secrets)
                                )),
                            }
                            parent_released = managed.detached;
                        }
                    }
                }
                Err(error) => cleanup_failures.push(error.message()),
            }
        }

        if parent_released {
            let script_ids: Vec<String> = state.sessions[session_id]
                .scripts
                .iter()
                .map(|e| e.id.clone())
                .collect();
            for id in &script_ids {
                match self.release_script(state, session_id, id, true) {
                    None => {
                        script_failures.remove(id);
                    }
                    Some(reason) => {
                        script_failures.insert(id.clone(), reason);
                    }
                }
            }
        }

        if should_resume && state.sessions[session_id].scripts.is_empty() {
            let (pid, device) = {
                let managed = state.sessions.get(session_id).expect("checked");
                (managed.pid, Arc::clone(&managed.device))
            };
            let cancel = Self::backend(state, OP).and_then(|b| {
                b.rt.cancellable()
                    .map_err(|e| provider_error(OP, &e, &secrets, None))
            });
            match cancel.and_then(|cancel| {
                device
                    .resume(pid, &cancel)
                    .map_err(|e| provider_error(OP, &e, &secrets, None))
            }) {
                Ok(()) => {
                    let managed = state.sessions.get_mut(session_id).expect("checked");
                    managed.target_resume_observed = true;
                    managed.resume_after_detach_pending = false;
                    target_resume_observed = true;
                }
                Err(error) => {
                    let managed = state.sessions.get_mut(session_id).expect("checked");
                    managed.resume_after_detach_pending = true;
                    cleanup_failures.push(format!(
                        "Unable to resume spawned target: {}",
                        error.message()
                    ));
                }
            }
        }

        let mut failures: Vec<String> = script_failures.into_values().collect();
        failures.extend(cleanup_failures);

        // Release the retained remote when the session is fully torn down.
        let release_remote = remote.is_some() && {
            let managed = state.sessions.get(session_id).expect("checked");
            (managed.remote_reference_held || managed.remote_removal_pending)
                && parent_released
                && managed.scripts.is_empty()
                && !managed.resume_after_detach_pending
        };
        if release_remote {
            if let Some(remote) = &remote {
                let release_reference = state.sessions[session_id].remote_reference_held;
                {
                    let managed = state.sessions.get_mut(session_id).expect("checked");
                    managed.remote_reference_held = false;
                }
                match Self::release_remote(state, OP, &remote.address, release_reference, &secrets)
                {
                    Ok(()) => {
                        let managed = state.sessions.get_mut(session_id).expect("checked");
                        managed.remote_removal_pending = false;
                    }
                    Err(cause) => {
                        let managed = state.sessions.get_mut(session_id).expect("checked");
                        managed.remote_removal_pending = true;
                        failures.push(format!(
                            "Unable to close remote Frida connection: {}",
                            cause.message()
                        ));
                    }
                }
            }
        }

        if !failures.is_empty() {
            let reason = failures.join("; ");
            return Err(AnalysisError::capability_unavailable(
                "frida",
                OP,
                failures.first().cloned().unwrap_or_default(),
            )
            .with_cleanup(reason, vec![session_id.to_owned()]));
        }
        state.sessions.remove(session_id);
        Ok(target_resume_observed)
    }

    /// `#releaseScript`.
    fn release_script(
        &self,
        state: &mut State,
        session_id: &str,
        script_id: &str,
        parent_released: bool,
    ) -> Option<String> {
        // Drain outstanding messages before releasing the handle.
        self.drain_session(state, session_id, script_id, false);
        let secrets = state
            .sessions
            .get(session_id)
            .and_then(|m| m.remote.as_ref().map(Remote::secrets))
            .unwrap_or_default();
        let managed = state.sessions.get_mut(session_id)?;
        let position = managed.scripts.iter().position(|e| e.id == script_id)?;
        let is_destroyed = match managed.scripts[position].script.is_destroyed() {
            Ok(is_destroyed) => is_destroyed,
            Err(error) => return Some(sanitize(&error, &secrets)),
        };
        if parent_released || is_destroyed {
            managed.scripts[position].state = ScriptState::Released;
        }
        if managed.scripts[position].state != ScriptState::Released {
            managed.scripts[position].state = ScriptState::CleanupPending;
            let cancel = match Self::backend(state, "unload_frida_script") {
                Ok(backend) => match backend.rt.cancellable() {
                    Ok(cancel) => cancel,
                    Err(error) => return Some(sanitize(&error, &secrets)),
                },
                Err(error) => return Some(error.message()),
            };
            let managed = state.sessions.get_mut(session_id)?;
            let entry = &mut managed.scripts[position];
            match entry.script.unload(&cancel) {
                Ok(()) => entry.state = ScriptState::Released,
                Err(error) => match entry.script.is_destroyed() {
                    Ok(true) => entry.state = ScriptState::Released,
                    Ok(false) => return Some(sanitize(&error, &secrets)),
                    Err(state_error) => {
                        return Some(format!(
                            "{}; unable to query script state: {}",
                            sanitize(&error, &secrets),
                            sanitize(&state_error, &secrets)
                        ));
                    }
                },
            }
        }
        // Dropping the ManagedScript disconnects the message handler.
        let managed = state.sessions.get_mut(session_id)?;
        managed.scripts.remove(position);
        managed.script_captures.remove(script_id);
        None
    }

    // -------------------------------------------------------------------
    // close_all

    pub(crate) fn close_all(&self) -> Result<(), AnalysisError> {
        let mut state = self.lock();
        state.closing = true;
        let session_ids: Vec<String> = state.sessions.keys().cloned().collect();
        let mut failures: Vec<String> = Vec::new();
        for id in session_ids {
            if let Err(error) = self.close_session_locked(&mut state, &id) {
                failures.push(error.message());
            }
        }
        let pending_ids: Vec<String> = state.pending_startups.keys().cloned().collect();
        for id in pending_ids {
            let secrets = state
                .pending_startups
                .get(&id)
                .and_then(|pending| pending.remote.as_ref())
                .map(Remote::secrets)
                .unwrap_or_default();
            let pending_failures =
                self.retry_pending_startup(&mut state, &id, "close_frida_session", &secrets);
            failures.extend(pending_failures);
            if state.pending_startups.contains_key(&id) {
                failures.push("Pending Frida startup cleanup remains owned".to_owned());
            }
        }
        let addresses: Vec<(String, usize, Vec<String>)> = state
            .remotes
            .iter()
            .map(|(address, reference)| {
                (
                    address.clone(),
                    reference.references,
                    reference.redaction_secrets.clone(),
                )
            })
            .collect();
        for (address, references, secrets) in addresses {
            if references != 0 {
                continue;
            }
            if let Err(cause) =
                Self::release_remote(&mut state, "close_frida_session", &address, false, &secrets)
            {
                failures.push(format!(
                    "Unable to close remote Frida connection during shutdown: {}",
                    cause.message()
                ));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            let reason = format!(
                "Frida session cleanup was incomplete: {}",
                failures.join("; ")
            );
            Err(AnalysisError::capability_unavailable(
                "frida",
                "close_frida_session",
                reason.clone(),
            )
            .with_cleanup(reason, Vec::new()))
        }
    }

    // -------------------------------------------------------------------
    // Message capture

    /// Collect a script's pending messages and record them. When `settle` is
    /// set, keep waiting through the startup idle gap; otherwise drain only
    /// what is already queued.
    fn drain_session(&self, state: &mut State, session_id: &str, script_id: &str, settle: bool) {
        let raws = {
            let Some(managed) = state.sessions.get(session_id) else {
                return;
            };
            let Some(entry) = managed.scripts.iter().find(|e| e.id == script_id) else {
                return;
            };
            collect_raw(entry.script.messages(), settle)
        };
        if raws.is_empty() {
            return;
        }
        let secrets = state
            .sessions
            .get(session_id)
            .and_then(|m| m.remote.as_ref().map(Remote::secrets))
            .unwrap_or_default();
        for raw in raws {
            if let Some(managed) = state.sessions.get_mut(session_id) {
                record_message(managed, script_id, raw, &secrets);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn source_kind(source: &ScriptSource) -> &'static str {
    match source {
        ScriptSource::Inline(_) => "inline",
        ScriptSource::File(_) => "file",
    }
}

fn session_observation(managed: &ManagedSession) -> SessionObservation {
    SessionObservation {
        session_id: managed.id.clone(),
        device_id: managed.device_id.clone(),
        target: managed.target.clone(),
        pid: managed.pid,
        mode: managed.mode,
        state: session_state(managed),
    }
}

/// `sessionState`.
fn session_state(managed: &ManagedSession) -> &'static str {
    if managed.detached {
        "detached"
    } else if managed.mode == Mode::Spawn && !managed.target_resume_observed {
        "paused"
    } else {
        "running"
    }
}

/// Pull queued messages from a script receiver.
fn collect_raw(
    receiver: &std::sync::mpsc::Receiver<ScriptMessage>,
    settle: bool,
) -> Vec<ScriptMessage> {
    let mut out = Vec::new();
    let deadline = Instant::now() + DRAIN_CAP;
    loop {
        let timeout = if settle {
            Duration::from_millis(DRAIN_IDLE_MS)
        } else {
            Duration::from_millis(0)
        };
        match receiver.recv_timeout(timeout) {
            Ok(message) => out.push(message),
            Err(_) => break,
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    out
}

/// `#recordMessage`: build the bounded, redacted observation and charge it
/// against the session capture budget, evicting oldest on overflow.
fn record_message(
    managed: &mut ManagedSession,
    script_id: &str,
    raw: ScriptMessage,
    secrets: &[String],
) {
    let Ok(parsed) = serde_json::from_str::<Value>(&raw.json) else {
        return;
    };
    let message_type = parsed.get("type").and_then(Value::as_str).unwrap_or("");
    // Drop frida's internal rpc and log messages, matching the npm binding's
    // `handleMessageIntercept` (these never reach `message` listeners).
    if message_type == "log" {
        return;
    }
    let payload = parsed.get("payload");
    if message_type == "send" {
        if let Some(Value::Array(items)) = payload {
            if items.first().and_then(Value::as_str) == Some("frida:rpc") {
                return;
            }
        }
    }

    let mut payload_result: Option<(Value, bool, usize)> = None;
    if let Some(payload) = payload {
        let bounded = bounded_json_value(
            payload,
            MAX_SESSION_CAPTURE_BYTES - MAX_MESSAGE_METADATA_BYTES,
            secrets,
        );
        if bounded.truncated {
            mark_truncated(managed, script_id);
        }
        payload_result = Some((bounded.value, bounded.truncated, bounded.bytes));
    }

    let mut binary: Map<String, Value> = Map::new();
    if let Some(data) = &raw.data {
        let payload_bytes = payload_result.as_ref().map(|(_, _, b)| *b).unwrap_or(0);
        let remaining = MAX_SESSION_CAPTURE_BYTES
            .saturating_sub(MAX_MESSAGE_METADATA_BYTES)
            .saturating_sub(payload_bytes)
            .saturating_sub(4096);
        let limit = MAX_BINARY_MESSAGE_BYTES.min(remaining / 4 * 3);
        if secrets
            .iter()
            .any(|secret| contains_subslice(data, secret.as_bytes()))
        {
            binary.insert("data_redacted".into(), Value::Bool(true));
        } else if data.len() > limit {
            binary.insert("data_truncated".into(), Value::Bool(true));
            binary.insert("data_bytes".into(), json!(data.len()));
            mark_truncated(managed, script_id);
        } else {
            use base64::Engine as _;
            use base64::engine::general_purpose::STANDARD as BASE64;
            binary.insert("data_base64".into(), json!(BASE64.encode(data)));
        }
    }

    let type_bounded = bounded_redacted_string(message_type, MAX_MESSAGE_TYPE_BYTES, secrets);
    let description = text_field(&parsed, "description", secrets);
    let stack = text_field(&parsed, "stack", secrets);
    let file_name = text_field(&parsed, "fileName", secrets);
    if type_bounded.truncated
        || description.as_ref().is_some_and(|(_, t)| *t)
        || stack.as_ref().is_some_and(|(_, t)| *t)
        || file_name.as_ref().is_some_and(|(_, t)| *t)
    {
        mark_truncated(managed, script_id);
    }

    let mut observation = Map::new();
    observation.insert("script_id".into(), json!(script_id));
    observation.insert("type".into(), json!(type_bounded.value));
    if type_bounded.truncated {
        observation.insert("type_truncated".into(), Value::Bool(true));
    }
    if let Some((value, truncated, _)) = payload_result {
        observation.insert("payload".into(), value);
        if truncated {
            observation.insert("payload_truncated".into(), Value::Bool(true));
        }
    }
    if let Some((value, truncated)) = description {
        observation.insert("description".into(), json!(value));
        if truncated {
            observation.insert("description_truncated".into(), Value::Bool(true));
        }
    }
    if let Some((value, truncated)) = stack {
        observation.insert("stack".into(), json!(value));
        if truncated {
            observation.insert("stack_truncated".into(), Value::Bool(true));
        }
    }
    if let Some((value, truncated)) = file_name {
        observation.insert("file_name".into(), json!(value));
        if truncated {
            observation.insert("file_name_truncated".into(), Value::Bool(true));
        }
    }
    if let Some(line) = safe_index(&parsed, "lineNumber") {
        observation.insert("line_number".into(), json!(line));
    }
    if let Some(column) = safe_index(&parsed, "columnNumber") {
        observation.insert("column_number".into(), json!(column));
    }
    for (key, value) in binary {
        observation.insert(key, value);
    }

    let observation = Value::Object(observation);
    let charge = serialized_len(&observation);
    if charge > MAX_SESSION_CAPTURE_BYTES {
        mark_truncated(managed, script_id);
        return;
    }
    while !managed.messages.is_empty()
        && managed.captured_bytes + charge > MAX_SESSION_CAPTURE_BYTES
    {
        let removed = managed.messages.remove(0);
        managed.captured_bytes -= removed.charge;
        if let Some(capture) = managed.script_captures.get_mut(&removed.script_id) {
            if capture.messages.first() == Some(&removed.observation) {
                capture.messages.remove(0);
            }
        }
        mark_truncated(managed, &removed.script_id);
    }
    if let Some(capture) = managed.script_captures.get_mut(script_id) {
        capture.messages.push(observation.clone());
    }
    managed.captured_bytes += charge;
    managed.messages.push(CapturedMessage {
        observation,
        script_id: script_id.to_owned(),
        charge,
    });
}

fn text_field(parsed: &Value, key: &str, secrets: &[String]) -> Option<(String, bool)> {
    let text = parsed.get(key).and_then(Value::as_str)?;
    let bounded = bounded_redacted_string(text, MAX_MESSAGE_TEXT_BYTES, secrets);
    Some((bounded.value, bounded.truncated))
}

fn safe_index(parsed: &Value, key: &str) -> Option<i64> {
    let number = parsed.get(key)?.as_i64()?;
    (number >= 0).then_some(number)
}

fn mark_truncated(managed: &mut ManagedSession, script_id: &str) {
    managed.messages_truncated = true;
    if let Some(capture) = managed.script_captures.get_mut(script_id) {
        capture.truncated = true;
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

impl rea_mcp::SessionResource for Manager {
    fn close(&self) -> Result<(), AnalysisError> {
        self.close_all()
    }
}
