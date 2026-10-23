//! Per-session JADX provider: serialized engine session, workspace root,
//! immutable snapshots, bridge embedding, launch, retained cleanup and idle
//! retirement.
//!
//! Compatibility owner: `src/android/JadxProvider.ts`, `JadxWorkspaceRoot.ts`
//! and `AndroidTargetSnapshot.ts`. One immutable APK session per REA session,
//! retired on idle (60 s) or shutdown. The native private-root ownership
//! replaces the Node workspace guardian: on every host the REA process owns
//! the root and removes it on retirement/close; a failed removal keeps
//! ownership for retry.
//!
//! Remaining owner-death gap: a hard-killed REA process cannot remove the
//! private root (the TS Windows guardian process survived owner death; the
//! native owner-only root has no surviving external owner).

use super::analysis::AndroidRequest;
use super::configuration::{self, JadxConfiguration};
use super::failure::{self, FailureCause, FailureContext};
use super::release::{self, JADX_PROVIDER_ID};
use super::session::{ExecuteContext, JadxSession};
use super::transport::JadxTransport;
use crate::common::errors::{object, provider_cleanup};
use crate::common::evidence::complete;
use crate::common::files::{self, SnapshotError, StableFileError};
use crate::common::target::BinaryTarget;
use crate::common::turnstile::Turnstile;
use crate::common::workspace::PrivateRoot;
use crate::common::{env, ids};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::Evidence;
use rea_mcp::{Session, SessionResource};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The embedded REA bridge source (distinct from the engine).
const BRIDGE_SOURCE: &[u8] = include_bytes!("../../../../../../bridge/android/ReaJadxBridge.java");

/// SHA-256 of the embedded bridge bytes.
pub fn bridge_sha256() -> String {
    files::sha256_hex(BRIDGE_SOURCE)
}

/// A retained engine session, keyed by its admission inputs.
struct Retained {
    key: String,
    root: PrivateRoot,
    session: JadxSession,
    snapshot: String,
    jar_hash: String,
    bridge_hash: String,
    idle_since: Option<Instant>,
}

/// Session-scoped JADX provider state.
#[derive(Default)]
pub struct JadxState {
    inner: Mutex<JadxStateInner>,
    /// Serializes every JADX operation on this session, as the single TS provider.
    pub turn: Turnstile,
}

#[derive(Default)]
struct JadxStateInner {
    retained: Option<Retained>,
    /// A root/session whose cleanup failed and must be retried.
    pending: Option<Pending>,
    closing: bool,
}

struct Pending {
    root: Option<PrivateRoot>,
    session: Option<JadxSession>,
    primary: Option<AnalysisError>,
}

impl JadxState {
    fn lock(&self) -> std::sync::MutexGuard<'_, JadxStateInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn is_closing(&self) -> bool {
        self.lock().closing
    }
}

/// `close()`: stop admission, retire the engine/workspace, retry failed cleanup.
impl SessionResource for JadxState {
    fn close(&self) -> Result<(), AnalysisError> {
        {
            let mut inner = self.lock();
            inner.closing = true;
        }
        // Join the active turn, then retire.
        let _turn = self.turn.acquire_uncancellable();
        retire(self, "close_binary")
    }
}

/// Register the JADX state as a shutdown resource once per session.
pub fn state(session: &Arc<Session>) -> Arc<JadxState> {
    let state = session.state::<JadxState>();
    session.own_once(Arc::clone(&state));
    state
}

/// Retire the retained (or pending) engine and workspace. A failed removal is
/// retained for retry and returns a provider cleanup error.
fn retire(state: &JadxState, operation: &str) -> Result<(), AnalysisError> {
    let mut inner = state.lock();
    // Adopt the retained session into pending if present.
    if inner.pending.is_none()
        && let Some(retained) = inner.retained.take()
    {
        inner.pending = Some(Pending {
            root: Some(retained.root),
            session: Some(retained.session),
            primary: None,
        });
    }
    let Some(mut pending) = inner.pending.take() else {
        return Ok(());
    };
    drop(inner);

    let mut resources: Vec<String> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();

    // Close the engine session first (prove process ownership stopped).
    let mut session_failed = false;
    if let Some(session) = pending.session.as_mut() {
        resources.push(session.transport.run_id.clone());
        if let Err(error) = session.close() {
            session_failed = true;
            reasons.push(error.user_message());
        }
    }
    if !session_failed {
        pending.session = None;
    }

    // Then remove the owned workspace root.
    let mut root_failed = false;
    if let Some(root) = pending.root.as_mut() {
        resources.push(root.path().display().to_string());
        if session_failed {
            // Keep the workspace until the session's ownership is proven stopped.
            root_failed = true;
        } else if let Err(error) = root.close() {
            root_failed = true;
            reasons.push(error.to_string());
        }
    }
    if !root_failed {
        pending.root = None;
    }

    if session_failed || root_failed {
        let mut inner = state.lock();
        let diagnostics = object(json!({
            "reason": reasons.join("; "),
            "cleanup_causes": reasons,
        }));
        let cleanup = provider_cleanup(JADX_PROVIDER_ID, operation, dedup(resources), diagnostics);
        let primary = pending.primary.take();
        inner.pending = Some(pending);
        return Err(match primary {
            Some(primary) => {
                crate::common::errors::with_cleanup_failure(primary, cleanup, operation)
            }
            None => cleanup,
        });
    }
    Ok(())
}

fn dedup(resources: Vec<String>) -> Vec<String> {
    let mut deduped: Vec<String> = Vec::new();
    for resource in resources {
        if !deduped.contains(&resource) {
            deduped.push(resource);
        }
    }
    deduped
}

/// Retire the engine if it has been idle at least 60 s since a successful op.
fn retire_if_idle(state: &JadxState) {
    let should = {
        let inner = state.lock();
        inner.pending.is_none()
            && inner
                .retained
                .as_ref()
                .and_then(|retained| retained.idle_since)
                .is_some_and(|since| since.elapsed() >= Duration::from_secs(60))
    };
    if should {
        let _ = retire(state, "close_binary");
    }
}

/// Mark the retained engine idle (idle retirement is checked on the next call).
fn schedule_idle(state: &JadxState) {
    let mut inner = state.lock();
    if let Some(retained) = inner.retained.as_mut() {
        retained.idle_since = Some(Instant::now());
    }
}

fn target_changed(operation: &str, path: &str) -> AnalysisError {
    AnalysisError::input(
        operation,
        vec![InputIssue::new(
            &["path"],
            "invalid_value",
            format!("APK bytes changed after admission at {path}; retry against a stable file."),
        )],
    )
}

fn source_changed(operation: &str, source: &str) -> AnalysisError {
    let reason = format!(
        "Selected JADX input bytes changed during admission at {source}; retry with a stable installation."
    );
    crate::common::errors::capability_unavailable(
        JADX_PROVIDER_ID,
        operation,
        reason.clone(),
        Some(reason),
        None,
    )
}

/// `hashAndroidSource(path)`: hash a stable source, mapping a change to the
/// capability-unavailable form.
fn hash_source(
    path: &Path,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<String, AnalysisError> {
    match files::hash_stable_file(path, cancellation) {
        Ok(digest) => Ok(digest.sha256),
        Err(StableFileError::Cancelled(_)) => Err(AnalysisError::cancelled(operation)),
        Err(StableFileError::Changed { .. }) => {
            Err(source_changed(operation, &path.display().to_string()))
        }
        Err(error) => Err(crate::common::errors::provider_adapter(
            JADX_PROVIDER_ID,
            operation,
            Some(error.to_string()),
            None,
        )),
    }
}

/// Build the session key: identical inputs reuse the retained session.
fn session_key(
    target: &BinaryTarget,
    configuration: &JadxConfiguration,
    jar_hash: &str,
    bridge_hash: &str,
    environment: &HashMap<String, String>,
) -> String {
    let options = json!([
        env::lookup(environment, "JAVA_TOOL_OPTIONS"),
        env::lookup(environment, "_JAVA_OPTIONS"),
        env::lookup(environment, "JDK_JAVA_OPTIONS"),
        env::lookup(environment, "PATH"),
        env::lookup(environment, "JAVA_HOME"),
    ]);
    json!({
        "path": target.path,
        "sha256": target.sha256,
        "jar": configuration.jar,
        "jarHash": jar_hash,
        "bridgeHash": bridge_hash,
        "java": configuration.java,
        "arguments": configuration.jvm_arguments,
        "options": options,
    })
    .to_string()
}

/// Analyze one admitted APK, reusing or acquiring the serialized session.
pub fn execute(
    state: &JadxState,
    target: &BinaryTarget,
    request: &AndroidRequest,
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<Evidence, AnalysisError> {
    retire_if_idle(state);
    {
        // Retire a stale pending cleanup before new work.
        let has_pending = state.lock().pending.is_some();
        if has_pending {
            retire(state, request.operation)?;
        }
    }
    let operation = request.operation;
    let timeout_ms = configuration::resolve_jadx_operation_timeout(environment, operation)?;

    let execution = execute_inner(
        state,
        target,
        request,
        environment,
        timeout_ms,
        cancellation,
    );
    match execution {
        Ok(evidence) => {
            schedule_idle(state);
            complete(evidence, cancellation, None)
        }
        Err(error) => Err(error),
    }
}

fn execute_inner(
    state: &JadxState,
    target: &BinaryTarget,
    request: &AndroidRequest,
    environment: &HashMap<String, String>,
    timeout_ms: u64,
    cancellation: &Cancellation,
) -> Result<Evidence, AnalysisError> {
    let operation = request.operation;
    if target.format != "apk" {
        return Err(crate::common::errors::capability_unavailable(
            JADX_PROVIDER_ID,
            operation,
            format!(
                "Target {} is {}; provide one standalone APK.",
                target.path, target.format
            ),
            None,
            None,
        ));
    }
    let configuration =
        configuration::resolve_jadx_configuration_inputs(environment, operation, cancellation)?;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    let jar_hash = hash_source(Path::new(&configuration.jar), operation, cancellation)?;
    let bridge_hash = bridge_sha256();

    // Verify the target's current bytes match its admitted digest.
    let target_hash = match files::hash_stable_file(Path::new(&target.path), cancellation) {
        Ok(digest) => digest.sha256,
        Err(StableFileError::Cancelled(_)) => return Err(AnalysisError::cancelled(operation)),
        Err(StableFileError::Changed { .. }) => {
            return Err(target_changed(operation, &target.path));
        }
        Err(error) => {
            return Err(crate::common::errors::provider_adapter(
                JADX_PROVIDER_ID,
                operation,
                Some(error.to_string()),
                None,
            ));
        }
    };
    if target_hash != target.sha256 {
        return Err(target_changed(operation, &target.path));
    }

    let key = session_key(target, &configuration, &jar_hash, &bridge_hash, environment);

    // Reuse a retained session only when the key matches.
    {
        let key_mismatch = {
            let inner = state.lock();
            inner
                .retained
                .as_ref()
                .is_some_and(|retained| retained.key != key)
        };
        if key_mismatch {
            retire(state, operation)?;
        }
    }
    {
        let mut inner = state.lock();
        if inner.retained.is_some() {
            let retained = inner.retained.as_mut().expect("retained present");
            retained.idle_since = None;
            let snapshot = retained.snapshot.clone();
            let jar_hash = retained.jar_hash.clone();
            let bridge_hash = retained.bridge_hash.clone();
            let context = ExecuteContext {
                request,
                target,
                snapshot,
                jar_hash,
                bridge_hash,
                timeout_ms,
            };
            let result = retained.session.execute(context, cancellation);
            drop(inner);
            return finish_retained(state, operation, request, timeout_ms, cancellation, result);
        }
    }

    // Acquire a fresh session.
    configuration::validate_jadx_configuration(
        &configuration,
        environment,
        operation,
        Some(timeout_ms),
        cancellation,
    )?;

    let parent = env::temporary_directory(environment);
    let root = PrivateRoot::create(&parent, "rea-android-").map_err(|error| {
        crate::common::errors::provider_adapter(
            JADX_PROVIDER_ID,
            operation,
            Some(format!(
                "Could not create the Android workspace root: {error}"
            )),
            None,
        )
    })?;

    let mut retained = match acquire_session(
        root,
        &configuration,
        &jar_hash,
        &bridge_hash,
        target,
        &key,
        operation,
        cancellation,
    ) {
        Ok(retained) => retained,
        Err((mut root, error)) => {
            let _ = root.close();
            return Err(error);
        }
    };

    let context = ExecuteContext {
        request,
        target,
        snapshot: retained.snapshot.clone(),
        jar_hash: retained.jar_hash.clone(),
        bridge_hash: retained.bridge_hash.clone(),
        timeout_ms,
    };
    let result = retained.session.execute(context, cancellation);
    match result {
        Ok(execution) => {
            retained.idle_since = None;
            let evidence = crate::common::evidence::execution_evidence(
                operation,
                parameters_for(request),
                execution,
                confidence_for(operation),
            )?;
            state.lock().retained = Some(retained);
            Ok(evidence)
        }
        Err(cause) => {
            let partial = retained.session.partial_observation();
            let initialized = retained.session.initialized();
            let command = retained.session.transport.command();
            let failure = capture(
                operation,
                timeout_ms,
                cancellation,
                Some(&retained.session.transport),
                initialized,
                command,
                cause,
                partial,
            );
            park_pending(
                state,
                Some(retained.root),
                Some(retained.session),
                failure.clone(),
            );
            match retire(state, operation) {
                Ok(()) => Err(failure),
                Err(error) => Err(error),
            }
        }
    }
}

/// Finish a retained-session execution: on failure capture + retire.
fn finish_retained(
    state: &JadxState,
    operation: &'static str,
    request: &AndroidRequest,
    timeout_ms: u64,
    cancellation: &Cancellation,
    result: Result<crate::common::evidence::Execution, AnalysisError>,
) -> Result<Evidence, AnalysisError> {
    match result {
        Ok(execution) => crate::common::evidence::execution_evidence(
            operation,
            parameters_for(request),
            execution,
            confidence_for(operation),
        ),
        Err(cause) => {
            let retained = state.lock().retained.take();
            let (partial, initialized, command, session, root) = match retained {
                Some(retained) => (
                    retained.session.partial_observation(),
                    retained.session.initialized(),
                    retained.session.transport.command(),
                    Some(retained.session),
                    Some(retained.root),
                ),
                None => (None, true, String::new(), None, None),
            };
            let failure = capture(
                operation,
                timeout_ms,
                cancellation,
                session.as_ref().map(|session| &session.transport),
                initialized,
                command,
                cause,
                partial,
            );
            park_pending(state, root, session, failure.clone());
            match retire(state, operation) {
                Ok(()) => Err(failure),
                Err(error) => Err(error),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn capture(
    operation: &'static str,
    timeout_ms: u64,
    cancellation: &Cancellation,
    transport: Option<&JadxTransport>,
    initialized: bool,
    command: String,
    cause: AnalysisError,
    partial: Option<Value>,
) -> AnalysisError {
    let timed_out = cancellation
        .reason()
        .is_some_and(|reason| reason.contains("timed out") || reason.contains("timeout"));
    let context = FailureContext {
        cause: FailureCause::Analysis(cause),
        operation,
        timeout_ms,
        timed_out,
        cancelled: cancellation.reason().map(str::to_owned),
        transport,
        initialized,
        command,
    };
    failure::capture_jadx_failure(context, partial)
}

fn park_pending(
    state: &JadxState,
    root: Option<PrivateRoot>,
    session: Option<JadxSession>,
    primary: AnalysisError,
) {
    let mut inner = state.lock();
    inner.retained = None;
    inner.pending = Some(Pending {
        root,
        session,
        primary: Some(primary),
    });
}

/// Acquire a fresh engine session inside the owned workspace root. On failure
/// the root is returned to the caller for retirement.
#[allow(clippy::too_many_arguments)]
fn acquire_session(
    root: PrivateRoot,
    configuration: &JadxConfiguration,
    jar_hash: &str,
    bridge_hash: &str,
    target: &BinaryTarget,
    key: &str,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Retained, (PrivateRoot, AnalysisError)> {
    let root_path = root.path().to_path_buf();

    macro_rules! bail {
        ($expr:expr) => {
            match $expr {
                Ok(value) => value,
                Err(error) => return Err((root, error)),
            }
        };
    }

    // Snapshot the engine JAR.
    let engine_path = root_path.join("engine.jar");
    let engine_hash = bail!(snapshot(
        Path::new(&configuration.jar),
        &engine_path,
        jar_hash,
        operation,
        cancellation,
        SnapshotKind::Engine,
        &configuration.jar,
    ));
    files::make_read_only(&engine_path).ok();

    // Snapshot the target APK.
    let snapshot_path = root_path.join("target.apk");
    bail!(snapshot(
        Path::new(&target.path),
        &snapshot_path,
        &target.sha256,
        operation,
        cancellation,
        SnapshotKind::Target,
        &target.path,
    ));
    files::make_read_only(&snapshot_path).ok();

    // Write the embedded bridge source, make it read-only, re-hash and compare.
    let bridge_path = root_path.join("ReaJadxBridge.java");
    bail!(
        files::write_new_file(&bridge_path, BRIDGE_SOURCE).map_err(|error| {
            crate::common::errors::provider_adapter(
                JADX_PROVIDER_ID,
                operation,
                Some(format!(
                    "Could not write the Android bridge source: {error}"
                )),
                None,
            )
        })
    );
    files::make_read_only(&bridge_path).ok();
    let copied_bridge_hash = bail!(hash_source(&bridge_path, operation, cancellation));
    if copied_bridge_hash != *bridge_hash {
        return Err((root, source_changed(operation, "ReaJadxBridge.java")));
    }
    if cancellation.reason().is_some() {
        return Err((root, AnalysisError::cancelled(operation)));
    }

    // Launch the protocol child.
    let mut arguments: Vec<String> = configuration.jvm_arguments.clone();
    arguments.push("--class-path".to_owned());
    arguments.push(engine_path.display().to_string());
    arguments.push(bridge_path.display().to_string());
    let spec = crate::common::process::CommandSpec::new(&configuration.java, arguments)
        .in_directory(&root_path);
    let run_id = ids::random_uuid();
    let transport = JadxTransport::new(spec, run_id);
    let session = JadxSession::new(transport);

    Ok(Retained {
        key: key.to_owned(),
        root,
        session,
        snapshot: snapshot_path.display().to_string(),
        jar_hash: engine_hash,
        bridge_hash: bridge_hash.to_owned(),
        idle_since: None,
    })
}

enum SnapshotKind {
    Engine,
    Target,
}

#[allow(clippy::too_many_arguments)]
fn snapshot(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
    operation: &str,
    cancellation: &Cancellation,
    kind: SnapshotKind,
    display_source: &str,
) -> Result<String, AnalysisError> {
    match files::copy_snapshot(source, destination, expected_sha256, cancellation) {
        Ok(observed) => Ok(observed),
        Err(SnapshotError::File(StableFileError::Cancelled(_))) => {
            Err(AnalysisError::cancelled(operation))
        }
        Err(SnapshotError::Changed(_)) => Err(match kind {
            SnapshotKind::Engine => crate::common::errors::capability_unavailable(
                JADX_PROVIDER_ID,
                operation,
                format!(
                    "REA_JADX_MCP_JAR bytes changed during admission at {display_source}; retry with a stable engine file."
                ),
                None,
                None,
            ),
            SnapshotKind::Target => AnalysisError::input(
                operation,
                vec![InputIssue::new(
                    &["path"],
                    "invalid_value",
                    format!(
                        "APK bytes changed after admission at {display_source}; retry against a stable file."
                    ),
                )],
            ),
        }),
        Err(SnapshotError::File(error)) => Err(crate::common::errors::provider_adapter(
            JADX_PROVIDER_ID,
            operation,
            Some(error.to_string()),
            None,
        )),
    }
}

/// `parameters` passed to the provider request and recorded in Evidence.
fn parameters_for(request: &AndroidRequest) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("path".into(), json!(request.path));
    match request.operation {
        "inspect_android_package" => {}
        "search_android_classes" => {
            map.insert(
                "query".into(),
                json!(request.query.clone().unwrap_or_default()),
            );
        }
        "inspect_android_class" => {
            map.insert(
                "class_name".into(),
                json!(request.class_name.clone().unwrap_or_default()),
            );
        }
        "inspect_android_method" => {
            map.insert(
                "class_name".into(),
                json!(request.class_name.clone().unwrap_or_default()),
            );
            map.insert(
                "method_name".into(),
                json!(request.method_name.clone().unwrap_or_default()),
            );
            if let Some(index) = request.overload_index {
                map.insert("overload_index".into(), json!(index));
            }
        }
        "trace_android_references" => {
            map.insert(
                "class_name".into(),
                json!(request.class_name.clone().unwrap_or_default()),
            );
            if let Some(method_name) = &request.method_name {
                map.insert("method_name".into(), json!(method_name));
            }
            if let Some(index) = request.overload_index {
                map.insert("overload_index".into(), json!(index));
            }
        }
        _ => {}
    }
    Value::Object(map)
}

fn confidence_for(operation: &str) -> &'static str {
    if operation == "inspect_android_method" {
        "derived"
    } else {
        "observed"
    }
}

/// `inspectJadxAvailability` exposed for the binary session owner.
pub fn availability(environment: &HashMap<String, String>, cancellation: &Cancellation) -> Value {
    configuration::inspect_jadx_availability(environment, cancellation)
}

/// Keep the release module reachable for remediation lookups.
#[allow(dead_code)]
fn _release_link() -> &'static str {
    release::JADX_PROVIDER_NAME
}
