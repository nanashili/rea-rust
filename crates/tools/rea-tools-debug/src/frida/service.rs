//! Shared CLI/MCP Frida workflows and Evidence.
//!
//! Port of `src/application/frida/FridaInstrumentationService.ts`: the device
//! and process listings, the load/status Evidence envelopes
//! (`rea.frida.instrumentation-observation` with the two fixed limitations and
//! the non-UTF-8 `source_representation` raw result) and the ephemeral
//! `instrument_with_frida` workflow (reject unreadable file → start → load →
//! resume a spawn → observe for the window → close, reporting `cleanup_error`).

use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use serde_json::{Map, Value, json};

use super::manager::{
    Manager, Mode, Remote, ScriptObservation, ScriptSource, Selector, SessionObservation,
    SessionStatus, SourceRepresentation, StartInput,
};

const PREDICATE: &str = "rea.frida.instrumentation-observation";
const OS_LIMITATION: &str =
    "The target operating system and architecture were not reported by this observation.";
const UTF8_LIMITATION: &str = "Invalid UTF-8 in the selected script file was decoded with replacement characters. source_sha256 identifies the original file bytes; raw_result.source_representation.loaded_source_sha256 identifies the UTF-8 encoding of the string passed to Frida.";

fn provider() -> EvidenceProvider {
    EvidenceProvider::new("frida", "Frida", None)
}

/// `createEvidence` for one Frida observation (no subject).
fn frida_evidence(
    operation: &str,
    result: Value,
    parameters: Value,
    source_representation: Option<&SourceRepresentation>,
) -> Result<Evidence, AnalysisError> {
    let mut limitations = vec![OS_LIMITATION.to_owned()];
    let mut observation = Observation::new(operation, parameters, result)
        .predicate(PREDICATE)
        .confidence("observed")
        .authority("external-service");
    if let Some(representation) = source_representation {
        limitations.push(UTF8_LIMITATION.to_owned());
        observation = observation.raw(json!({
            "source_representation": {
                "encoding": "utf8",
                "decoding": "replacement",
                "loaded_source_sha256": representation.loaded_source_sha256,
            }
        }));
    }
    observation = observation.limitations(limitations);
    Evidence::create(None, &provider(), observation)
        .map_err(|error| AnalysisError::output(operation, error.to_string()))
}

fn source_output(script: &ScriptObservation) -> Vec<(String, Value)> {
    vec![
        ("source_kind".into(), json!(script.source_kind)),
        (
            "source_path".into(),
            script
                .source_path
                .clone()
                .map_or(Value::Null, Value::String),
        ),
        ("source_sha256".into(), json!(script.source_sha256)),
    ]
}

fn script_output(script: &ScriptObservation) -> Value {
    let mut map = Map::new();
    map.insert("script_id".into(), json!(script.script_id));
    for (key, value) in source_output(script) {
        map.insert(key, value);
    }
    map.insert("messages".into(), Value::Array(script.messages.clone()));
    map.insert(
        "messages_truncated".into(),
        json!(script.messages_truncated),
    );
    Value::Object(map)
}

pub(crate) fn session_output(session: &SessionObservation) -> Value {
    json!({
        "session_id": session.session_id,
        "device_id": session.device_id,
        "target": session.target,
        "pid": session.pid,
        "mode": mode_str(session.mode),
        "state": session.state,
    })
}

fn session_status_output(status: &SessionStatus) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("session_id".into(), json!(status.session.session_id));
    map.insert("device_id".into(), json!(status.session.device_id));
    map.insert("state".into(), json!(status.session.state));
    map.insert("target".into(), json!(status.session.target));
    map.insert("pid".into(), json!(status.session.pid));
    map.insert("mode".into(), json!(mode_str(status.session.mode)));
    map.insert(
        "scripts".into(),
        Value::Array(
            status
                .scripts
                .iter()
                .map(|(id, name)| json!({"script_id": id, "name": name}))
                .collect(),
        ),
    );
    map.insert("messages".into(), Value::Array(status.messages.clone()));
    map.insert(
        "messages_truncated".into(),
        json!(status.messages_truncated),
    );
    map
}

fn mode_str(mode: Mode) -> &'static str {
    match mode {
        Mode::Attach => "attach",
        Mode::Spawn => "spawn",
    }
}

// ---------------------------------------------------------------------------
// Device and process listings

pub(crate) fn list_devices(
    manager: &Manager,
    remote: Option<Remote>,
) -> Result<Value, AnalysisError> {
    let (devices, cleanup_error) = manager.list_devices(remote)?;
    Ok(json!({
        "devices": devices
            .into_iter()
            .map(|(device_id, name, kind)| json!({
                "device_id": device_id, "name": name, "type": kind,
            }))
            .collect::<Vec<_>>(),
        "cleanup_error": cleanup_error,
    }))
}

pub(crate) fn list_processes(
    manager: &Manager,
    selector: Selector,
) -> Result<Value, AnalysisError> {
    let (device_id, processes, cleanup_error) = manager.list_processes(selector)?;
    Ok(json!({
        "device_id": device_id,
        "processes": processes
            .into_iter()
            .map(|(pid, name)| json!({"pid": pid, "name": name, "identifier": Value::Null}))
            .collect::<Vec<_>>(),
        "cleanup_error": cleanup_error,
    }))
}

// ---------------------------------------------------------------------------
// load_frida_script / frida_session_status

pub(crate) fn load_script(
    manager: &Manager,
    session_id: &str,
    source: ScriptSource,
) -> Result<Evidence, AnalysisError> {
    let script = manager.load_script(session_id, &source)?;
    frida_evidence(
        "load_frida_script",
        script_output(&script),
        json!({ "session_id": session_id }),
        script.source_representation.as_ref(),
    )
}

pub(crate) fn status_evidence(
    manager: &Manager,
    session_id: &str,
) -> Option<Result<Evidence, AnalysisError>> {
    let status = match manager.status(session_id) {
        Ok(Some(status)) => status,
        Ok(None) => return None,
        Err(error) => return Some(Err(error)),
    };
    Some(frida_evidence(
        "frida_session_status",
        Value::Object(session_status_output(&status)),
        json!({ "session_id": session_id }),
        None,
    ))
}

// ---------------------------------------------------------------------------
// instrument_with_frida

/// The ephemeral attach/spawn + load + observe + detach workflow.
pub(crate) struct InstrumentInput {
    pub start: StartInput,
    pub source: ScriptSource,
    pub duration_ms: u64,
}

pub(crate) fn instrument(
    manager: &Manager,
    input: InstrumentInput,
) -> Result<Evidence, AnalysisError> {
    if let Some(error) = unreadable_script_file(&input.source) {
        return Err(error);
    }
    let remote = input.start.selector.remote.clone();
    let started = manager.start_session(input.start.clone())?;
    let device_id = started.device_id.clone();
    let session_id = started.session_id.clone();

    let loaded = match manager.load_script(&session_id, &input.source) {
        Ok(script) => script,
        Err(error) => {
            return Err(match manager.close_session(&session_id) {
                Ok(_) => error,
                Err(close) => with_cleanup_failure(error, &close, &session_id),
            });
        }
    };

    if started.mode == Mode::Spawn {
        if let Err(error) = manager.resume_session(&session_id) {
            return Err(match manager.close_session(&session_id) {
                Ok(_) => error,
                Err(close) => with_cleanup_failure(error, &close, &session_id),
            });
        }
    }

    if input.duration_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(input.duration_ms));
    }

    let status_result = manager.status(&session_id);
    let closed = manager.close_session(&session_id);
    let status = match status_result {
        Ok(status) => status,
        Err(error) => {
            return Err(match closed {
                Ok(_) => error,
                Err(close) => with_cleanup_failure(error, &close, &session_id),
            });
        }
    };
    let cleanup_error = match &closed {
        Ok(_) => Value::Null,
        Err(error) => Value::String(error.message()),
    };

    let mut result = status
        .as_ref()
        .map(session_status_output)
        .unwrap_or_else(|| {
            // No live status: fall back to the start observation + script.
            let mut map = Map::new();
            for (key, value) in started_fields(&started) {
                map.insert(key, value);
            }
            map.insert("scripts".into(), Value::Array(Vec::new()));
            map.insert("messages".into(), Value::Array(loaded.messages.clone()));
            map.insert(
                "messages_truncated".into(),
                json!(loaded.messages_truncated),
            );
            map
        });
    for (key, value) in source_output(&loaded) {
        result.insert(key, value);
    }
    result.insert("cleanup_error".into(), cleanup_error);

    frida_evidence(
        "instrument_with_frida",
        Value::Object(result),
        frida_parameters(&session_id, &device_id, &remote, &input.start),
        loaded.source_representation.as_ref(),
    )
}

fn started_fields(started: &SessionObservation) -> Vec<(String, Value)> {
    vec![
        ("session_id".into(), json!(started.session_id)),
        ("device_id".into(), json!(started.device_id)),
        ("state".into(), json!(started.state)),
        ("target".into(), json!(started.target)),
        ("pid".into(), json!(started.pid)),
        ("mode".into(), json!(mode_str(started.mode))),
    ]
}

/// `fridaParameters`.
fn frida_parameters(
    session_id: &str,
    device_id: &str,
    remote: &Option<Remote>,
    start: &StartInput,
) -> Value {
    let mut map = Map::new();
    map.insert("session_id".into(), json!(session_id));
    map.insert("device_id".into(), json!(device_id));
    if let Some(remote) = remote {
        let mut remote_map = Map::new();
        remote_map.insert("address".into(), json!(remote.address));
        if let Some(origin) = &remote.origin {
            remote_map.insert("origin".into(), json!(origin));
        }
        if let Some(interval) = remote.keepalive_interval {
            remote_map.insert("keepalive_interval".into(), json!(interval));
        }
        map.insert("remote".into(), Value::Object(remote_map));
    }
    map.insert("mode".into(), json!(mode_str(start.mode)));
    match start.mode {
        Mode::Attach => {
            map.insert("pid".into(), json!(start.pid.unwrap_or(0)));
        }
        Mode::Spawn => {
            map.insert(
                "program".into(),
                json!(start.program.clone().unwrap_or_default()),
            );
            if let Some(argv) = &start.argv {
                map.insert("argv".into(), json!(argv));
            }
        }
    }
    Value::Object(map)
}

/// `withCleanupFailure`.
fn with_cleanup_failure(
    original: AnalysisError,
    cleanup: &AnalysisError,
    session_id: &str,
) -> AnalysisError {
    let reason = cleanup.message();
    AnalysisError::capability_unavailable(
        "frida",
        "instrument_with_frida",
        format!("{}; cleanup failed: {reason}", original.message()),
    )
    .with_cleanup(reason, vec![session_id.to_owned()])
}

/// `unreadableScriptFile`: reject a file source before any attach/spawn effect.
fn unreadable_script_file(source: &ScriptSource) -> Option<AnalysisError> {
    let ScriptSource::File(path) = source else {
        return None;
    };
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => match std::fs::File::open(path) {
            Ok(_) => None,
            Err(cause) if is_permission(&cause) => Some(AnalysisError::access_denied(
                "instrument_with_frida",
                path,
                "EACCES",
            )),
            Err(cause) => Some(read_input_error(path, &format!("{}", io_reason(&cause)))),
        },
        Ok(_) => Some(read_input_error(path, "it is not a regular file")),
        Err(cause) if is_permission(&cause) => Some(AnalysisError::access_denied(
            "instrument_with_frida",
            path,
            "EACCES",
        )),
        Err(cause) => Some(read_input_error(path, io_reason(&cause))),
    }
}

fn read_input_error(path: &str, reason: &str) -> AnalysisError {
    AnalysisError::input(
        "instrument_with_frida",
        vec![InputIssue::new(
            &["path"],
            "invalid_value",
            format!("Cannot read Frida script file {path}: {reason}."),
        )],
    )
}

fn is_permission(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::PermissionDenied)
}

fn io_reason(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "no file exists there",
        _ => "it could not be read",
    }
}
