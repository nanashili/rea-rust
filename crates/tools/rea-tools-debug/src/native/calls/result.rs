//! Tracer result decoding and projection into the result/partial contracts.
//!
//! Compatibility owners: `src/native/NativeCallObservation.ts`
//! (`nativeCallFacts`, `projectNativeCalls`, `projectPartialNativeCalls`,
//! `NATIVE_CALL_OBSERVATION_LIMITATIONS`), `src/native/LldbCallTracer.ts`
//! (`tracedSchema`, `tracerOutputSchema`), `src/native/LldbRetainedObservations.ts`
//! (`projectLldbPartialObservation`, `parseLldbObservationJournal`) and the
//! `nativeCallObservationResultSchema` / `nativeCallPartialObservationSchema`
//! strict object schemas.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::input::ObservationInput;

/// `NATIVE_CALL_OBSERVATION_LIMITATIONS`.
pub(crate) const NATIVE_CALL_OBSERVATION_LIMITATIONS: [&str; 6] = [
    "Only entries are observed; return values, floating-point and stack-passed arguments are not captured.",
    "Registers are the raw integer argument registers at entry. For Objective-C methods the first two hold the receiver and the selector.",
    "Receiver classes come from LLDB's Objective-C runtime reader without running target code; they are null for class methods and for receivers LLDB cannot classify.",
    "Calls that never reach a symbol's entry, such as inlined code or objc_direct methods called directly, are not observed.",
    "The target is launched directly under LLDB, not through LaunchServices; LLDB disables ASLR for it, so load addresses can equal file addresses.",
    "The observation window is checked about once a second, and recording pauses the process at every entry, which slows it.",
];

/// Target identity reported by the bridge (`tracedSchema.target_identity`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetIdentity {
    pub loaded_image_sha256: Option<String>,
    pub selected_file_sha256: Option<String>,
    pub file_device: Option<String>,
    pub file_inode: Option<String>,
    pub module_path: Option<String>,
    pub module_uuid: Option<String>,
    pub stable: bool,
}

/// One resolved breakpoint (`tracedSchema.breakpoints[]`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedBreakpoint {
    pub index: u64,
    pub location_count: u64,
    pub locations: Vec<Value>,
}

/// Bounded output counters (`tracedSchema.target_output`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetOutput {
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_complete: bool,
    pub stderr_complete: bool,
}

/// A completed bridge run (`tracedSchema`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TracedRun {
    #[allow(dead_code)]
    status: String,
    pub version: String,
    pub pid: i64,
    pub outcome: String,
    pub exit_status: Option<i64>,
    pub exit_description: Option<String>,
    #[allow(dead_code)]
    pub killed: bool,
    pub terminated: bool,
    pub target_identity: TargetIdentity,
    #[allow(dead_code)]
    pub resource_limit_reached: bool,
    #[serde(default)]
    pub breakpoint_locations_truncated: Option<bool>,
    pub target_output: TargetOutput,
    pub elapsed_ms: f64,
    pub breakpoints: Vec<ResolvedBreakpoint>,
    pub events: Vec<Value>,
    pub other_stops: Vec<String>,
}

/// A bridge failure status (`tracerOutputSchema` non-traced member).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TracerError {
    pub status: String,
    pub error: Option<String>,
    #[serde(default)]
    pub target_process_created: Option<bool>,
    #[serde(default)]
    pub target_process_exit_observed: Option<bool>,
}

/// `tracerOutputSchema` discriminated union.
#[derive(Clone, Debug)]
pub(crate) enum TracerOutput {
    Traced(TracedRun),
    Failed(TracerError),
}

impl TracerOutput {
    /// Parse the bridge result JSON (`readTracerOutput` schema validation).
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let value: Value =
            serde_json::from_str(text).map_err(|error| format!("invalid tracer JSON: {error}"))?;
        let status = value
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| "tracer result missing status".to_owned())?;
        if status == "traced" {
            let mut run: TracedRun = serde_json::from_value(value)
                .map_err(|error| format!("tracer result failed schema validation: {error}"))?;
            validate_run(&mut run)?;
            Ok(Self::Traced(run))
        } else if matches!(
            status,
            "target-error"
                | "target-integrity-error"
                | "target-identity-unavailable"
                | "launch-error"
                | "tracer-error"
        ) {
            let failure: TracerError = serde_json::from_value(value)
                .map_err(|error| format!("tracer result failed schema validation: {error}"))?;
            Ok(Self::Failed(failure))
        } else {
            Err(format!("unknown tracer status: {status}"))
        }
    }
}

/// Bounded output capture (`CapturedOutput`).
#[derive(Clone, Debug)]
pub(crate) struct CapturedOutput {
    pub text: String,
    pub bytes: u64,
    pub truncated: bool,
    pub complete: bool,
}

impl CapturedOutput {
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "text": self.text,
            "bytes": self.bytes,
            "truncated": self.truncated,
            "complete": self.complete,
        })
    }
}

/// Identity echoed in the result's `target`.
#[derive(Clone, Debug)]
pub(crate) struct TargetFacts {
    pub path: String,
    pub sha256: String,
    pub architecture: String,
}

/// A completed trace before projection (`NativeCallTrace`).
pub(crate) struct NativeCallTrace {
    pub debugger_path: String,
    pub debugger_sha256: String,
    pub run: TracedRun,
    pub stdout: Option<CapturedOutput>,
    pub stderr: Option<CapturedOutput>,
    pub terminated: bool,
}

/// `nativeCallFacts` common projection, shared by complete and partial results.
fn facts(
    target: &TargetFacts,
    input: &ObservationInput,
    trace: &NativeCallTrace,
) -> Map<String, Value> {
    let run = &trace.run;
    let unresolved: Vec<u64> = run
        .breakpoints
        .iter()
        .filter(|breakpoint| breakpoint.location_count == 0)
        .map(|breakpoint| breakpoint.index)
        .collect();
    let event_limit = run.outcome == "event-limit";
    let resource_limit = run.outcome == "resource-limit";
    let breakpoint_location_limit = run.breakpoint_locations_truncated == Some(true);
    let partial = event_limit
        || resource_limit
        || breakpoint_location_limit
        || run.outcome == "duration-elapsed"
        || run.outcome == "stop-limit"
        || !unresolved.is_empty();

    let breakpoints: Vec<Value> = input
        .breakpoints
        .iter()
        .enumerate()
        .map(|(index, request)| {
            let resolved = run.breakpoints.get(index);
            json!({
                "index": index,
                "request": request.request(),
                "location_count": resolved.map(|b| b.location_count).unwrap_or(0),
                "locations": resolved.map(|b| Value::Array(b.locations.clone())).unwrap_or(Value::Array(vec![])),
            })
        })
        .collect();

    let mut coverage = Map::new();
    coverage.insert(
        "status".into(),
        json!(if partial { "partial" } else { "complete" }),
    );
    coverage.insert("event_limit_reached".into(), json!(event_limit));
    coverage.insert("resource_limit_reached".into(), json!(resource_limit));
    if breakpoint_location_limit {
        coverage.insert("breakpoint_locations_truncated".into(), json!(true));
    }
    coverage.insert("unresolved_breakpoints".into(), json!(unresolved));

    let limitations = build_limitations(input, trace, &unresolved);

    let target_object = json!({
        "path": target.path,
        "sha256": target.sha256,
        "architecture": target.architecture,
        "arguments": input.arguments_value(),
        "environment": input.environment_object(),
        "working_directory": input.working_directory,
        "launch_identity": {
            "loaded_image_sha256": run.target_identity.loaded_image_sha256,
            "file_device": run.target_identity.file_device,
            "file_inode": run.target_identity.file_inode,
            "selected_file_sha256": run.target_identity.selected_file_sha256,
            "module_path": run.target_identity.module_path,
            "module_uuid": run.target_identity.module_uuid,
            "stable": run.target_identity.stable,
        },
    });

    let process = json!({
        "pid": run.pid,
        "outcome": run.outcome,
        "exit_status": run.exit_status,
        "exit_description": run.exit_description,
        "terminated": run.terminated && trace.terminated,
        "elapsed_ms": run.elapsed_ms,
        "stdout": trace.stdout.as_ref().map_or(Value::Null, CapturedOutput::to_value),
        "stderr": trace.stderr.as_ref().map_or(Value::Null, CapturedOutput::to_value),
        "other_stops": run.other_stops,
    });

    let debugger = json!({
        "path": trace.debugger_path,
        "sha256": trace.debugger_sha256,
        "version": run.version,
    });

    let mut object = Map::new();
    object.insert("target".into(), target_object);
    object.insert("debugger".into(), debugger);
    object.insert("process".into(), process);
    object.insert("breakpoints".into(), Value::Array(breakpoints));
    object.insert("events".into(), Value::Array(run.events.clone()));
    object.insert("coverage".into(), Value::Object(coverage));
    object.insert("limitations".into(), Value::Array(limitations));
    object
}

fn build_limitations(
    input: &ObservationInput,
    trace: &NativeCallTrace,
    unresolved: &[u64],
) -> Vec<Value> {
    let run = &trace.run;
    let event_limit = run.outcome == "event-limit";
    let resource_limit = run.outcome == "resource-limit";
    let breakpoint_location_limit = run.breakpoint_locations_truncated == Some(true);
    let mut notes: Vec<String> = NATIVE_CALL_OBSERVATION_LIMITATIONS
        .iter()
        .map(|note| (*note).to_owned())
        .collect();
    notes.push("The selected pathname digest and LLDB module identity are checked around launch. No immutable executable snapshot is used; concurrent in-place mutation or replacement and restoration cannot be ruled out, so the loaded-image digest remains unknown.".to_owned());
    if event_limit {
        notes.push(format!(
            "Observation stopped at max_events ({}); later calls were not recorded and the process was killed.",
            input.max_events
        ));
    }
    if resource_limit {
        notes.push("Observation stopped before retaining the next complete event because the estimated 8 MiB trace-payload or 65,536-frame aggregate budget was reached; the process was killed.".to_owned());
    }
    if run.outcome == "duration-elapsed" {
        notes.push(format!(
            "The process was still running after duration_ms ({}) and was killed.",
            input.duration_ms
        ));
    }
    if !run.target_identity.stable {
        notes.push("LLDB did not provide enough module identity evidence to confirm pathname and module continuity around launch.".to_owned());
    }
    if run.outcome == "stop-limit" {
        notes.push(
            "Observation stopped after repeated signal or exception stops; the process was killed."
                .to_owned(),
        );
    }
    if !unresolved.is_empty() {
        let joined = unresolved
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        notes.push(format!(
            "Breakpoints {joined} matched no code in any image loaded while observing; their calls could not be observed."
        ));
    }
    if run
        .breakpoints
        .iter()
        .any(|breakpoint| (breakpoint.locations.len() as u64) < breakpoint.location_count)
    {
        notes.push("Breakpoints with many matching locations list only the first 64; location_count gives the total.".to_owned());
    }
    if breakpoint_location_limit {
        notes.push("Resolved breakpoint locations exceeded the aggregate 8 MiB metadata budget; omitted locations are counted in location_count. This metadata limit does not change the process outcome.".to_owned());
    }
    // In the complete path stdout/stderr are always present (never null).
    let (stdout, stderr) = (trace.stdout.as_ref(), trace.stderr.as_ref());
    if stdout.is_none() || stderr.is_none() {
        notes.push("One or more target output captures were unavailable.".to_owned());
    }
    if stdout.is_some_and(|c| c.truncated) || stderr.is_some_and(|c| c.truncated) {
        notes.push("Target output beyond 1 MiB per stream is counted but not kept.".to_owned());
    }
    if stdout.is_some_and(|c| !c.complete) || stderr.is_some_and(|c| !c.complete) {
        notes.push("Target output draining did not complete; reported byte counts are observed lower bounds, not stream totals.".to_owned());
    }
    if !(run.terminated && trace.terminated) {
        notes.push(format!(
            "REA could not confirm that process {} exited; check for it before relying on host state.",
            run.pid
        ));
    }
    notes.into_iter().map(Value::String).collect()
}

/// `projectNativeCalls` with the complete result's limitation list.
pub(crate) fn project(
    target: &TargetFacts,
    input: &ObservationInput,
    trace: &NativeCallTrace,
) -> Value {
    Value::Object(facts(target, input, trace))
}

/// The complete result's `limitations` (bound to Evidence by the provider).
pub(crate) fn project_limitations(
    target: &TargetFacts,
    input: &ObservationInput,
    trace: &NativeCallTrace,
) -> Vec<String> {
    facts(target, input, trace)
        .get("limitations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// `projectPartialNativeCalls`: retained completed facts with partial coverage.
pub(crate) fn project_partial(
    target: &TargetFacts,
    input: &ObservationInput,
    trace: &NativeCallTrace,
    reason: &str,
) -> Value {
    let mut facts = facts(target, input, trace);
    // `nativeCallPartialObservationSchema.parse` key order.
    let mut coverage = match facts.remove("coverage") {
        Some(Value::Object(coverage)) => coverage,
        _ => Map::new(),
    };
    coverage.remove("status");
    coverage.insert("status".into(), json!("partial"));
    coverage.insert("reason".into(), json!(reason));
    let mut object = Map::new();
    object.insert("kind".into(), json!("native-call-observation"));
    for key in ["target", "process", "debugger", "breakpoints", "events"] {
        if let Some(value) = facts.remove(key) {
            object.insert(key.into(), value);
        }
    }
    object.insert("coverage".into(), Value::Object(coverage));
    if let Some(limitations) = facts.remove("limitations") {
        object.insert("limitations".into(), limitations);
    }
    Value::Object(object)
}

fn is_hex_address(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() > 2
            && text.starts_with("0x")
            && text[2..]
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn nullable_string(value: Option<&Value>) -> Option<Value> {
    match value {
        Some(Value::Null) => Some(Value::Null),
        Some(Value::String(text)) => Some(Value::String(text.clone())),
        _ => None,
    }
}

fn non_negative_int(value: Option<&Value>) -> Option<Value> {
    value.filter(|value| value.as_u64().is_some()).cloned()
}

/// `nativeCodeLocationSchema.safeParse`, in schema key order.
fn location_fields(object: &Map<String, Value>, into: &mut Map<String, Value>) -> Option<()> {
    let load_address = object
        .get("load_address")
        .filter(|value| is_hex_address(value))?;
    let file_address = match object.get("file_address") {
        Some(Value::Null) => Value::Null,
        Some(value) if is_hex_address(value) => value.clone(),
        _ => return None,
    };
    into.insert("load_address".into(), load_address.clone());
    into.insert("file_address".into(), file_address);
    for key in ["module", "module_path", "symbol"] {
        into.insert(key.into(), nullable_string(object.get(key))?);
    }
    Some(())
}

const LOCATION_KEYS: [&str; 5] = [
    "load_address",
    "file_address",
    "module",
    "module_path",
    "symbol",
];

/// A strict code location (`nativeCodeLocationSchema.parse`).
pub(crate) fn normalize_location(value: &Value) -> Option<Value> {
    let object = value.as_object()?;
    if object
        .keys()
        .any(|key| !LOCATION_KEYS.contains(&key.as_str()))
    {
        return None;
    }
    let mut location = Map::new();
    location_fields(object, &mut location)?;
    Some(Value::Object(location))
}

/// A strict call event (`nativeCallEventSchema.parse`), in schema key order.
pub(crate) fn normalize_event(value: &Value) -> Option<Value> {
    const EVENT_KEYS: [&str; 8] = [
        "sequence",
        "elapsed_ms",
        "thread_id",
        "breakpoint_index",
        "receiver_class",
        "selector",
        "registers",
        "backtrace",
    ];
    let object = value.as_object()?;
    if object
        .keys()
        .any(|key| !LOCATION_KEYS.contains(&key.as_str()) && !EVENT_KEYS.contains(&key.as_str()))
    {
        return None;
    }
    let mut event = Map::new();
    event.insert("sequence".into(), non_negative_int(object.get("sequence"))?);
    let elapsed = object
        .get("elapsed_ms")
        .filter(|value| value.as_f64().is_some_and(|ms| ms >= 0.0))?;
    event.insert("elapsed_ms".into(), elapsed.clone());
    event.insert(
        "thread_id".into(),
        non_negative_int(object.get("thread_id"))?,
    );
    event.insert(
        "breakpoint_index".into(),
        non_negative_int(object.get("breakpoint_index"))?,
    );
    location_fields(object, &mut event)?;
    event.insert(
        "receiver_class".into(),
        nullable_string(object.get("receiver_class"))?,
    );
    event.insert("selector".into(), nullable_string(object.get("selector"))?);
    let registers = object
        .get("registers")?
        .as_array()?
        .iter()
        .map(|register| {
            let register = register.as_object()?;
            if register.len() != 2 {
                return None;
            }
            let name = register.get("name").filter(|name| name.is_string())?;
            let value = register
                .get("value")
                .filter(|value| is_hex_address(value))?;
            Some(json!({ "name": name, "value": value }))
        })
        .collect::<Option<Vec<_>>>()?;
    event.insert("registers".into(), Value::Array(registers));
    let backtrace = object
        .get("backtrace")?
        .as_array()?
        .iter()
        .map(normalize_location)
        .collect::<Option<Vec<_>>>()?;
    event.insert("backtrace".into(), Value::Array(backtrace));
    Some(Value::Object(event))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The remaining `tracedSchema` refinements serde cannot express.
fn validate_run(run: &mut TracedRun) -> Result<(), String> {
    let invalid = |field: &str| format!("tracer result failed schema validation: {field}");
    if run.pid <= 0 {
        return Err(invalid("pid"));
    }
    if !matches!(
        run.outcome.as_str(),
        "exited" | "duration-elapsed" | "event-limit" | "stop-limit" | "resource-limit"
    ) {
        return Err(invalid("outcome"));
    }
    if !(run.elapsed_ms >= 0.0) {
        return Err(invalid("elapsed_ms"));
    }
    if run.target_identity.loaded_image_sha256.is_some() {
        return Err(invalid("target_identity.loaded_image_sha256"));
    }
    if run
        .target_identity
        .selected_file_sha256
        .as_deref()
        .is_some_and(|digest| !is_sha256(digest))
    {
        return Err(invalid("target_identity.selected_file_sha256"));
    }
    for breakpoint in &mut run.breakpoints {
        breakpoint.locations = breakpoint
            .locations
            .iter()
            .map(normalize_location)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| invalid("breakpoints.locations"))?;
    }
    run.events = run
        .events
        .iter()
        .map(normalize_event)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| invalid("events"))?;
    Ok(())
}
