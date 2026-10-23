//! Bounded passive capture state and its canonical projection.
//!
//! Compatibility owners: the capture half of
//! `src/inspector/V8InspectorProvider.ts` (`ingestEvent`, retained metadata
//! budget) and `src/inspector/V8InspectorCaptureProjection.ts`.
use super::inspector::Event;
use super::scope::{self, Decision};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// `INSPECTOR_MAX_RETAINED_METADATA_BYTES`.
const MAX_RETAINED_METADATA_BYTES: i64 = 8 * 1024 * 1024;
const RETAINED_OBJECT_OVERHEAD_BYTES: i64 = 512;
const BUDGET_EXCEEDED: &str = "retained_metadata_budget_exceeded";

struct ScriptDraft {
    raw_url: String,
    context_key: Option<String>,
    cdp_hash: Option<String>,
    length: Option<u64>,
    is_module: Option<bool>,
}

#[derive(Clone)]
struct ContextDraft {
    key: String,
    state: &'static str,
    name: Option<String>,
    origin: Option<String>,
}

#[derive(Default)]
pub(crate) struct CaptureState {
    scripts: Vec<ScriptDraft>,
    /// Insertion order is irrelevant: the projection sorts by key.
    contexts: BTreeMap<String, ContextDraft>,
    events_observed: u64,
    events_retained: u64,
    events_dropped: u64,
    metadata_bytes: i64,
    scripts_observed: u64,
    invalid_scripts: u64,
    invalid_contexts: u64,
    truncated: bool,
    truncation_reasons: BTreeSet<String>,
}

/// UTF-16 code units of an optional JavaScript string.
fn units(text: Option<&str>) -> i64 {
    text.map_or(0, |text| text.encode_utf16().count() as i64)
}

fn script_bytes(draft: &ScriptDraft) -> i64 {
    RETAINED_OBJECT_OVERHEAD_BYTES
        + 2 * (units(Some(&draft.raw_url)) * 2
            + units(draft.context_key.as_deref())
            + units(draft.cdp_hash.as_deref()))
}

fn context_bytes(draft: &ContextDraft) -> i64 {
    RETAINED_OBJECT_OVERHEAD_BYTES
        + 2 * (units(Some(&draft.key))
            + units(draft.name.as_deref())
            + units(draft.origin.as_deref()))
}

/// `numberValue` + `Number.isSafeInteger`, rendered as `String(identifier)`.
fn context_key(value: Option<&Value>) -> Option<String> {
    let number = value?.as_number()?;
    if let Some(integer) = number.as_i64() {
        return (integer.unsigned_abs() <= 9_007_199_254_740_991).then(|| integer.to_string());
    }
    let float = number.as_f64()?;
    (float.is_finite() && float.fract() == 0.0 && float.abs() <= 9_007_199_254_740_991.0)
        .then(|| format!("{}", float as i64))
}

impl CaptureState {
    /// `ingestEvent`.
    pub(crate) fn ingest(&mut self, event: Event) {
        match event.method.as_str() {
            "Debugger.scriptParsed" => {
                self.events_observed += 1;
                self.ingest_script(&event.params);
            }
            "Debugger.scriptFailedToParse" => {
                self.events_observed += 1;
                self.invalid_scripts += 1;
                self.retain_event(0);
            }
            "Runtime.executionContextCreated"
            | "Runtime.executionContextDestroyed"
            | "Runtime.executionContextsCleared" => {
                self.events_observed += 1;
                self.ingest_context(&event.method, &event.params);
            }
            _ => {}
        }
    }

    fn ingest_script(&mut self, params: &Value) {
        self.scripts_observed += 1;
        let Some(raw_url) = params.get("url").and_then(Value::as_str) else {
            self.invalid_scripts += 1;
            self.retain_event(0);
            return;
        };
        let length = params
            .get("length")
            .and_then(Value::as_f64)
            .filter(|length| {
                length.is_finite()
                    && length.fract() == 0.0
                    && *length >= 0.0
                    && *length <= 9_007_199_254_740_991.0
            });
        let draft = ScriptDraft {
            raw_url: raw_url.to_owned(),
            context_key: context_key(params.get("executionContextId")),
            cdp_hash: params
                .get("hash")
                .and_then(Value::as_str)
                .map(str::to_owned),
            length: length.map(|length| length as u64),
            is_module: params.get("isModule").and_then(Value::as_bool),
        };
        if self.retain_event(script_bytes(&draft)) {
            self.scripts.push(draft);
        }
    }

    fn ingest_context(&mut self, method: &str, params: &Value) {
        if method == "Runtime.executionContextsCleared" {
            let delta: i64 = self
                .contexts
                .values()
                .map(|context| {
                    let cleared = ContextDraft {
                        state: "cleared",
                        ..context.clone()
                    };
                    context_bytes(&cleared) - context_bytes(context)
                })
                .sum();
            if self.replace_metadata(delta) {
                for context in self.contexts.values_mut() {
                    context.state = "cleared";
                }
                self.retain_event(0);
            }
            return;
        }
        let created = method == "Runtime.executionContextCreated";
        let runtime_context = if created {
            params.get("context").filter(|value| value.is_object())
        } else {
            Some(params)
        };
        let key =
            context_key(runtime_context.and_then(|context| {
                context.get(if created { "id" } else { "executionContextId" })
            }));
        let Some(key) = key else {
            self.invalid_contexts += 1;
            self.retain_event(0);
            return;
        };
        let previous = self.contexts.get(&key).cloned();
        let text = |field: &str| {
            runtime_context
                .and_then(|context| context.get(field))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let draft = ContextDraft {
            key: key.clone(),
            state: if created { "created" } else { "destroyed" },
            name: if created {
                text("name")
            } else {
                previous.as_ref().and_then(|context| context.name.clone())
            },
            origin: if created {
                text("origin")
            } else {
                previous.as_ref().and_then(|context| context.origin.clone())
            },
        };
        let bytes = context_bytes(&draft) - previous.as_ref().map_or(0, context_bytes);
        if self.retain_event(bytes) {
            self.contexts.insert(key, draft);
        }
    }

    fn retain_event(&mut self, bytes: i64) -> bool {
        if !self.replace_metadata(bytes) {
            return false;
        }
        self.events_retained += 1;
        true
    }

    fn replace_metadata(&mut self, delta: i64) -> bool {
        if self.metadata_bytes + delta > MAX_RETAINED_METADATA_BYTES {
            self.events_dropped += 1;
            self.truncated = true;
            self.truncation_reasons.insert(BUDGET_EXCEEDED.to_owned());
            return false;
        }
        self.metadata_bytes += delta;
        true
    }
}

/// `describeInspectorTargetLimitations`.
pub(crate) fn target_limitations(attachment_unknown: bool) -> Vec<Value> {
    let mut limitations = vec![
        "REA attaches to an already-running exact target and never launches, resumes, evaluates, pauses, or mutates it.",
        "Only Runtime.enable and Debugger.enable are sent; source text, object values, EventEmitter activity, and Electron IPC are not inspected.",
        "The selected endpoint and target ID authorize observation; discovery file locations can remain unresolved and do not prove filesystem identity.",
        "Node discovery reports a best-effort pathname rather than an encoded file URL; lossy Windows paths and ambiguous underscores are preserved without guessing a file path.",
        "Every target exposed by the selected Inspector endpoint is eligible for observation; target IDs and locations are not authenticated as operating-system process identity.",
    ];
    if attachment_unknown {
        limitations.push(
            "Inspector discovery did not report the target's current debugger attachment state; it is retained as unknown, and observation rejects only targets explicitly marked attached.",
        );
    }
    limitations.push("No runtime graph depth is traversed because passive Inspector events do not establish require/import caller edges.");
    limitations
        .into_iter()
        .map(|text| Value::String(text.to_owned()))
        .collect()
}

/// The authorized target facts the projection embeds.
pub(crate) struct AuthorizedTarget {
    pub id: String,
    pub kind: String,
    pub attached: Option<bool>,
    pub location: Value,
}

pub(crate) struct Request<'a> {
    pub runtime_kind: Option<&'a str>,
    pub observation_ms: u64,
}

fn script(draft: &ScriptDraft, location: Value) -> (String, Value) {
    let stable = json!({
        "location": location,
        "execution_context_key": draft.context_key,
        "cdp_hash": draft.cdp_hash,
        "length": draft.length,
        "is_module": draft.is_module,
    });
    let digest = Sha256::digest(stable.to_string().as_bytes());
    let key = format!("v8_script_{}", hex(&digest));
    let item = json!({
        "script_key": key,
        "location": location,
        "execution_context_key": draft.context_key,
        "cdp_hash": draft.cdp_hash,
        "length": draft.length,
        "is_module": draft.is_module,
        "status": "observed-loaded",
    });
    (key, item)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `finalizeInspectorCapture`; `verify` authorizes every distinct script URL,
/// otherwise reported locations are projected without filesystem access.
pub(crate) fn finalize(
    request: &Request<'_>,
    runtime: &Value,
    target: &AuthorizedTarget,
    state: &CaptureState,
    verify: bool,
    cancellation: &Cancellation,
    operation: &str,
) -> Result<Value, AnalysisError> {
    let check = || match cancellation.reason() {
        Some(_) if verify => Err(AnalysisError::cancelled(operation)),
        _ => Ok(()),
    };
    check()?;
    let mut excluded_locations = 0_u64;
    let mut unresolved = 0_u64;
    let mut scripts: BTreeMap<String, Value> = BTreeMap::new();
    if verify {
        let mut decisions: BTreeMap<&str, Decision> = BTreeMap::new();
        for draft in &state.scripts {
            if !decisions.contains_key(draft.raw_url.as_str()) {
                check()?;
                let decision = scope::authorize_location(&draft.raw_url, cancellation, operation)?;
                check()?;
                decisions.insert(&draft.raw_url, decision);
            }
        }
        check()?;
        for draft in &state.scripts {
            match &decisions[draft.raw_url.as_str()] {
                Decision::Denied => excluded_locations += 1,
                Decision::Allowed(location) => {
                    let (key, item) = script(draft, location.clone());
                    scripts.insert(key, item);
                }
            }
        }
    } else {
        for draft in &state.scripts {
            let location = match scope::project_reported_url(&draft.raw_url) {
                Decision::Allowed(location) => location,
                Decision::Denied => json!({
                    "kind": "unresolved",
                    "reported_url": draft.raw_url,
                    "reason": "location-authorization-not-attempted",
                }),
            };
            if location["kind"] == "unresolved" {
                unresolved += 1;
            }
            let (key, item) = script(draft, location);
            scripts.insert(key, item);
        }
    }
    let contexts: Vec<Value> = state
        .contexts
        .values()
        .map(|context| {
            json!({
                "context_key": context.key,
                "state": context.state,
                "name": context.name,
                "origin": context.origin,
            })
        })
        .collect();
    check()?;
    let mut unknowns: Vec<String> = Vec::new();
    if target.location["kind"] == "unresolved" {
        unknowns.push("The discovery-reported file location cannot be verified; loaded script locations are resolved independently from Debugger.scriptParsed.".to_owned());
    }
    if unresolved > 0 {
        unknowns.push(format!(
            "{unresolved} observed script location{} unverified; raw URLs and script metadata are retained.",
            if unresolved == 1 { " remains" } else { "s remain" }
        ));
    }
    if state.invalid_contexts > 0 {
        let count = state.invalid_contexts;
        unknowns.push(format!(
            "{count} execution-context lifecycle {} excluded; the affected contexts' lifecycle state is unknown.",
            if count == 1 {
                "event with a missing or malformed execution-context ID was"
            } else {
                "events with a missing or malformed execution-context ID were"
            }
        ));
    }
    unknowns.extend(
        [
            "Scripts collected before attachment may have been garbage-collected and therefore omitted.",
            "A bounded observation window cannot establish that an unobserved script or behavior never occurs.",
            "The declared Node/Electron process role is not authenticated by the Inspector protocol.",
        ]
        .map(str::to_owned),
    );
    let mut target_value = Map::new();
    target_value.insert("target_id".into(), Value::String(target.id.clone()));
    target_value.insert("protocol_type".into(), Value::String(target.kind.clone()));
    target_value.insert(
        "attached".into(),
        target.attached.map_or(Value::Null, Value::Bool),
    );
    target_value.insert("location".into(), target.location.clone());
    target_value.insert(
        "runtime_kind".into(),
        Value::String(request.runtime_kind.unwrap_or("unknown").to_owned()),
    );
    target_value.insert(
        "runtime_kind_authority".into(),
        Value::String(
            if request.runtime_kind.is_none() {
                "not-declared"
            } else {
                "caller-declared-unverified"
            }
            .to_owned(),
        ),
    );
    Ok(json!({
        "runtime": runtime,
        "target": target_value,
        "capture": {
            "observation_ms": request.observation_ms,
            "events_observed": state.events_observed,
            "events_retained": state.events_retained,
            "events_dropped": state.events_dropped,
            "metadata_bytes_retained": state.metadata_bytes,
            "truncated": state.truncated,
            "truncation_reasons": state.truncation_reasons.iter().collect::<Vec<_>>(),
        },
        "scripts": {
            "items": scripts.into_values().collect::<Vec<_>>(),
            "observed_total": state.scripts_observed,
            "excluded": {
                "unsupported_location": excluded_locations,
                "invalid_protocol_value": state.invalid_scripts,
            },
        },
        "execution_contexts": contexts,
        "directly_observed": [
            "Debugger.scriptParsed established script presence within the bounded capture window.",
            "Runtime execution-context lifecycle events established context creation, destruction, or clearing.",
        ],
        "unavailable_without_instrumentation": [
            "require/import caller-to-callee edges",
            "EventEmitter emissions and listener invocation",
            "Electron IPC messages and handlers",
            "script unload events",
        ],
        "unknowns": unknowns,
        "limitations": target_limitations(target.attached.is_none()),
    }))
}
