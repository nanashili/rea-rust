//! `parseRuntimeCaptures` (`javascriptRuntimeReconciliationCaptureParsing.ts`
//! and `javascriptRuntimeReconciliationActive.ts`).
//!
//! Envelope identity, parameter and target checks are ported with their
//! issue paths and messages. The complete web, Electron, V8 Inspector and
//! active Electron result schemas have no native owner; the fields this
//! workflow reads are revalidated structurally and a failure is reported once
//! at `normalized_result` instead of the original's per-field Zod issues.
use super::paths;
use super::{custom, digest, join, str_of};
use crate::javascript::graph_evidence;
use rea_core::analysis_error::InputIssue;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

/// Normalized inspection, as the original `ParsedRuntimeCapture.inspection`.
pub struct Inspection {
    pub target: Value,
    pub frames: Vec<Value>,
    pub scripts: Vec<Value>,
    pub workers: Vec<Value>,
    /// Canonical completeness (`status`, `conditions`, `truncated_sections`,
    /// `unavailable_sections`, `dropped_events.scripts`).
    pub completeness: Value,
}

pub struct Capture {
    pub kind: &'static str,
    pub evidence: Value,
    pub inspection: Inspection,
    pub capture_sha256: String,
    pub scripts_complete_within_scope: bool,
}

impl Capture {
    pub fn evidence_id(&self) -> &str {
        str_of(&self.evidence["evidence_id"])
    }
    pub fn target_id(&self) -> &str {
        str_of(&self.inspection.target["target_id"])
    }
    fn sections(&self, key: &str) -> impl Iterator<Item = &str> {
        self.inspection.completeness[key]
            .as_array()
            .into_iter()
            .flatten()
            .map(str_of)
    }
    pub fn truncated_section(&self, section: &str) -> bool {
        self.sections("truncated_sections")
            .any(|value| value == section)
    }
    pub fn unavailable_section(&self, section: &str) -> bool {
        self.sections("unavailable_sections")
            .any(|value| value == section)
    }
    pub fn has_unavailable_sections(&self) -> bool {
        self.sections("unavailable_sections").next().is_some()
    }
    pub fn condition_truncated(&self) -> bool {
        self.sections("conditions")
            .any(|value| value == "truncated")
    }
    pub fn complete_within_window(&self) -> bool {
        self.inspection.completeness["status"] == "complete_within_window"
    }
}

type Issues = Vec<InputIssue>;

pub fn parse_runtime_captures(observations: &Value) -> Result<Vec<Capture>, Issues> {
    let mut captures = Vec::new();
    for (index, observation) in observations.as_array().into_iter().flatten().enumerate() {
        let path = [json!("runtime_observations"), json!(index)];
        captures.push(parse_runtime_capture(observation, &path)?);
    }
    captures.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
    Ok(captures)
}

fn parse_runtime_capture(input: &Value, path: &[Value]) -> Result<Capture, Issues> {
    let evidence = graph_evidence::parse_evidence_input(input, path)?;
    match evidence["operation"].as_str() {
        Some("inspect_web_page") => parse_cdp_capture(evidence, path, "browser"),
        Some("inspect_electron_page") => parse_cdp_capture(evidence, path, "electron"),
        Some("observe_javascript_runtime") => parse_v8_capture(evidence, path),
        Some("capture_electron_scenario") => parse_active_capture(evidence, path),
        _ => Err(vec![custom(
            path,
            "Runtime reconciliation requires inspect_web_page, inspect_electron_page, observe_javascript_runtime, or capture_electron_scenario Evidence",
        )]),
    }
}

struct Identity {
    operation: &'static str,
    predicate: &'static str,
    provider_id: &'static str,
    provider_name: &'static str,
    provider_version: &'static str,
    authority: &'static str,
    confidence: &'static str,
}

/// `assertEvidenceIdentity`.
fn assert_identity(evidence: &Value, expected: &Identity, path: &[Value]) -> Result<(), Issues> {
    let provider = &evidence["provider"];
    if evidence["operation"] == expected.operation
        && evidence["predicate_type"] == expected.predicate
        && provider["id"] == expected.provider_id
        && provider["name"] == expected.provider_name
        && provider["version"] == expected.provider_version
        && evidence["authority"] == expected.authority
        && evidence["confidence"] == expected.confidence
    {
        return Ok(());
    }
    Err(vec![custom(
        path,
        format!(
            "Evidence does not match the supported {} contract",
            expected.operation
        ),
    )])
}

fn invalid_result(path: &[Value]) -> Issues {
    vec![custom(
        &join(path, &[json!("normalized_result")]),
        "Runtime Evidence result does not satisfy its schema.",
    )]
}

fn issue(path: Vec<Value>, reason: &'static str, expected: Option<Value>) -> InputIssue {
    InputIssue {
        path,
        reason,
        message: None,
        expected,
        minimum: None,
        maximum: None,
    }
}

/// Parameters object (`z.object(...).passthrough()`).
fn parameters<'a>(evidence: &'a Value, path: &[Value]) -> Result<&'a Map<String, Value>, Issues> {
    evidence["parameters"].as_object().ok_or_else(|| {
        vec![issue(
            join(path, &[json!("parameters")]),
            "invalid_type",
            Some(json!("object")),
        )]
    })
}

/// `z.string().min(1)` (optionally trimmed) at `parameters.<field>`.
fn string_field(
    parameters: &Map<String, Value>,
    field: &str,
    trim: bool,
    path: &[Value],
    issues: &mut Issues,
) -> Option<String> {
    let at = join(path, &[json!("parameters"), json!(field)]);
    match parameters.get(field) {
        None => {
            issues.push(issue(at, "missing_argument", Some(json!("string"))));
            None
        }
        Some(Value::String(value)) => {
            let value = if trim {
                value.trim().to_owned()
            } else {
                value.clone()
            };
            if value.is_empty() {
                let mut bounded = issue(at, "out_of_range", None);
                bounded.minimum = Some(1.0);
                issues.push(bounded);
                return None;
            }
            Some(value)
        }
        Some(_) => {
            issues.push(issue(at, "invalid_type", Some(json!("string"))));
            None
        }
    }
}

/// `browserEndpointSchema`.
fn endpoint_field(
    parameters: &Map<String, Value>,
    field: &str,
    path: &[Value],
    issues: &mut Issues,
) {
    let Some(value) = string_field(parameters, field, false, path, issues) else {
        return;
    };
    let at = join(path, &[json!("parameters"), json!(field)]);
    match url::Url::parse(&value) {
        Err(_) => issues.push(custom(&at, "Invalid CDP endpoint URL")),
        Ok(url) if !paths::http_discovery_origin(&url) => issues.push(custom(
            &at,
            "CDP endpoint must be an explicit-port HTTP URL on 127.0.0.1 or ::1",
        )),
        Ok(_) => {}
    }
}

fn boolean_field(
    parameters: &Map<String, Value>,
    field: &str,
    path: &[Value],
    issues: &mut Issues,
) -> Option<bool> {
    let at = join(path, &[json!("parameters"), json!(field)]);
    match parameters.get(field) {
        Some(Value::Bool(value)) => Some(*value),
        None => {
            issues.push(issue(at, "missing_argument", Some(json!("boolean"))));
            None
        }
        Some(_) => {
            issues.push(issue(at, "invalid_type", Some(json!("boolean"))));
            None
        }
    }
}

fn strings(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

fn nullable(value: &Value, check: fn(&Value) -> bool) -> bool {
    value.is_null() || check(value)
}

/// `scriptsComplete`.
fn scripts_complete(completeness: &Value) -> bool {
    let contains = |key: &str| {
        completeness[key]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "scripts"))
    };
    !contains("truncated_sections")
        && !contains("unavailable_sections")
        && completeness["dropped_events"]["scripts"].as_u64() == Some(0)
}

/// Structural check of the canonical completeness fields this workflow reads.
fn valid_completeness(completeness: &Value) -> bool {
    completeness["status"].is_string()
        && strings(&completeness["conditions"])
        && strings(&completeness["truncated_sections"])
        && strings(&completeness["unavailable_sections"])
        && completeness["dropped_events"]["scripts"].is_u64()
}

/// The location field of one web/Electron entity: `url`, `file_path` or (for
/// scripts) `unresolved_location`.
fn has_location(entity: &Value, electron: bool) -> bool {
    if electron {
        entity["file_path"].is_string() || entity["unresolved_location"]["reported_url"].is_string()
    } else {
        entity["url"].is_string() || entity["unresolved_location"]["reported_url"].is_string()
    }
}

/// Apply schema defaults and check the inspection fields read downstream.
fn normalize_cdp_inspection(result: &Value, electron: bool) -> Option<Inspection> {
    let target = result["target"].clone();
    let valid_target = target["target_id"].is_string()
        && target["type"].is_string()
        && target["title"].is_string()
        && (electron || target["origin"].is_string())
        && has_location(&target, electron);
    let frames = result["frames"].as_array()?.clone();
    let valid_frames = frames.iter().all(|frame| {
        frame["frame_id"].is_string()
            && nullable(&frame["parent_frame_id"], Value::is_string)
            && has_location(frame, electron)
    });
    let mut scripts = result["scripts"]["items"].as_array()?.clone();
    for script in &mut scripts {
        let object = script.as_object_mut()?;
        object.entry("frame_id").or_insert(Value::Null);
    }
    let valid_scripts = scripts.iter().all(|script| {
        script["script_key"].is_string()
            && nullable(&script["frame_id"], Value::is_string)
            && has_location(script, electron)
            && script["source"]["included"].is_boolean()
            && (script["source"]["included"] != true
                || script["source"]["artifact"]["sha256"].is_string())
    });
    let mut workers = result["workers"].as_array()?.clone();
    for worker in &mut workers {
        let object = worker.as_object_mut()?;
        object.entry("opener_target_id").or_insert(Value::Null);
        object.entry("parent_frame_id").or_insert(Value::Null);
    }
    let valid_workers = workers.iter().all(|worker| {
        worker["target_id"].is_string()
            && worker["type"].is_string()
            && nullable(&worker["parent_frame_id"], Value::is_string)
            && has_location(worker, electron)
    });
    let completeness = result["completeness"].clone();
    (valid_target
        && valid_frames
        && valid_scripts
        && valid_workers
        && valid_completeness(&completeness))
    .then_some(Inspection {
        target,
        frames,
        scripts,
        workers,
        completeness,
    })
}

/// The inspection with schema defaults applied, as the parsed result the
/// original digests.
fn parsed_cdp_result(result: &Value, inspection: &Inspection) -> Value {
    let mut parsed = result.clone();
    parsed["scripts"]["items"] = Value::Array(inspection.scripts.clone());
    parsed["workers"] = Value::Array(inspection.workers.clone());
    parsed
}

/// `parseBrowserCapture` / `parseElectronCapture`.
fn parse_cdp_capture(
    evidence: Value,
    path: &[Value],
    kind: &'static str,
) -> Result<Capture, Issues> {
    let electron = kind == "electron";
    let identity = if electron {
        Identity {
            operation: "inspect_electron_page",
            predicate: "rea.electron-page-inspection",
            provider_id: "rea-cdp-electron",
            provider_name: "REA Electron file-page CDP observation provider",
            provider_version: "1",
            authority: "external-service",
            confidence: "observed",
        }
    } else {
        Identity {
            operation: "inspect_web_page",
            predicate: "rea.web-page-inspection",
            provider_id: "rea-cdp-browser",
            provider_name: "REA Chrome DevTools Protocol observation provider",
            provider_version: "2",
            authority: "external-service",
            confidence: "observed",
        }
    };
    assert_identity(&evidence, &identity, path)?;
    let result = &evidence["normalized_result"];
    let inspection =
        normalize_cdp_inspection(result, electron).ok_or_else(|| invalid_result(path))?;
    let source_included = inspection
        .scripts
        .iter()
        .any(|script| script["source"]["included"] == true);
    let parameters = parameters(&evidence, path)?;
    let mut issues = Vec::new();
    let target_id = string_field(parameters, "target_id", true, path, &mut issues);
    let include_sources = boolean_field(parameters, "include_script_sources", path, &mut issues);
    let mut allowed = BTreeSet::new();
    if electron {
        endpoint_field(parameters, "cdp_endpoint", path, &mut issues);
    } else {
        recorded_endpoint_field(parameters, path, &mut issues);
        allowed_origins(parameters, path, &mut issues, &mut allowed);
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    if target_id.as_deref() != Some(str_of(&inspection.target["target_id"])) {
        return Err(vec![custom(
            &join(path, &[json!("parameters"), json!("target_id")]),
            "Runtime Evidence target disagrees with its captured result",
        )]);
    }
    if !electron && !allowed.contains(str_of(&inspection.target["origin"])) {
        return Err(vec![custom(
            &join(path, &[json!("parameters"), json!("allowed_origins")]),
            "Browser Evidence target is outside its recorded origin scope",
        )]);
    }
    if source_included && include_sources != Some(true) {
        return Err(vec![custom(
            &join(
                path,
                &[json!("parameters"), json!("include_script_sources")],
            ),
            "Runtime Evidence contains source without source-capture selection",
        )]);
    }
    let capture_sha256 =
        digest(&parsed_cdp_result(result, &inspection)).map_err(|_| invalid_result(path))?;
    let scripts_complete_within_scope = scripts_complete(&inspection.completeness);
    Ok(Capture {
        kind,
        evidence,
        inspection,
        capture_sha256,
        scripts_complete_within_scope,
    })
}

/// `recordedBrowserObservationEndpointSchema` at `parameters.cdp_endpoint`.
fn recorded_endpoint_field(parameters: &Map<String, Value>, path: &[Value], issues: &mut Issues) {
    let Some(value) = string_field(parameters, "cdp_endpoint", false, path, issues) else {
        return;
    };
    let accepted = url::Url::parse(&value).is_ok_and(|url| {
        paths::http_discovery_origin(&url) || paths::redacted_browser_socket(&url)
    });
    if !accepted {
        issues.push(custom(
            &join(path, &[json!("parameters"), json!("cdp_endpoint")]),
            "Recorded CDP endpoint must be a loopback HTTP origin or a redacted browser WebSocket URL",
        ));
    }
}

/// `browserAllowedOriginsSchema` (default `[]`).
fn allowed_origins(
    parameters: &Map<String, Value>,
    path: &[Value],
    issues: &mut Issues,
    allowed: &mut BTreeSet<String>,
) {
    let at = join(path, &[json!("parameters"), json!("allowed_origins")]);
    let items = match parameters.get("allowed_origins") {
        None => return,
        Some(Value::Array(items)) => items,
        Some(_) => {
            issues.push(issue(at, "invalid_type", Some(json!("array"))));
            return;
        }
    };
    for (index, item) in items.iter().enumerate() {
        let item_path = join(&at, &[json!(index)]);
        match item.as_str() {
            None => issues.push(issue(item_path, "invalid_type", Some(json!("string")))),
            Some("") => {
                let mut bounded = issue(item_path, "out_of_range", None);
                bounded.minimum = Some(1.0);
                issues.push(bounded);
            }
            Some(value) => match paths::exact_origin(value) {
                Some(origin) => {
                    allowed.insert(origin);
                }
                None => issues.push(custom(
                    &item_path,
                    "Expected one exact HTTP(S) origin without a path or wildcard",
                )),
            },
        }
    }
}

fn valid_runtime_location(location: &Value) -> bool {
    match location["kind"].as_str() {
        Some("file") => location["file_path"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        Some("url") => {
            location["origin"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
                && location["sanitized_url"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
        }
        Some("builtin") => location["specifier"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        Some("unresolved") => {
            location["reported_url"].is_string()
                && matches!(
                    location["reason"].as_str(),
                    Some("unverifiable-file-location" | "location-authorization-not-attempted")
                )
        }
        _ => false,
    }
}

/// Structural check of `javascriptRuntimeObservationSchema` fields read here.
fn valid_v8_result(result: &Value) -> bool {
    let target = &result["target"];
    let scripts = &result["scripts"];
    target["target_id"]
        .as_str()
        .is_some_and(|value| !value.is_empty())
        && target["protocol_type"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
        && nullable(&target["attached"], Value::is_boolean)
        && target["runtime_kind"].is_string()
        && valid_runtime_location(&target["location"])
        && result["capture"]["truncated"].is_boolean()
        && result["capture"]["events_dropped"].is_u64()
        && scripts["excluded"]["unsupported_location"].is_u64()
        && scripts["excluded"]["invalid_protocol_value"].is_u64()
        && scripts["items"].as_array().is_some_and(|items| {
            items.iter().all(|script| {
                script["script_key"]
                    .as_str()
                    .is_some_and(|key| key.starts_with("v8_script_"))
                    && valid_runtime_location(&script["location"])
                    && nullable(&script["execution_context_key"], Value::is_string)
                    && nullable(&script["cdp_hash"], Value::is_string)
                    && nullable(&script["length"], Value::is_u64)
                    && nullable(&script["is_module"], Value::is_boolean)
            })
        })
}

/// `parseV8Capture`.
fn parse_v8_capture(evidence: Value, path: &[Value]) -> Result<Capture, Issues> {
    assert_identity(
        &evidence,
        &Identity {
            operation: "observe_javascript_runtime",
            predicate: "rea.javascript-runtime-observation",
            provider_id: "rea-v8-inspector",
            provider_name: "REA passive Node/Electron V8 Inspector provider",
            provider_version: "1",
            authority: "external-service",
            confidence: "observed",
        },
        path,
    )?;
    let result = &evidence["normalized_result"];
    if !valid_v8_result(result) {
        return Err(invalid_result(path));
    }
    let parameters = parameters(&evidence, path)?;
    let mut issues = Vec::new();
    endpoint_field(parameters, "inspector_endpoint", path, &mut issues);
    let target_id = string_field(parameters, "target_id", true, path, &mut issues);
    let runtime_kind = match parameters.get("runtime_kind") {
        None => None,
        Some(Value::String(kind))
            if matches!(
                kind.as_str(),
                "node" | "electron-main" | "electron-preload" | "electron-renderer"
            ) =>
        {
            Some(kind.clone())
        }
        Some(_) => {
            issues.push(InputIssue {
                path: join(path, &[json!("parameters"), json!("runtime_kind")]),
                reason: "invalid_value",
                message: None,
                expected: Some(json!([
                    "node",
                    "electron-main",
                    "electron-preload",
                    "electron-renderer"
                ])),
                minimum: None,
                maximum: None,
            });
            None
        }
    };
    if !issues.is_empty() {
        return Err(issues);
    }
    let target = &result["target"];
    if target_id.as_deref() != target["target_id"].as_str()
        || runtime_kind
            .as_ref()
            .is_some_and(|kind| target["runtime_kind"] != kind.as_str())
    {
        return Err(vec![custom(
            &join(path, &[json!("parameters"), json!("target_id")]),
            "Runtime Evidence target or declared role disagrees with its result",
        )]);
    }
    let invalid_builtin = |location: &Value| {
        location["kind"] == "builtin" && !str_of(&location["specifier"]).starts_with("node:")
    };
    if invalid_builtin(&target["location"]) {
        return Err(vec![custom(
            &join(
                path,
                &[
                    json!("normalized_result"),
                    json!("target"),
                    json!("location"),
                ],
            ),
            "Runtime Evidence contains an invalid builtin location",
        )]);
    }
    for (index, script) in result["scripts"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        if invalid_builtin(&script["location"]) {
            return Err(vec![custom(
                &join(
                    path,
                    &[
                        json!("normalized_result"),
                        json!("scripts"),
                        json!("items"),
                        json!(index),
                        json!("location"),
                    ],
                ),
                "Runtime Evidence contains an invalid builtin location",
            )]);
        }
    }
    let capture_sha256 = digest(result).map_err(|_| invalid_result(path))?;
    let inspection = normalize_v8_inspection(result);
    Ok(Capture {
        kind: "v8-inspector",
        evidence,
        inspection,
        capture_sha256,
        scripts_complete_within_scope: false,
    })
}

/// `runtimeLocation`.
fn runtime_location(location: &Value, into: &mut Map<String, Value>) {
    match location["kind"].as_str() {
        Some("unresolved") => {
            into.insert("unresolved_location".into(), location.clone());
        }
        Some("file") => {
            into.insert("file_path".into(), location["file_path"].clone());
        }
        Some("url") => {
            into.insert("url".into(), location["sanitized_url"].clone());
        }
        _ => {
            into.insert("url".into(), location["specifier"].clone());
        }
    }
}

/// The fields of `classifyBrowserCompleteness` read downstream.
fn classify_completeness(
    policy_filtered: bool,
    attach_limited: bool,
    truncated_sections: &[&str],
    unavailable_sections: &BTreeSet<&str>,
    dropped_scripts: u64,
) -> Value {
    let truncated = !truncated_sections.is_empty() || dropped_scripts > 0;
    let attach_limited = attach_limited || !unavailable_sections.is_empty();
    let status = if truncated {
        "truncated"
    } else if policy_filtered {
        "policy_filtered"
    } else if attach_limited {
        "attach_limited"
    } else {
        "complete_within_window"
    };
    let mut conditions = Vec::new();
    if attach_limited {
        conditions.push("attach_limited");
    }
    if policy_filtered {
        conditions.push("policy_filtered");
    }
    if truncated {
        conditions.push("truncated");
    }
    if conditions.is_empty() {
        conditions.push("complete_within_window");
    }
    json!({
        "status": status,
        "conditions": conditions,
        "truncated_sections": truncated_sections,
        "unavailable_sections": unavailable_sections,
        "dropped_events": { "scripts": dropped_scripts },
    })
}

/// `normalizeV8Inspection`.
fn normalize_v8_inspection(result: &Value) -> Inspection {
    let source = &result["target"];
    let mut target = Map::new();
    target.insert("target_id".into(), source["target_id"].clone());
    target.insert("type".into(), source["protocol_type"].clone());
    target.insert("title".into(), source["runtime_kind"].clone());
    target.insert("attached".into(), source["attached"].clone());
    runtime_location(&source["location"], &mut target);
    let scripts = result["scripts"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|script| {
            let mut item = Map::new();
            item.insert("script_key".into(), script["script_key"].clone());
            item.insert("frame_id".into(), script["execution_context_key"].clone());
            runtime_location(&script["location"], &mut item);
            item.insert("cdp_hash".into(), script["cdp_hash"].clone());
            item.insert("length".into(), script["length"].clone());
            item.insert("is_module".into(), script["is_module"].clone());
            item.insert("language".into(), Value::Null);
            item.insert(
                "source".into(),
                json!({
                    "included": false,
                    "reason": "V8 Inspector source capture is outside passive authority.",
                }),
            );
            Value::Object(item)
        })
        .collect();
    let excluded = &result["scripts"]["excluded"];
    let mut unavailable: BTreeSet<&str> = ["frames", "script_sources", "workers"].into();
    if excluded["invalid_protocol_value"].as_u64().unwrap_or(0) > 0 {
        unavailable.insert("scripts");
    }
    let truncated: &[&str] = if result["capture"]["truncated"] == true {
        &["scripts"]
    } else {
        &[]
    };
    let completeness = classify_completeness(
        excluded["unsupported_location"].as_u64().unwrap_or(0) > 0,
        true,
        truncated,
        &unavailable,
        result["capture"]["events_dropped"].as_u64().unwrap_or(0),
    );
    Inspection {
        target: Value::Object(target),
        frames: Vec::new(),
        scripts,
        workers: Vec::new(),
        completeness,
    }
}

/// `parseActiveElectronCapture`; its issues are relative to the Evidence.
fn parse_active_capture(evidence: Value, path: &[Value]) -> Result<Capture, Issues> {
    let provider = &evidence["provider"];
    if !(evidence["operation"] == "capture_electron_scenario"
        && evidence["predicate_type"] == "rea.electron-active-scenario"
        && provider["id"] == "rea-playwright-electron-active"
        && provider["name"] == "REA Playwright active Electron observation provider"
        && provider["version"] == "1"
        && evidence["authority"] == "controlled-replay"
        && evidence["confidence"] == "observed")
    {
        return Err(vec![custom(
            path,
            "Evidence does not match the supported capture_electron_scenario contract",
        )]);
    }
    let result = &evidence["normalized_result"];
    let application_path = result["application"]["application_path"]
        .as_str()
        .filter(|value| value.starts_with('/'))
        .ok_or_else(|| invalid_result(path))?
        .to_owned();
    let parameters = parameters(&evidence, path)?;
    let mut issues = Vec::new();
    let mut absolute = |field: &str| -> Option<String> {
        let value = string_field(parameters, field, false, path, &mut issues)?;
        if value.starts_with('/') {
            return Some(value);
        }
        issues.push(custom(
            &join(path, &[json!("parameters"), json!(field)]),
            "Invalid input",
        ));
        None
    };
    let declared_path = absolute("application_path");
    let root = absolute("application_root");
    if !issues.is_empty() {
        return Err(issues);
    }
    if declared_path.as_deref() != Some(application_path.as_str())
        || !paths::is_path_within_root(root.as_deref().unwrap_or_default(), &application_path)
    {
        return Err(vec![custom(
            &join(
                path,
                &[
                    json!("normalized_result"),
                    json!("application"),
                    json!("application_path"),
                ],
            ),
            "Active Electron Evidence application path disagrees with its configured root",
        )]);
    }
    let capture_sha256 = digest(result).map_err(|_| invalid_result(path))?;
    let path_digest = digest(&json!(application_path)).map_err(|_| invalid_result(path))?;
    let unavailable: BTreeSet<&str> = ["frames", "scripts", "script_sources", "workers"].into();
    let inspection = Inspection {
        target: json!({
            "target_id": format!("electron-active:{}", &path_digest[..32]),
            "type": "electron-application",
            "title": application_path,
            "attached": true,
            "file_path": application_path,
        }),
        frames: Vec::new(),
        scripts: Vec::new(),
        workers: Vec::new(),
        completeness: classify_completeness(false, false, &[], &unavailable, 0),
    };
    Ok(Capture {
        kind: "electron-active",
        evidence,
        inspection,
        capture_sha256,
        scripts_complete_within_scope: false,
    })
}
