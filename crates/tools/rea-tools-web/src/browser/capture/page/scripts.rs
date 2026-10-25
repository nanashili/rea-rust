//! Script and worker inventories: `src/browser/CdpPageCaptureScripts.ts`,
//! `CdpPageCaptureWorkers.ts`, `CdpScriptSourceBudget.ts` and the script
//! identities of `src/domain/webInventory.ts`.
use super::super::connection::Rejection;
use super::super::values;
use super::documents::{Resource, hex, resource_key};
use super::events::Script;
use super::{Capture, OPERATION};
use crate::cdp::json_text::canonical_json;
use crate::cdp::observation_error;
use crate::cdp::target_session::Deadline;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

/// `WEB_RUNTIME_LIMITS.sourceBytes` and `commandTimeoutMs`.
const SOURCE_BYTES: usize = 32 * 1024 * 1024;
const SOURCE_DEADLINE: Duration = Duration::from_millis(20_000);
const BYTES_REASON: &str =
    "script source was omitted because the aggregate 32 MiB source budget was exhausted";
const DEADLINE_REASON: &str =
    "script source was omitted because the 20-second source collection deadline elapsed";
const NOT_SELECTED: &str = "source capture was not selected";

fn excluded(reason: &str) -> Value {
    json!({ "included": false, "reason": reason })
}

/// `createCapturedWebScriptReconciler`.
struct Reconciler {
    /// `None` means multiple observations of one raw URL.
    raw: HashMap<String, Option<Value>>,
    keys: HashMap<String, Vec<String>>,
}

impl Reconciler {
    fn new(raw_resources: &[Resource], resources: &[Value]) -> Self {
        let mut raw: HashMap<String, Option<Value>> = HashMap::new();
        for resource in raw_resources {
            let duplicate = raw.contains_key(&resource.raw_url);
            raw.insert(
                resource.raw_url.clone(),
                (!duplicate).then(|| resource.public.clone()),
            );
        }
        let mut keys: HashMap<String, Vec<String>> = HashMap::new();
        for resource in resources {
            keys.entry(resource["url"].as_str().unwrap_or("").to_owned())
                .or_default()
                .push(resource["resource_key"].as_str().unwrap_or("").to_owned());
        }
        for list in keys.values_mut() {
            if list.len() > 1 {
                let unique: BTreeSet<String> = list.drain(..).collect();
                list.extend(unique);
            }
        }
        Self { raw, keys }
    }
    fn reconcile(&self, raw_url: &str, url: &str) -> Value {
        if let Some(Some(public)) = self.raw.get(raw_url) {
            return json!({ "status": "exact", "resource_key": resource_key(public) });
        }
        if let Some(candidates) = self.keys.get(url) {
            return json!({ "status": "ambiguous", "candidate_resource_keys": candidates });
        }
        json!({ "status": "unmatched", "reason": "no_exact_sanitized_url" })
    }
}

/// `CdpScriptSourceBudget`.
struct SourceBudget {
    deadline: Deadline,
    retained: usize,
}

impl SourceBudget {
    fn timed_out(&self) -> bool {
        self.deadline.expired()
    }
    fn admit(&mut self, text: &str) -> bool {
        if text.len() > SOURCE_BYTES - self.retained {
            return false;
        }
        self.retained += text.len();
        true
    }
}

/// `WebSourceMapRequest`; retained for `analyze_web_bundle`.
#[allow(dead_code)]
pub(in crate::browser::capture) struct SourceMapRequest {
    pub script_key: String,
    pub declared_url: String,
    pub fetch_url: String,
}

/// `captureScripts`.
pub(super) fn capture_scripts(
    capture: &mut Capture<'_, '_>,
    raw_resources: &[Resource],
    resources: &[Value],
    frame_ids: &BTreeSet<String>,
) -> Result<(Value, Vec<SourceMapRequest>), AnalysisError> {
    let include = capture.options.include_script_sources;
    let scripts: Vec<Script> = capture.events.scripts.values().cloned().collect();
    let mut budget = (include && !scripts.is_empty()).then(|| SourceBudget {
        deadline: Deadline::new(Some(&capture.conn.cancellation), SOURCE_DEADLINE),
        retained: 0,
    });
    let reconciler = Reconciler::new(raw_resources, resources);
    let mut drafts: Vec<(Value, Option<String>)> = Vec::new();
    for script in &scripts {
        let mut source = excluded(if include {
            DEADLINE_REASON
        } else {
            NOT_SELECTED
        });
        if include && budget.as_ref().is_some_and(SourceBudget::timed_out) {
            capture
                .events
                .completeness
                .exclude("script_sources", "resource_budget_exhausted");
        } else if let (true, Some(budget)) = (include, budget.as_mut()) {
            match script_source(capture, script, budget) {
                Ok(captured) => source = captured,
                Err(error) => {
                    if capture.conn.cancellation.reason().is_some() {
                        return Err(AnalysisError::cancelled(OPERATION));
                    }
                    if budget.timed_out() {
                        capture
                            .events
                            .completeness
                            .exclude("script_sources", "resource_budget_exhausted");
                    } else {
                        return Err(error);
                    }
                }
            }
        }
        let item = json!({
            "frame_id": capture.events.frame_for_script(script, frame_ids),
            "url": script.url,
            "cdp_hash": script.hash,
            "length": script.length,
            "is_module": script.is_module,
            "language": script.language,
            "source_map_url": script.source_map_url,
            "origin": script.origin,
            "resource_reconciliation": reconciler.reconcile(&script.raw_url, &script.url),
            "source": source,
        });
        drafts.push((item, script.source_map_raw_url.clone()));
    }
    drop(budget);
    let total = capture.events.scripts.len();
    if !include {
        capture.events.completeness.exclude_count(
            "script_sources",
            "not_approved",
            Some(total as u64),
        );
    }
    Ok(keyed_inventory(drafts, total))
}

fn script_source(
    capture: &mut Capture<'_, '_>,
    script: &Script,
    budget: &mut SourceBudget,
) -> Result<Value, AnalysisError> {
    let response = capture.send_rejectable(
        "Debugger.getScriptSource",
        json!({ "scriptId": script.script_id }),
        Some(budget.deadline.cancellation().clone()),
    );
    let response = response.map_err(Rejection::into_error)?;
    if capture.conn.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OPERATION));
    }
    let Some(content) = values::string(response.get("scriptSource")) else {
        return Err(observation_error(
            OPERATION,
            "protocol_error",
            Some("Debugger.getScriptSource returned malformed source text: scriptSource must be a string.".to_owned()),
        ));
    };
    if budget.timed_out() {
        capture
            .events
            .completeness
            .exclude("script_sources", "resource_budget_exhausted");
        return Ok(excluded(DEADLINE_REASON));
    }
    if !budget.admit(content) {
        capture
            .events
            .completeness
            .exclude("script_sources", "resource_budget_exhausted");
        return Ok(excluded(BYTES_REASON));
    }
    Ok(json!({
        "included": true,
        "artifact": {
            "sha256": hex(&Sha256::digest(content.as_bytes())),
            "bytes": content.len(),
            "media_type": "text/javascript",
            "charset": "utf-8",
            "text": content,
        },
    }))
}

/// `stableWebScriptKey`.
fn script_key(item: &Value) -> String {
    let identity = json!({
        "url": item["url"],
        "cdp_hash": item["cdp_hash"],
        "length": item["length"],
        "is_module": item["is_module"],
        "language": item["language"],
        "source_map_url": item["source_map_url"],
    });
    format!(
        "scr_{}",
        hex(&Sha256::digest(canonical_json(&identity).as_bytes()))
    )
}

fn source_digest(source: &Value) -> &str {
    if source["included"] == true {
        source["artifact"]["sha256"].as_str().unwrap_or("")
    } else {
        source["reason"].as_str().unwrap_or("")
    }
}

/// `keyAndBuildInventory`.
fn keyed_inventory(
    drafts: Vec<(Value, Option<String>)>,
    total: usize,
) -> (Value, Vec<SourceMapRequest>) {
    let mut keyed: Vec<(String, Value, Option<String>)> = drafts
        .into_iter()
        .map(|(item, raw)| (script_key(&item), item, raw))
        .collect();
    keyed.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| source_digest(&left.1["source"]).cmp(source_digest(&right.1["source"])))
            .then_with(|| {
                left.1["frame_id"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(right.1["frame_id"].as_str().unwrap_or(""))
            })
    });
    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    for (base, _, _) in &keyed {
        *totals.entry(base.clone()).or_insert(0) += 1;
    }
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut requests = Vec::new();
    let mut items = Vec::new();
    for (base, item, raw) in keyed {
        let occurrence = {
            let entry = seen.entry(base.clone()).or_insert(0);
            *entry += 1;
            *entry
        };
        let key = if totals[&base] == 1 {
            base.clone()
        } else {
            format!("{base}_{occurrence}")
        };
        if let (Some(declared), Some(raw)) = (item["source_map_url"].as_str(), raw) {
            requests.push(SourceMapRequest {
                script_key: key.clone(),
                declared_url: declared.to_owned(),
                fetch_url: raw,
            });
        }
        let mut entry = serde_json::Map::new();
        entry.insert("script_key".into(), json!(key));
        if let Value::Object(fields) = item {
            entry.extend(fields);
        }
        items.push(Value::Object(entry));
    }
    (json!({ "total": total, "items": items }), requests)
}

/// `captureWorkers`.
pub(super) fn capture_workers(
    capture: &mut Capture<'_, '_>,
    frame_ids: &BTreeSet<String>,
) -> Result<Vec<Value>, AnalysisError> {
    let result = capture.browser_optional("Target.getTargets", json!({}))?;
    let completeness = &mut capture.events.completeness;
    let mut items = Vec::new();
    if result.is_none() {
        completeness.unavailable("workers");
    }
    let targets = result
        .as_ref()
        .and_then(|result| result.get("targetInfos"))
        .and_then(Value::as_array);
    if result.is_some() && targets.is_none() {
        completeness.exclude_count("workers", "invalid_protocol_value", None);
        return Ok(items);
    }
    let mut malformed = 0_u64;
    for entry in targets.into_iter().flatten() {
        let Some(target) = entry.as_object() else {
            malformed += 1;
            continue;
        };
        let Some(kind) = values::string(target.get("type")).filter(|kind| !kind.is_empty()) else {
            malformed += 1;
            continue;
        };
        if !kind.contains("worker") {
            continue;
        }
        let target_id = values::string(target.get("targetId")).filter(|id| !id.is_empty());
        let attached = target.get("attached").and_then(Value::as_bool);
        let url = values::string(target.get("url"));
        let (Some(target_id), Some(attached), Some(raw_url)) = (target_id, attached, url) else {
            malformed += 1;
            continue;
        };
        let opener = target.get("openerId").map(|value| value.as_str());
        let parent = target.get("parentFrameId").map(|value| value.as_str());
        if matches!(opener, Some(None)) || matches!(parent, Some(None)) {
            malformed += 1;
            continue;
        }
        let (opener, parent) = (opener.flatten(), parent.flatten());
        let related = opener == Some(capture.target_id.as_str())
            || parent.is_some_and(|frame| frame_ids.contains(frame));
        if !related {
            completeness.exclude("workers", "out_of_target_scope");
            continue;
        }
        let Some(sanitized) = values::allowed_sanitized_url(Some(raw_url), &capture.origins) else {
            completeness.exclude(
                "workers",
                if raw_url.is_empty() {
                    "unattributed_origin"
                } else if values::is_http_url(Some(raw_url)) {
                    "disallowed_origin"
                } else {
                    "unsupported_url"
                },
            );
            continue;
        };
        items.push(json!({
            "target_id": target_id,
            "type": kind,
            "url": sanitized.url,
            "origin": sanitized.origin,
            "attached": attached,
            "opener_target_id": opener,
            "parent_frame_id": parent,
        }));
    }
    if malformed > 0 {
        completeness.exclude_count("workers", "invalid_protocol_value", Some(malformed));
    }
    Ok(items)
}
