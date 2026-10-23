//! Request initiators joined by script ID (`src/browser/execution/CdpRuntimeRequests.ts`
//! and `CdpRuntimeInitiator.ts`).
use super::protocol;
use super::session::RETAINED_EVENT_BYTES;
use super::sources::Sources;
use crate::cdp::urls;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use std::collections::BTreeSet;

struct Callsite {
    script_id: String,
    url: Option<String>,
    line: u64,
    column: Option<u64>,
    function_name: Option<String>,
}

struct Item {
    request_id: String,
    url: String,
    method: String,
    timestamp: Value,
    initiator_type: String,
    reported_initiator: Value,
    callsites: Vec<Callsite>,
    async_parent_ids: Vec<Value>,
}

pub(super) struct Requests {
    operation: &'static str,
    frame_id: String,
    allowed_origins: BTreeSet<String>,
    items: Vec<Item>,
    pub excluded: u64,
    bytes: usize,
    failure: Option<AnalysisError>,
}

/// `sanitizeRuntimeInitiator`: sanitize known transport fields, retaining
/// declarations and every unknown producer field.
fn sanitize_initiator(mut initiator: Value, sources: &Sources) -> Value {
    if let Some(url) = initiator.get_mut("url") {
        if let Some(text) = url.as_str() {
            *url = Value::String(urls::sanitize_browser_url(text).url);
        }
    }
    let mut stack = initiator.get_mut("stack");
    while let Some(Value::Object(current)) = stack {
        if let Some(Value::Array(frames)) = current.get_mut("callFrames") {
            for frame in frames.iter_mut() {
                let Some(frame) = frame.as_object_mut() else {
                    continue;
                };
                let (Some(url), Some(script_id)) = (
                    frame.get("url").and_then(Value::as_str).map(str::to_owned),
                    frame
                        .get("scriptId")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                ) else {
                    continue;
                };
                frame.insert(
                    "url".into(),
                    Value::String(sources.source_url(&script_id, &url)),
                );
            }
        }
        stack = current.get_mut("parent");
    }
    initiator
}

impl Requests {
    pub(super) fn new(
        operation: &'static str,
        frame_id: String,
        allowed_origins: BTreeSet<String>,
    ) -> Self {
        Self {
            operation,
            frame_id,
            allowed_origins,
            items: Vec::new(),
            excluded: 0,
            bytes: 0,
            failure: None,
        }
    }

    /// `ingest`: only armed-window requests from the selected main frame and origins.
    pub(super) fn ingest(&mut self, event: &Value, sources: &Sources) {
        if event.get("method").and_then(Value::as_str) != Some("Network.requestWillBeSent")
            || self.failure.is_some()
        {
            return;
        }
        let params = event.get("params").cloned().unwrap_or(Value::Null);
        if let Err(message) = self.ingest_request(&params, sources) {
            self.failure = Some(AnalysisError::output(self.operation, message));
        }
    }

    fn ingest_request(&mut self, params: &Value, sources: &Sources) -> Result<(), String> {
        let request =
            protocol::request(params).ok_or("Malformed Network.requestWillBeSent event.")?;
        let url = urls::sanitize_browser_url(&request.url);
        let allowed = url
            .origin
            .as_ref()
            .is_some_and(|origin| self.allowed_origins.contains(origin));
        if request.frame_id.as_deref() != Some(self.frame_id.as_str()) || !allowed {
            self.excluded += 1;
            return Ok(());
        }
        self.bytes += serde_json::to_string(params).map_or(0, |text| text.len());
        if self.bytes > RETAINED_EVENT_BYTES {
            return Err(
                "Request initiator evidence exceeds its complete 8 MiB event budget.".into(),
            );
        }
        let mut callsites = Vec::new();
        let mut parents = Vec::new();
        let mut current = request.initiator_stack.clone();
        while let Some(value) = current {
            let stack = protocol::stack(&value).ok_or("Malformed request initiator stack.")?;
            for frame in stack.call_frames {
                callsites.push(Callsite {
                    url: Some(sources.source_url(&frame.script_id, &frame.url)),
                    script_id: frame.script_id,
                    line: frame.line,
                    column: Some(frame.column),
                    function_name: Some(frame.function_name),
                });
            }
            if let Some((id, debugger_id)) = stack.parent_id {
                parents.push(json!({ "id": id, "debugger_id": debugger_id }));
            }
            current = stack.parent;
        }
        if let (Some(initiator_url), Some(line)) = (&request.initiator_url, request.initiator_line)
        {
            let url = urls::sanitize_browser_url(initiator_url).url;
            callsites.push(Callsite {
                url: Some(sources.source_url("", &url)),
                script_id: String::new(),
                line,
                column: request.initiator_column,
                function_name: None,
            });
        }
        self.items.push(Item {
            request_id: request.request_id,
            url: url.url,
            method: request.method,
            timestamp: request.timestamp,
            initiator_type: request.initiator_type,
            reported_initiator: sanitize_initiator(request.initiator, sources),
            callsites,
            async_parent_ids: parents,
        });
        Ok(())
    }

    /// `result`: rebind callsites after metadata collection ends.
    pub(super) fn result(&self, sources: &Sources) -> Result<Vec<Value>, AnalysisError> {
        self.check()?;
        Ok(self
            .items
            .iter()
            .map(|item| {
                json!({
                    "request_id": item.request_id,
                    "url": item.url,
                    "method": item.method,
                    "timestamp_seconds": item.timestamp,
                    "initiator_type": item.initiator_type,
                    "reported_initiator": sanitize_initiator(item.reported_initiator.clone(), sources),
                    "callsites": item.callsites.iter().map(|site| sources.location(
                        &site.script_id,
                        site.url.as_deref(),
                        site.line,
                        site.column,
                        site.function_name.as_deref(),
                    )).collect::<Vec<_>>(),
                    "async_parent_ids": item.async_parent_ids,
                    "causal_attribution": "unknown",
                })
            })
            .collect())
    }

    /// Script IDs of every retained callsite.
    pub(super) fn callsite_script_ids(&self) -> Vec<String> {
        self.items
            .iter()
            .flat_map(|item| item.callsites.iter().map(|site| site.script_id.clone()))
            .filter(|id| !id.is_empty())
            .collect()
    }

    pub(super) fn check(&self) -> Result<(), AnalysisError> {
        self.failure.clone().map_or(Ok(()), Err)
    }
}
