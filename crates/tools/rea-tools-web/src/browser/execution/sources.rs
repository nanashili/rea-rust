//! Source ownership proven by execution context/frame metadata
//! (`src/browser/execution/CdpRuntimeSources.ts`).
use super::protocol::{self, Script};
use super::session::{RETAINED_EVENT_BYTES, RuntimeSession, SOURCE_BYTES};
use crate::cdp::urls;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// `WebRuntimeSource.source`.
#[derive(Clone, Debug)]
pub(super) enum SourceState {
    Captured {
        text: String,
        sha256: String,
        utf8_bytes: usize,
        utf16_units: usize,
    },
    Unavailable(String),
    Excluded(String),
}

/// `WebRuntimeSource`.
#[derive(Clone, Debug)]
pub(super) struct SourceItem {
    pub script_id: String,
    url: String,
    execution_context_id: Option<u64>,
    reported_execution_context: Option<Value>,
    reported_script_context_aux_data: Option<Value>,
    frame_id: Option<String>,
    producer_hash: Option<String>,
    source_map_url: Option<String>,
    has_source_url: Option<bool>,
    language: Option<String>,
    resource_start: Option<(u64, u64)>,
    pub source: SourceState,
}

impl SourceItem {
    pub(super) fn to_json(&self) -> Value {
        let source = match &self.source {
            SourceState::Captured {
                text,
                sha256,
                utf8_bytes,
                utf16_units,
            } => json!({
                "state": "captured",
                "text": text,
                "sha256": sha256,
                "utf8_bytes": utf8_bytes,
                "utf16_units": utf16_units,
            }),
            SourceState::Unavailable(reason) => json!({ "state": "unavailable", "reason": reason }),
            SourceState::Excluded(reason) => json!({ "state": "excluded", "reason": reason }),
        };
        json!({
            "script_id": self.script_id,
            "url": self.url,
            "execution_context_id": self.execution_context_id,
            "reported_execution_context": self.reported_execution_context,
            "reported_script_context_aux_data": self.reported_script_context_aux_data,
            "frame_id": self.frame_id,
            "producer_hash": self.producer_hash,
            "source_map_url": self.source_map_url,
            "has_source_url": self.has_source_url,
            "language": self.language,
            "resource_start": self.resource_start.map(|(line, column)| json!({
                "line_number": line,
                "column_number": column,
            })),
            "source": source,
        })
    }
}

/// How events delivered during source reads are handled.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadEvents {
    /// Inventory is open (`ingest`).
    Ingest,
    /// Frozen inventory; known identities stay checked (`verifyKnownIdentity`).
    VerifyKnown,
    /// No subscriber consumes them.
    Ignore,
}

pub(super) struct Sources {
    operation: &'static str,
    session_id: Option<String>,
    frame_id: String,
    pub scripts: HashMap<String, Script>,
    /// Discovery order of script IDs (`Map` insertion order).
    pub script_order: Vec<String>,
    contexts: HashMap<u64, Value>,
    changed: HashSet<String>,
    changed_contexts: HashSet<u64>,
    sources: Vec<SourceItem>,
    source_index: HashMap<String, usize>,
    retained_bytes: usize,
    source_bytes: usize,
    failure: Option<AnalysisError>,
}

fn aux_string<'a>(aux: Option<&'a Value>, key: &str) -> Option<&'a str> {
    aux.and_then(|aux| aux.get(key)).and_then(Value::as_str)
}

impl Sources {
    pub(super) fn new(session: &RuntimeSession<'_>) -> Self {
        Self {
            operation: session.operation,
            session_id: session.transport.session_id().map(str::to_owned),
            frame_id: session.target.frame_id.clone(),
            scripts: HashMap::new(),
            script_order: Vec::new(),
            contexts: HashMap::new(),
            changed: HashSet::new(),
            changed_contexts: HashSet::new(),
            sources: Vec::new(),
            source_index: HashMap::new(),
            retained_bytes: 0,
            source_bytes: 0,
            failure: None,
        }
    }

    /// `ingest`.
    pub(super) fn ingest(&mut self, event: &Value, retain_new_metadata: bool) {
        if event.get("sessionId").and_then(Value::as_str) != self.session_id.as_deref()
            || self.failure.is_some()
        {
            return;
        }
        if let Err(message) = self.ingest_metadata(event, retain_new_metadata) {
            self.failure = Some(AnalysisError::output(self.operation, message));
        }
    }

    fn ingest_metadata(&mut self, event: &Value, retain_new_metadata: bool) -> Result<(), String> {
        let method = event.get("method").and_then(Value::as_str);
        let params = event.get("params").cloned().unwrap_or(Value::Null);
        match method {
            Some("Runtime.executionContextCreated") => {
                self.retained_bytes += serde_json::to_string(&params).map_or(0, |text| text.len());
                if self.retained_bytes > RETAINED_EVENT_BYTES {
                    return Err(
                        "Context/script metadata exceeds the complete 8 MiB event budget.".into(),
                    );
                }
                let (id, context) = protocol::context_created(&params)
                    .ok_or("Malformed Runtime.executionContextCreated event.")?;
                if self
                    .contexts
                    .get(&id)
                    .is_some_and(|previous| previous != &context)
                {
                    self.changed_contexts.insert(id);
                    let affected: Vec<usize> = self
                        .sources
                        .iter()
                        .enumerate()
                        .filter(|(_, item)| item.execution_context_id == Some(id))
                        .map(|(index, _)| index)
                        .collect();
                    for index in affected {
                        self.revalidate_at(index);
                    }
                }
                if retain_new_metadata {
                    self.contexts.insert(id, context);
                }
            }
            Some("Debugger.scriptParsed") => {
                self.retained_bytes += serde_json::to_string(&params).map_or(0, |text| text.len());
                if self.retained_bytes > RETAINED_EVENT_BYTES {
                    return Err("Script metadata exceeds the complete 8 MiB event budget.".into());
                }
                let script = protocol::script_parsed(&params)
                    .ok_or("Malformed Debugger.scriptParsed event.")?;
                if self
                    .scripts
                    .get(&script.script_id)
                    .is_some_and(|previous| previous != &script)
                {
                    self.changed.insert(script.script_id.clone());
                    if let Some(&index) = self.source_index.get(&script.script_id) {
                        self.revalidate_at(index);
                    }
                }
                if retain_new_metadata {
                    if !self.scripts.contains_key(&script.script_id) {
                        self.script_order.push(script.script_id.clone());
                    }
                    self.scripts.insert(script.script_id.clone(), script);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// `check`.
    pub(super) fn check(&self) -> Result<(), AnalysisError> {
        self.failure.clone().map_or(Ok(()), Err)
    }

    /// Record an unparseable delivery outside the event callback.
    pub(super) fn fail(&mut self, error: AnalysisError) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
    }

    /// `verifyKnownIdentity`.
    pub(super) fn verify_known_identity(&mut self, event: &Value) {
        let params = event.get("params");
        match event.get("method").and_then(Value::as_str) {
            Some("Debugger.scriptParsed") => {
                let known = params
                    .and_then(|params| params.get("scriptId"))
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .is_some_and(|id| self.scripts.contains_key(id));
                if known {
                    self.ingest(event, false);
                }
            }
            Some("Runtime.executionContextCreated") => {
                let known = params
                    .and_then(|params| params.get("context"))
                    .and_then(|context| context.get("id"))
                    .and_then(protocol::integer)
                    .is_some_and(|id| self.contexts.contains_key(&id));
                if known {
                    self.ingest(event, false);
                }
            }
            _ => {}
        }
    }

    /// `belongsToDocument`.
    pub(super) fn belongs_to_document(&self, script_id: &str) -> bool {
        let Some(script) = self.scripts.get(script_id) else {
            return false;
        };
        if self.changed.contains(script_id)
            || self.changed_contexts.contains(&script.execution_context_id)
        {
            return false;
        }
        let script_context = script.aux.as_ref();
        let context = self
            .contexts
            .get(&script.execution_context_id)
            .and_then(|context| context.get("auxData"));
        let worlds = [script_context, context];
        let not_default = |world: &Option<&Value>| {
            world.is_some_and(|world| {
                world.get("isDefault").and_then(Value::as_bool) == Some(false)
                    || world
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind != "default")
            })
        };
        let default = |world: &Option<&Value>| {
            world.is_some_and(|world| {
                world.get("isDefault").and_then(Value::as_bool) == Some(true)
                    || world.get("type").and_then(Value::as_str) == Some("default")
            })
        };
        if worlds.iter().any(not_default) || !worlds.iter().any(default) {
            return false;
        }
        let reported = aux_string(script_context, "frameId");
        let context_frame = aux_string(context, "frameId");
        (reported.is_none() || context_frame.is_none() || reported == context_frame)
            && reported.or(context_frame) == Some(self.frame_id.as_str())
    }

    /// `read`: retain complete script text with an independent digest.
    pub(super) fn read(
        &mut self,
        session: &mut RuntimeSession<'_>,
        script_ids: &[String],
        events: ReadEvents,
    ) -> Result<Vec<Value>, AnalysisError> {
        self.check()?;
        let mut seen = HashSet::new();
        for script_id in script_ids {
            if !seen.insert(script_id.as_str()) || self.source_index.contains_key(script_id) {
                continue;
            }
            let script = self.scripts.get(script_id).cloned();
            let owned = self.belongs_to_document(script_id);
            let context = script
                .as_ref()
                .and_then(|script| self.contexts.get(&script.execution_context_id))
                .cloned();
            let mut item = SourceItem {
                script_id: script_id.clone(),
                url: self.source_url(
                    script_id,
                    script.as_ref().map_or("", |script| script.url.as_str()),
                ),
                execution_context_id: script.as_ref().map(|script| script.execution_context_id),
                reported_execution_context: context,
                reported_script_context_aux_data: script
                    .as_ref()
                    .and_then(|script| script.aux.clone()),
                frame_id: owned.then(|| self.frame_id.clone()),
                producer_hash: script.as_ref().and_then(|script| script.hash.clone()),
                source_map_url: script
                    .as_ref()
                    .and_then(|script| script.source_map_url.clone()),
                has_source_url: script.as_ref().and_then(|script| script.has_source_url),
                language: script
                    .as_ref()
                    .and_then(|script| script.script_language.clone()),
                resource_start: script
                    .as_ref()
                    .map(|script| (script.start_line, script.start_column)),
                source: SourceState::Excluded(if self.changed.contains(script_id) {
                    "The script changed identity during observation; source attribution is unknown."
                        .into()
                } else {
                    "Selected main-document default-world ownership was not established.".into()
                }),
            };
            let webassembly = script
                .as_ref()
                .and_then(|script| script.script_language.as_deref())
                == Some("WebAssembly");
            if owned && !webassembly {
                item.source = self.capture(session, script_id, events)?;
            } else if owned {
                item.source = SourceState::Excluded(
                    "WebAssembly bytecode is outside this JavaScript source operation.".into(),
                );
            }
            self.revalidate(&mut item);
            self.source_index
                .insert(script_id.clone(), self.sources.len());
            self.sources.push(item);
        }
        self.check()?;
        Ok(self.sources.iter().map(SourceItem::to_json).collect())
    }

    /// Retained source text by script ID.
    pub(super) fn retained(&self, script_id: &str) -> Option<&SourceState> {
        self.source_index
            .get(script_id)
            .map(|&index| &self.sources[index].source)
    }

    /// `location`.
    pub(super) fn location(
        &self,
        script_id: &str,
        url: Option<&str>,
        line: u64,
        column: Option<u64>,
        function_name: Option<&str>,
    ) -> Value {
        json!({
            "script_id": script_id,
            "url": url.map(|url| self.source_url(script_id, url)),
            "line_number": line,
            "column_number": column,
            "function_name": function_name,
            "source_association": if self.belongs_to_document(script_id) { "script_id" } else { "unknown" },
        })
    }

    /// `sourceUrl`.
    pub(super) fn source_url(&self, script_id: &str, url: &str) -> String {
        if !self.changed.contains(script_id)
            && self
                .scripts
                .get(script_id)
                .and_then(|script| script.has_source_url)
                == Some(false)
        {
            urls::sanitize_browser_url(url).url
        } else {
            url.to_owned()
        }
    }

    fn revalidate_at(&mut self, index: usize) {
        let mut item = self.sources[index].clone();
        self.revalidate(&mut item);
        self.sources[index] = item;
    }

    fn revalidate(&self, item: &mut SourceItem) {
        if item.frame_id.is_none() || self.belongs_to_document(&item.script_id) {
            return;
        }
        let previous = match &item.source {
            SourceState::Unavailable(reason) => format!(" Previous source read failure: {reason}"),
            _ => String::new(),
        };
        item.frame_id = None;
        item.source = SourceState::Excluded(format!(
            "The script or context changed identity during source collection; attribution is unknown.{previous}"
        ));
    }

    fn capture(
        &mut self,
        session: &mut RuntimeSession<'_>,
        script_id: &str,
        events: ReadEvents,
    ) -> Result<SourceState, AnalysisError> {
        let raw = session.command("Debugger.getScriptSource", json!({ "scriptId": script_id }));
        self.pump(session, events);
        let raw = match raw {
            Ok(raw) => raw,
            Err(error) => {
                if session.cancellation.reason().is_some() {
                    return Err(error);
                }
                return Ok(SourceState::Unavailable(error.user_message()));
            }
        };
        let Some(text) = raw.get("scriptSource").and_then(Value::as_str) else {
            return Err(AnalysisError::output(
                self.operation,
                "Debugger.getScriptSource returned malformed source text.",
            ));
        };
        let bytes = text.len();
        self.source_bytes += bytes;
        if self.source_bytes > SOURCE_BYTES {
            return Err(AnalysisError::output(
                self.operation,
                "Complete runtime source evidence exceeds its 32 MiB budget; no partial evidence is returned.",
            ));
        }
        Ok(SourceState::Captured {
            text: text.to_owned(),
            sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
            utf8_bytes: bytes,
            utf16_units: text.encode_utf16().count(),
        })
    }

    /// Deliver events received during a source read to this subscriber.
    fn pump(&mut self, session: &mut RuntimeSession<'_>, events: ReadEvents) {
        let (delivered, overflowed) = session.take_events();
        if events == ReadEvents::Ignore {
            return;
        }
        if overflowed {
            self.fail(AnalysisError::output(
                self.operation,
                "Context/script metadata exceeds the complete 8 MiB event budget.",
            ));
        }
        for event in &delivered {
            match events {
                ReadEvents::Ingest => self.ingest(event, true),
                ReadEvents::VerifyKnown => self.verify_known_identity(event),
                ReadEvents::Ignore => {}
            }
        }
    }
}
