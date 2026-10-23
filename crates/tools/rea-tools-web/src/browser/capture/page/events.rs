//! Passive page-capture event accumulator: `src/browser/CdpCaptureEvents.ts`,
//! `CdpCaptureEventHandlers.ts`, `CdpCaptureEventHelpers.ts`,
//! `CdpCaptureEventBodyShapes.ts`, `CdpCaptureEventState.ts` and
//! `CdpCaptureEventTypes.ts`. Payloads are validated and normalized at
//! ingestion; raw values never outlive the handler.
use super::super::completeness::Completeness;
use super::super::values::{self, Event, Record};
use super::Options;
use super::metadata;
use super::ordered::OrderedMap;
use crate::cdp::json_text::{
    decode_padded_base64, infer_json_shape, js_number_string, padded_base64_byte_length,
};
use crate::cdp::urls;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};

/// `CDP_CAPTURE_SCRIPT_METADATA_LIMITS`.
const RETAINED_SCRIPT_BYTES: usize = 8 * 1024 * 1024;
const RETAINED_SCRIPTS: usize = 50_000;
const SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// `CapturedScript`.
#[derive(Clone)]
pub(super) struct Script {
    pub script_id: String,
    pub raw_url: String,
    pub url: String,
    pub origin: Option<String>,
    pub hash: Option<String>,
    pub length: Option<u64>,
    pub is_module: Option<bool>,
    pub language: Option<String>,
    pub source_map_url: Option<String>,
    pub source_map_raw_url: Option<String>,
    pub execution_context_key: Option<String>,
    pub frame_id: Option<String>,
}

/// One retained network request (`NetworkState`).
#[derive(Clone)]
pub(super) struct Request {
    pub request_id: String,
    pub url: String,
    pub origin: String,
    pub method: String,
    pub resource_type: Option<String>,
    pub status: Value,
    pub mime_type: Option<String>,
    pub encoded_data_length: Value,
    pub redirects: Vec<Value>,
    pub initiator: Value,
    pub body_status: &'static str,
    pub body_request: Option<Value>,
    pub body_response: Option<Value>,
}

impl Request {
    pub(super) fn to_json(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "url": self.url,
            "origin": self.origin,
            "method": self.method,
            "resource_type": self.resource_type,
            "status": self.status,
            "mime_type": self.mime_type,
            "encoded_data_length": self.encoded_data_length,
            "redirects": self.redirects,
            "initiator": self.initiator,
            "body_shapes": {
                "status": self.body_status,
                "request": self.body_request,
                "response": self.body_response,
            },
        })
    }
}

/// `ResponseBodyCandidate`.
#[derive(Clone)]
pub(super) struct BodyCandidate {
    pub request_id: String,
    pub occurrence: u64,
}

pub(super) struct WebSocket {
    pub request_id: String,
    pub url: String,
    pub events: Vec<Value>,
}

/// `CdpCaptureEvents`.
pub(super) struct Events {
    options: Options,
    origins: BTreeSet<String>,
    budget_exclusions_recorded: bool,
    request_occurrences: HashMap<String, u64>,
    body_examined: HashMap<String, u64>,
    pub scripts: OrderedMap<Script>,
    budget_omissions: HashSet<String>,
    rejected_script_budget: u64,
    rejected_source_map_budget: u64,
    script_bytes: HashMap<String, usize>,
    retained_script_bytes: usize,
    context_frames: HashMap<String, String>,
    pub network: OrderedMap<Request>,
    request_timestamps: HashMap<String, f64>,
    malformed_redirects: HashSet<String>,
    pub websockets: OrderedMap<WebSocket>,
    pub console: Vec<Value>,
    pub response_metadata: Vec<Value>,
    pub agent_hints: Vec<Value>,
    pub completeness: Completeness,
    pub origin_violation: bool,
    pub navigation_during_capture: bool,
    main_frame_id: Option<String>,
    committed_document: Option<String>,
}

const INITIAL_ATTACH_LIMITED: [&str; 5] = [
    "network_requests",
    "console_events",
    "websocket_connections",
    "websocket_frames",
    "metadata",
];

impl Events {
    pub(super) fn new(options: Options, origins: BTreeSet<String>) -> Self {
        Self {
            options,
            origins,
            budget_exclusions_recorded: false,
            request_occurrences: HashMap::new(),
            body_examined: HashMap::new(),
            scripts: OrderedMap::default(),
            budget_omissions: HashSet::new(),
            rejected_script_budget: 0,
            rejected_source_map_budget: 0,
            script_bytes: HashMap::new(),
            retained_script_bytes: 0,
            context_frames: HashMap::new(),
            network: OrderedMap::default(),
            request_timestamps: HashMap::new(),
            malformed_redirects: HashSet::new(),
            websockets: OrderedMap::default(),
            console: Vec::new(),
            response_metadata: Vec::new(),
            agent_hints: Vec::new(),
            completeness: Completeness::new(&INITIAL_ATTACH_LIMITED),
            origin_violation: false,
            navigation_during_capture: false,
            main_frame_id: None,
            committed_document: None,
        }
    }

    pub(super) fn begin_authorized_frame(&mut self, frame_id: &str) {
        let options = self.options.clone();
        let origins = std::mem::take(&mut self.origins);
        *self = Self::new(options, origins);
        self.main_frame_id = Some(frame_id.to_owned());
        if !self.options.include_console_text {
            self.completeness
                .exclude_count("console_text", "not_approved", None);
        }
        if !self.options.include_json_body_shapes {
            self.completeness
                .exclude_count("json_body_shapes", "not_approved", None);
        }
        if !self.options.include_websocket_shapes {
            self.completeness
                .exclude_count("websocket_shapes", "not_approved", None);
        }
    }

    /// `beginFinalCapture`: keeps `navigationDuringCapture`.
    pub(super) fn begin_final_capture(&mut self, frame_id: &str) {
        self.main_frame_id = Some(frame_id.to_owned());
        self.committed_document = None;
    }

    pub(super) fn record_script_budget_exclusions(&mut self) {
        if self.budget_exclusions_recorded {
            return;
        }
        self.budget_exclusions_recorded = true;
        let scripts = self.rejected_script_budget;
        let source_maps = self.rejected_source_map_budget + self.budget_omissions.len() as u64;
        if scripts > 0 {
            self.completeness
                .exclude_count("scripts", "resource_budget_exhausted", Some(scripts));
        }
        if source_maps > 0 {
            self.completeness.exclude_count(
                "source_maps",
                "resource_budget_exhausted",
                Some(source_maps),
            );
        }
    }

    pub(super) fn ingest(&mut self, event: &Event) {
        let Some(params) = event.params.as_object() else {
            return;
        };
        match event.method.as_str() {
            "Runtime.executionContextCreated" => self.execution_context_created(params),
            "Runtime.executionContextDestroyed" => {
                if let Some(key) = execution_context_key(params.get("executionContextId")) {
                    self.context_frames.remove(&key);
                }
            }
            "Runtime.executionContextsCleared" => self.context_frames.clear(),
            "Debugger.scriptParsed" => self.script_parsed(params),
            "Network.requestWillBeSent" => {
                let request_id = values::string(params.get("requestId")).map(str::to_owned);
                let previous = request_id.as_ref().and_then(|id| self.network.version(id));
                self.request_will_be_sent(params);
                if let Some(id) = request_id {
                    if self.network.version(&id) != previous {
                        *self.request_occurrences.entry(id).or_insert(0) += 1;
                    }
                }
            }
            "Network.responseReceived" => self.response_received(params),
            "Network.loadingFinished" => self.loading_finished(params),
            "Runtime.consoleAPICalled" => self.console_api_called(params),
            "Page.frameNavigated" => self.frame_navigated(params),
            "Network.webSocketCreated" => self.websocket_created(params),
            "Network.webSocketFrameSent" => self.websocket_frame(params, "sent"),
            "Network.webSocketFrameReceived" => self.websocket_frame(params, "received"),
            _ => {}
        }
    }

    /// `frameForScript`.
    pub(super) fn frame_for_script(
        &self,
        script: &Script,
        frame_ids: &BTreeSet<String>,
    ) -> Option<String> {
        script
            .frame_id
            .as_ref()
            .filter(|frame| frame_ids.contains(*frame))
            .cloned()
    }

    pub(super) fn response_body_requests(&self) -> Vec<BodyCandidate> {
        if !self.options.include_json_body_shapes {
            return Vec::new();
        }
        self.network
            .values()
            .filter(|request| !self.malformed_redirects.contains(&request.request_id))
            .filter(|request| is_json_media_type(request.mime_type.as_deref()))
            .filter_map(|request| {
                self.request_occurrences
                    .get(&request.request_id)
                    .map(|occurrence| BodyCandidate {
                        request_id: request.request_id.clone(),
                        occurrence: *occurrence,
                    })
            })
            .collect()
    }

    pub(super) fn current_body_request(&self, candidate: &BodyCandidate) -> Option<&Request> {
        if self.request_occurrences.get(&candidate.request_id) != Some(&candidate.occurrence) {
            return None;
        }
        self.network.get(&candidate.request_id)
    }

    pub(super) fn response_body_unavailable(&mut self, candidate: &BodyCandidate) {
        if self.current_body_request(candidate).is_none() {
            return;
        }
        self.body_examined
            .insert(candidate.request_id.clone(), candidate.occurrence);
        if self.malformed_redirects.contains(&candidate.request_id) {
            return;
        }
        self.update_response_shape(&candidate.request_id, None);
        self.completeness.unavailable("json_body_shapes");
    }

    pub(super) fn settle_unexamined_bodies(&mut self) {
        for candidate in self.response_body_requests() {
            let pending = self
                .current_body_request(&candidate)
                .is_some_and(|request| request.body_response.is_none())
                && self.body_examined.get(&candidate.request_id) != Some(&candidate.occurrence);
            if pending {
                self.response_body_unavailable(&candidate);
            }
        }
    }

    pub(super) fn ingest_response_body(&mut self, candidate: &BodyCandidate, value: &Value) {
        if self.current_body_request(candidate).is_none() {
            return;
        }
        self.body_examined
            .insert(candidate.request_id.clone(), candidate.occurrence);
        if self.malformed_redirects.contains(&candidate.request_id) {
            return;
        }
        // `ingestResponseBodyShape`.
        let result = value.as_object();
        let body = values::string(result.and_then(|result| result.get("body")));
        let encoded = result
            .and_then(|result| result.get("base64Encoded"))
            .and_then(Value::as_bool);
        let (Some(body), Some(encoded)) = (body, encoded) else {
            self.invalid_response_shape(&candidate.request_id);
            return;
        };
        let decoded = if encoded {
            decode_padded_base64(body).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        } else {
            Some(body.to_owned())
        };
        let Some(decoded) = decoded else {
            self.invalid_response_shape(&candidate.request_id);
            return;
        };
        let shape = infer_json_shape(&decoded);
        if shape.is_none() {
            self.completeness.unavailable("json_body_shapes");
        }
        self.update_response_shape(&candidate.request_id, shape);
    }

    fn invalid_response_shape(&mut self, request_id: &str) {
        self.update_response_shape(request_id, None);
        self.completeness
            .exclude("json_body_shapes", "invalid_protocol_value");
    }

    /// `updateResponseBodyShape`.
    fn update_response_shape(&mut self, request_id: &str, response: Option<Value>) {
        let Some(current) = self.network.get_mut(request_id) else {
            return;
        };
        current.body_status = if response.is_some() {
            "included"
        } else if current.body_request.is_some() {
            "partial"
        } else {
            "unavailable"
        };
        current.body_response = response;
        self.network.touch(request_id);
    }

    fn execution_context_created(&mut self, params: &Record) {
        let context = values::record(params.get("context"));
        let identifier = values::number(context.and_then(|context| context.get("id")));
        let frame_id = values::string(
            values::record(context.and_then(|context| context.get("auxData")))
                .and_then(|aux| aux.get("frameId")),
        );
        let (Some(identifier), Some(frame_id)) =
            (identifier.filter(|id| is_safe_integer(*id)), frame_id)
        else {
            return;
        };
        self.context_frames
            .insert(integer_string(identifier), frame_id.to_owned());
    }

    fn script_parsed(&mut self, params: &Record) {
        let script_id = values::string(params.get("scriptId"));
        let raw_url = values::string(params.get("url")).unwrap_or("").to_owned();
        let sanitized = values::allowed_sanitized_url(Some(&raw_url), &self.origins);
        let Some(script_id) = script_id.map(str::to_owned) else {
            self.completeness
                .exclude("scripts", "invalid_protocol_value");
            return;
        };
        let replaced = self.script_bytes.get(&script_id).copied().unwrap_or(0);
        self.budget_omissions.remove(&script_id);
        if replaced > 0 {
            self.scripts.remove(&script_id);
            self.script_bytes.remove(&script_id);
            self.retained_script_bytes -= replaced;
        }
        let Some(sanitized) = sanitized else {
            self.completeness
                .exclude("scripts", values::exclusion_reason_for_url(Some(&raw_url)));
            return;
        };
        let context_key = execution_context_key(params.get("executionContextId"));
        let length = values::number(params.get("length"))
            .filter(|length| is_safe_integer(*length) && *length >= 0.0);
        let mut script = Script {
            script_id: script_id.clone(),
            raw_url: raw_url.clone(),
            url: sanitized.url,
            origin: sanitized.origin,
            hash: values::string(params.get("hash")).map(str::to_owned),
            length: length.map(|length| length as u64),
            is_module: params.get("isModule").and_then(Value::as_bool),
            language: values::string(params.get("scriptLanguage")).map(str::to_owned),
            source_map_url: None,
            source_map_raw_url: None,
            frame_id: context_key
                .as_ref()
                .and_then(|key| self.context_frames.get(key))
                .cloned(),
            execution_context_key: context_key,
        };
        let base_bytes = [
            Some(&script.script_id),
            Some(&script.raw_url),
            Some(&script.url),
            script.origin.as_ref(),
            script.hash.as_ref(),
            script.language.as_ref(),
            script.execution_context_key.as_ref(),
            script.frame_id.as_ref(),
        ]
        .into_iter()
        .map(|text| text.map_or(0, String::len))
        .sum::<usize>();
        let declared = values::string(params.get("sourceMapURL")).filter(|url| !url.is_empty());
        let remaining = RETAINED_SCRIPT_BYTES - self.retained_script_bytes;
        if self.scripts.len() >= RETAINED_SCRIPTS || base_bytes > remaining {
            self.rejected_script_budget += 1;
            if declared.is_some() {
                self.rejected_source_map_budget += 1;
            }
            return;
        }
        let (source_map_url, source_map_raw_url, exhausted) =
            self.source_map_for_script(declared, &raw_url, remaining - base_bytes);
        if exhausted {
            self.budget_omissions.insert(script_id.clone());
        }
        let retained = base_bytes
            + source_map_url.as_ref().map_or(0, String::len)
            + source_map_raw_url.as_ref().map_or(0, String::len);
        script.source_map_url = source_map_url;
        script.source_map_raw_url = source_map_raw_url;
        self.retained_script_bytes += retained;
        self.script_bytes.insert(script_id.clone(), retained);
        self.scripts.set(&script_id, script);
    }

    /// `sourceMapForScript`.
    fn source_map_for_script(
        &mut self,
        declared: Option<&str>,
        script_url: &str,
        remaining: usize,
    ) -> (Option<String>, Option<String>, bool) {
        let Some(declared) = declared else {
            return (None, None, false);
        };
        let Some(resolved) = urls::parse_with_base(declared, script_url) else {
            self.completeness.exclude("source_maps", "unsupported_url");
            return (None, None, false);
        };
        let raw = resolved.as_str().to_owned();
        if let Some(sanitized) = values::allowed_sanitized_url(Some(&raw), &self.origins) {
            if raw.len() + sanitized.url.len() > remaining {
                return (None, None, true);
            }
            return (Some(sanitized.url), Some(raw), false);
        }
        self.completeness
            .exclude("source_maps", values::exclusion_reason_for_url(Some(&raw)));
        (None, None, false)
    }

    fn request_will_be_sent(&mut self, params: &Record) {
        let Some(request_id) = values::string(params.get("requestId")).map(str::to_owned) else {
            self.completeness
                .exclude("network_requests", "invalid_protocol_value");
            return;
        };
        let request = values::record(params.get("request"));
        if self.malformed_redirects.contains(&request_id) {
            return;
        }
        let previous = self.network.get(&request_id).cloned();
        let has_redirect = params.contains_key("redirectResponse");
        if !has_redirect
            && previous.is_some()
            && self.preserve_malformed_redirect(&request_id, previous.as_ref())
        {
            return;
        }
        let method = values::string(request.and_then(|request| request.get("method")))
            .filter(|method| !method.is_empty());
        let initiator = values::record(params.get("initiator"));
        let initiator_type = values::string(initiator.and_then(|initiator| initiator.get("type")))
            .filter(|kind| !kind.is_empty());
        let (Some(request), Some(method), Some(initiator_type)) = (request, method, initiator_type)
        else {
            self.preserve_malformed_redirect(&request_id, previous.as_ref());
            return;
        };
        let raw_url = values::string(request.get("url"));
        let Some(sanitized) = values::allowed_sanitized_url(raw_url, &self.origins) else {
            self.completeness.exclude(
                "network_requests",
                values::exclusion_reason_for_url(raw_url),
            );
            self.network.remove(&request_id);
            self.request_timestamps.remove(&request_id);
            return;
        };
        let redirect_response = values::record(params.get("redirectResponse"));
        if has_redirect
            && redirect_response.is_none()
            && self.preserve_malformed_redirect(&request_id, previous.as_ref())
        {
            return;
        }
        let mut redirects = previous
            .as_ref()
            .map(|previous| previous.redirects.clone())
            .unwrap_or_default();
        if let Some(redirect) = redirect_response {
            let raw_response_url = values::string(redirect.get("url"));
            let response_url = raw_response_url
                .filter(|url| !url.is_empty())
                .and_then(|url| values::allowed_sanitized_url(Some(url), &self.origins));
            let reason = redirect_response_url_reason(raw_response_url);
            match (&previous, response_url) {
                (None, None) => self.completeness.exclude("network_requests", reason),
                (None, Some(_)) => self.completeness.attach_limited("network_requests"),
                (Some(_), None) => {
                    self.completeness.exclude("network_requests", reason);
                    self.network.remove(&request_id);
                    self.request_timestamps.remove(&request_id);
                    return;
                }
                (Some(previous), Some(response_url)) => {
                    let encoded = values::number(redirect.get("encodedDataLength"))
                        .filter(|length| *length >= 0.0);
                    if encoded.is_none() {
                        self.completeness
                            .exclude("network_requests", "invalid_protocol_value");
                    }
                    redirects.push(json!({
                        "url": previous.url,
                        "response_url": response_url.url,
                        "method": previous.method,
                        "resource_type": previous.resource_type,
                        "status": number_or_null(redirect.get("status")),
                        "mime_type": values::string(redirect.get("mimeType")),
                        "encoded_data_length": encoded.map_or(Value::Null, values::js_number),
                        "request_timestamp": self.request_timestamps.get(&request_id).copied().map_or(Value::Null, values::js_number),
                        "redirect_event_timestamp": number_or_null(params.get("timestamp")),
                    }));
                }
            }
        }
        let frame = initiator_location(initiator);
        let raw_initiator_url = values::string(frame.and_then(|frame| frame.get("url")));
        let initiator_url = values::allowed_sanitized_url(raw_initiator_url, &self.origins);
        if raw_initiator_url.is_some() && initiator_url.is_none() {
            self.completeness.exclude(
                "network_initiators",
                values::exclusion_reason_for_url(raw_initiator_url),
            );
        }
        let (body_status, body_request) = self.request_body_shape(request);
        let state = Request {
            request_id: request_id.clone(),
            url: sanitized.url,
            origin: sanitized.origin.unwrap_or_default(),
            method: method.to_owned(),
            resource_type: values::string(params.get("type")).map(str::to_owned),
            status: Value::Null,
            mime_type: None,
            encoded_data_length: Value::Null,
            redirects,
            initiator: json!({
                "type": initiator_type,
                "url": initiator_url.map(|url| url.url),
                "line": values::integer_or_null(frame.and_then(|frame| frame.get("lineNumber"))),
                "column": values::integer_or_null(frame.and_then(|frame| frame.get("columnNumber"))),
            }),
            body_status,
            body_request,
            body_response: None,
        };
        self.network.set(&request_id, state);
        match values::number(params.get("timestamp")) {
            Some(timestamp) => {
                self.request_timestamps.insert(request_id, timestamp);
            }
            None => {
                self.request_timestamps.remove(&request_id);
            }
        }
    }

    /// `requestBodyShape`.
    fn request_body_shape(&mut self, request: &Record) -> (&'static str, Option<Value>) {
        if !self.options.include_json_body_shapes {
            return ("not_approved", None);
        }
        let body = values::string(request.get("postData"));
        let (true, Some(body)) = (
            is_json_content_type(values::record(request.get("headers"))),
            body,
        ) else {
            return ("unavailable", None);
        };
        let shape = infer_json_shape(body);
        if shape.is_none() {
            self.completeness.unavailable("json_body_shapes");
        }
        (
            if shape.is_some() {
                "included"
            } else {
                "unavailable"
            },
            shape,
        )
    }

    /// `preserveMalformedRedirectEvidence`.
    fn preserve_malformed_redirect(
        &mut self,
        request_id: &str,
        previous: Option<&Request>,
    ) -> bool {
        self.completeness
            .exclude("network_requests", "invalid_protocol_value");
        let Some(previous) = previous else {
            return false;
        };
        self.malformed_redirects.insert(request_id.to_owned());
        if self.options.include_json_body_shapes
            && is_json_media_type(previous.mime_type.as_deref())
            && previous.body_response.is_none()
        {
            self.update_response_shape(request_id, None);
            self.completeness
                .exclude("json_body_shapes", "invalid_protocol_value");
        }
        true
    }

    fn response_received(&mut self, params: &Record) {
        let Some(request_id) = values::string(params.get("requestId")).map(str::to_owned) else {
            self.completeness
                .exclude("network_requests", "invalid_protocol_value");
            return;
        };
        if self.malformed_redirects.contains(&request_id) || self.network.get(&request_id).is_none()
        {
            return;
        }
        let response = values::record(params.get("response"));
        let raw_url = values::string(response.and_then(|response| response.get("url")));
        let sanitized = values::allowed_sanitized_url(raw_url, &self.origins);
        let (Some(response), Some(sanitized)) = (response, sanitized) else {
            let reason = if response.is_none() {
                "invalid_protocol_value"
            } else {
                values::exclusion_reason_for_url(raw_url)
            };
            self.completeness.exclude("network_requests", reason);
            self.network.remove(&request_id);
            self.request_timestamps.remove(&request_id);
            return;
        };
        if let Some(current) = self.network.get_mut(&request_id) {
            current.status = number_or_null(response.get("status"));
            current.mime_type = values::string(response.get("mimeType")).map(str::to_owned);
        }
        self.network.touch(&request_id);
        let (metadata, hints) =
            metadata::safe_response_metadata(&request_id, &sanitized.url, response, &self.origins);
        self.response_metadata.push(metadata);
        self.agent_hints.extend(hints);
    }

    fn loading_finished(&mut self, params: &Record) {
        let Some(request_id) = values::string(params.get("requestId")) else {
            return;
        };
        if self.malformed_redirects.contains(request_id) || self.network.get(request_id).is_none() {
            return;
        }
        let Some(encoded) =
            values::number(params.get("encodedDataLength")).filter(|length| *length >= 0.0)
        else {
            self.completeness
                .exclude("network_requests", "invalid_protocol_value");
            return;
        };
        if let Some(current) = self.network.get_mut(request_id) {
            current.encoded_data_length = values::js_number(encoded);
        }
        let request_id = request_id.to_owned();
        self.network.touch(&request_id);
    }

    fn console_api_called(&mut self, params: &Record) {
        let Some(frame) = first_call_frame(values::record(params.get("stackTrace"))) else {
            self.completeness
                .exclude("console_events", "unattributed_origin");
            return;
        };
        let raw_url = values::string(frame.get("url"));
        let Some(source) = values::allowed_sanitized_url(raw_url, &self.origins) else {
            self.completeness
                .exclude("console_events", values::exclusion_reason_for_url(raw_url));
            return;
        };
        let arguments = records(params.get("args"));
        let text_capture = if self.options.include_console_text {
            let mut captured = Vec::new();
            let mut retained = 0_usize;
            for (index, argument) in arguments.iter().enumerate() {
                let Some((kind, text)) = console_primitive(argument) else {
                    continue;
                };
                retained += text.len();
                captured.push(json!({ "argument_index": index, "type": kind, "text": text }));
            }
            json!({ "status": "included", "values": captured, "retained_bytes": retained })
        } else {
            json!({ "status": "not_approved", "values": [], "retained_bytes": 0 })
        };
        self.console.push(json!({
            "type": values::string(params.get("type")).unwrap_or("unknown"),
            "timestamp": values::number(params.get("timestamp")).map_or(json!(0), values::js_number),
            "argument_types": arguments
                .iter()
                .map(|argument| values::string(argument.get("type")).unwrap_or("unknown"))
                .collect::<Vec<_>>(),
            "url": source.url,
            "line": values::integer_or_null(frame.get("lineNumber")),
            "column": values::integer_or_null(frame.get("columnNumber")),
            "text_capture": text_capture,
        }));
    }

    fn websocket_frame(&mut self, params: &Record, direction: &str) {
        let Some(request_id) = values::string(params.get("requestId")) else {
            return;
        };
        if self.websockets.get(request_id).is_none() {
            return;
        }
        let response = values::record(params.get("response"));
        let payload =
            values::string(response.and_then(|response| response.get("payloadData"))).unwrap_or("");
        let opcode = values::number(response.and_then(|response| response.get("opcode")))
            .unwrap_or(0.0)
            .trunc()
            .max(0.0);
        let text = opcode == 1.0;
        let decoded = if text {
            None
        } else {
            padded_base64_byte_length(payload)
        };
        if !text && decoded.is_none() {
            self.completeness
                .exclude("websocket_frames", "invalid_protocol_value");
        }
        let shape = if !self.options.include_websocket_shapes {
            Value::Null
        } else if !text {
            json!({ "format": "binary", "json_shape": null })
        } else {
            let shape = infer_json_shape(payload);
            json!({ "format": if shape.is_none() { "text" } else { "json" }, "json_shape": shape })
        };
        let event = json!({
            "direction": direction,
            "opcode": values::js_number(opcode),
            "payload_bytes": if text { json!(payload.len()) } else { decoded.map_or(Value::Null, |bytes| json!(bytes)) },
            "payload_shape": shape,
        });
        if let Some(connection) = self.websockets.get_mut(request_id) {
            connection.events.push(event);
        }
    }

    fn websocket_created(&mut self, params: &Record) {
        let request_id = values::string(params.get("requestId"));
        let raw_url = values::string(params.get("url"));
        let (Some(request_id), Some(raw_url)) = (request_id, raw_url) else {
            self.completeness
                .exclude("websocket_connections", "invalid_protocol_value");
            return;
        };
        let source_url = urls::sanitize_browser_url(raw_url).url;
        let Some(mut parsed) = urls::parse(&source_url) else {
            self.completeness
                .exclude("websocket_connections", "unsupported_url");
            return;
        };
        let scheme = match parsed.scheme() {
            "ws" => "http",
            "wss" => "https",
            _ => {
                self.completeness
                    .exclude("websocket_connections", "unsupported_url");
                return;
            }
        };
        let _ = parsed.set_scheme(scheme);
        if !self.origins.contains(&urls::origin(&parsed)) {
            self.completeness
                .exclude("websocket_connections", "disallowed_origin");
            return;
        }
        if self.websockets.get(request_id).is_some() {
            self.completeness
                .exclude("websocket_connections", "invalid_protocol_value");
            return;
        }
        self.websockets.set(
            request_id,
            WebSocket {
                request_id: request_id.to_owned(),
                url: source_url,
                events: Vec::new(),
            },
        );
    }

    fn frame_navigated(&mut self, params: &Record) {
        let Some(main) = self.main_frame_id.as_deref() else {
            return;
        };
        let frame = values::record(params.get("frame"));
        if values::string(frame.and_then(|frame| frame.get("id"))) != Some(main) {
            return;
        }
        let raw_url = values::string(frame.and_then(|frame| frame.get("url")));
        let loader = values::string(frame.and_then(|frame| frame.get("loaderId")));
        let document = format!("{}\0{}", loader.unwrap_or(""), raw_url.unwrap_or(""));
        if self.committed_document.as_deref() == Some(document.as_str()) {
            return;
        }
        self.committed_document = Some(document);
        self.navigation_during_capture = true;
        if values::is_http_url(raw_url)
            && values::allowed_sanitized_url(raw_url, &self.origins).is_none()
        {
            self.origin_violation = true;
        }
    }
}

fn is_safe_integer(value: f64) -> bool {
    value.fract() == 0.0 && value.abs() <= SAFE_INTEGER
}

fn integer_string(value: f64) -> String {
    js_number_string(value)
}

/// `executionContextKey`.
fn execution_context_key(value: Option<&Value>) -> Option<String> {
    values::number(value)
        .filter(|id| is_safe_integer(*id))
        .map(integer_string)
}

fn number_or_null(value: Option<&Value>) -> Value {
    values::number(value).map_or(Value::Null, values::js_number)
}

/// `recordsValue`.
pub(super) fn records(value: Option<&Value>) -> Vec<&Record> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

/// `firstCallFrame`.
fn first_call_frame(value: Option<&Record>) -> Option<&Record> {
    records(value?.get("callFrames")).into_iter().next()
}

/// `initiatorLocation`.
fn initiator_location(initiator: Option<&Record>) -> Option<&Record> {
    let mut stack = values::record(initiator.and_then(|initiator| initiator.get("stack")));
    let mut depth = 0;
    while depth < 32 {
        let Some(current) = stack else {
            break;
        };
        if let Some(frame) = first_call_frame(Some(current)) {
            return Some(frame);
        }
        stack = values::record(current.get("parent"));
        depth += 1;
    }
    values::string(initiator.and_then(|initiator| initiator.get("url"))).and(initiator)
}

fn redirect_response_url_reason(value: Option<&str>) -> &'static str {
    match value {
        None | Some("") => "invalid_protocol_value",
        Some(text) if urls::parse(text).is_none() => "invalid_protocol_value",
        Some(text) => values::exclusion_reason_for_url(Some(text)),
    }
}

fn is_json_content_type(headers: Option<&Record>) -> bool {
    headers.is_some_and(|headers| {
        headers.iter().any(|(name, value)| {
            name.to_lowercase() == "content-type" && is_json_media_type(value.as_str())
        })
    })
}

/// `isJsonMediaType`.
pub(super) fn is_json_media_type(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let media = super::super::js_trim(value.split(';').next().unwrap_or("")).to_lowercase();
    media == "application/json" || media.ends_with("+json")
}

/// `consolePrimitive`.
fn console_primitive(value: &Record) -> Option<(String, String)> {
    let kind = values::string(value.get("type"))?;
    let text = match kind {
        "string" => value.get("value")?.as_str()?.to_owned(),
        "boolean" => value.get("value")?.as_bool()?.to_string(),
        "number" => match value.get("value") {
            Some(Value::Number(number)) => js_number_string(number.as_f64()?),
            _ => value.get("unserializableValue")?.as_str()?.to_owned(),
        },
        "bigint" => value.get("unserializableValue")?.as_str()?.to_owned(),
        "undefined" => "undefined".to_owned(),
        _ => return None,
    };
    Some((kind.to_owned(), text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(method: &str, params: Value) -> Event {
        Event {
            method: method.to_owned(),
            params,
            session_id: None,
        }
    }

    fn json_request(events: &mut Events, id: &str) {
        events.ingest(&event(
            "Network.requestWillBeSent",
            json!({
                "requestId": id,
                "request": { "url": "http://127.0.0.1:1/a.json", "method": "GET", "headers": {} },
                "initiator": { "type": "script" },
                "timestamp": 1.5,
            }),
        ));
        events.ingest(&event(
            "Network.responseReceived",
            json!({ "requestId": id, "response": { "url": "http://127.0.0.1:1/a.json", "status": 200, "mimeType": "application/json", "headers": {} } }),
        ));
        events.ingest(&event(
            "Network.loadingFinished",
            json!({ "requestId": id, "encodedDataLength": 10 }),
        ));
    }

    /// A JSON response that arrives after the body pass enumerated its
    /// candidates is settled as unavailable (`settleUnexaminedResponseBodies`);
    /// live timing rarely reproduces this ordering.
    #[test]
    fn late_json_response_is_settled_unavailable() {
        let options = Options {
            observation_ms: 0,
            include_accessibility_text: false,
            include_console_text: false,
            include_json_body_shapes: true,
            include_websocket_shapes: false,
            include_storage_keys: false,
            include_storage_fingerprints: false,
            include_script_sources: false,
        };
        let mut events = Events::new(options, BTreeSet::from(["http://127.0.0.1:1".to_owned()]));
        events.begin_authorized_frame("main");
        json_request(&mut events, "1");
        let candidates = events.response_body_requests();
        assert_eq!(candidates.len(), 1);
        events.ingest_response_body(
            &candidates[0],
            &json!({ "body": "{\"a\":[1]}", "base64Encoded": false }),
        );
        json_request(&mut events, "2");
        events.settle_unexamined_bodies();
        let statuses: Vec<&str> = events
            .network
            .values()
            .map(|request| request.body_status)
            .collect();
        assert_eq!(statuses, ["included", "unavailable"]);
        let snapshot = events.completeness.snapshot();
        assert!(
            snapshot["unavailable_sections"]
                .as_array()
                .is_some_and(|sections| sections.contains(&json!("json_body_shapes")))
        );
    }
}
