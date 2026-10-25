//! Contract boundary for navigation-aware web session observation.

use rea_core::cancellation::Cancellation;
use rea_core::failure::{Detail, Failure};
use rea_host::cdp_transport::{CdpEvent, CdpEventBatch, CdpTransportError, CdpWebSocketTransport};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const OPERATION: &str = "observe_web_session";

/// Transport operations needed by the navigation observation producer.
pub trait CdpSessionTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;

    fn poll_events(&mut self, timeout: Duration, cancellation: &Cancellation)
    -> Result<(), String>;

    fn drain_events(&mut self) -> CdpEventBatch;
}

/// A connected, caller-selected page target for navigation observation.
pub struct ConnectedCdpWebSessionPort<T> {
    transport: T,
    target_id: String,
}

impl ConnectedCdpWebSessionPort<CdpWebSocketTransport> {
    pub fn connect(websocket_endpoint: &str, target_id: &str) -> Result<Self, CdpTransportError> {
        let transport = CdpWebSocketTransport::connect_for_target(websocket_endpoint, target_id)?;
        Ok(Self::from_transport(transport, target_id))
    }
}

impl<T> ConnectedCdpWebSessionPort<T> {
    pub fn from_transport(transport: T, target_id: &str) -> Self {
        Self {
            transport,
            target_id: target_id.to_owned(),
        }
    }

    pub fn observe(&mut self, input: &Value, cancellation: &Cancellation) -> Result<Value, Failure>
    where
        T: CdpSessionTransport,
    {
        validate_input(input)?;
        let requested_target = input["target_id"].as_str().expect("validated target_id");
        if requested_target != self.target_id {
            return Err(target_mismatch());
        }

        let allowed_origins = input
            .get("allowed_origins")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let initial = self
            .transport
            .request("Page.getFrameTree", Value::Object(Default::default()))
            .map_err(|error| transport_failure(&error))?;
        let initial_frame =
            main_frame(&initial).ok_or_else(|| protocol_failure("initial frame is missing"))?;
        let initial_url = initial_frame
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let main_frame_id = initial_frame
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol_failure("initial frame id is missing"))?
            .to_owned();
        let initial_url = approved_url(&initial_url, &allowed_origins);
        let armed_at = timestamp();
        let mut capture = TimelineCapture::new(allowed_origins, main_frame_id, initial_url.clone());

        enable_observation(&mut self.transport)?;
        self.observe_window(&mut capture, input, cancellation)?;

        let ended_at = timestamp();
        let end_reason = capture.end_reason.unwrap_or("window_elapsed");
        let result = serde_json::json!({
            "browser": browser_version(&mut self.transport),
            "target": {
                "target_id": self.target_id,
                "initial_url": initial_url,
                "final_url": capture.final_url,
            },
            "window": {
                "armed_at": armed_at,
                "ended_at": ended_at,
                "requested_ms": observation_ms(input),
                "end_reason": end_reason,
            },
            "timeline": capture.timeline,
            "completeness": {
                "status": if capture.scope_excluded { "partial" } else { "complete" },
                "available": ["timeline"],
                "unavailable": if capture.scope_excluded { vec!["timeline"] } else { Vec::<&str>::new() },
                "omissions": if capture.scope_excluded { vec!["out_of_target_scope"] } else { Vec::<&str>::new() },
            },
            "limitations": [
                "The timeline begins after REA attaches; earlier navigation and network activity is unavailable.",
                "Only navigation metadata is retained; headers, bodies, cookies, console values, and payloads are not captured by this tool.",
                "An out-of-policy destination ends collection immediately and is recorded without its URL.",
            ],
        });
        retain_result(input, result)
    }

    fn observe_window(
        &mut self,
        capture: &mut TimelineCapture,
        input: &Value,
        cancellation: &Cancellation,
    ) -> Result<(), Failure>
    where
        T: CdpSessionTransport,
    {
        let deadline = std::time::Instant::now() + Duration::from_millis(observation_ms(input));
        while capture.end_reason.is_none() && std::time::Instant::now() < deadline {
            if cancellation.reason().is_some() {
                return Err(cancelled_failure());
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            self.transport
                .poll_events(remaining.min(Duration::from_millis(100)), cancellation)
                .map_err(|error| transport_failure(&error))?;
            let batch = self.transport.drain_events();
            capture.ingest(batch);
        }
        Ok(())
    }
}

impl CdpSessionTransport for CdpWebSocketTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        CdpWebSocketTransport::request(self, method, params).map_err(|error| error.to_string())
    }

    fn poll_events(
        &mut self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), String> {
        CdpWebSocketTransport::poll_events(self, timeout, cancellation)
            .map_err(|error| error.to_string())
    }

    fn drain_events(&mut self) -> CdpEventBatch {
        CdpWebSocketTransport::drain_events(self)
    }
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web session input must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "cdp_endpoint" | "allowed_origins" | "target_id" | "observation_ms"
        ) {
            return Err(invalid("web session input contains an unknown field"));
        }
    }
    let endpoint = object
        .get("cdp_endpoint")
        .and_then(Value::as_str)
        .filter(|endpoint| !endpoint.is_empty())
        .ok_or_else(|| invalid("cdp_endpoint must be a non-empty string"))?;
    validate_endpoint(endpoint)?;
    let target_id = non_empty(object.get("target_id"), "target_id")?;
    if target_id.trim().is_empty() {
        return Err(invalid("target_id must be a non-empty string"));
    }
    if let Some(origins) = object.get("allowed_origins") {
        let origins = origins
            .as_array()
            .ok_or_else(|| invalid("allowed_origins must be an array"))?;
        for origin in origins {
            let value = origin
                .as_str()
                .ok_or_else(|| invalid("allowed_origins must contain strings"))?;
            validate_origin(value)?;
        }
    }
    if let Some(duration) = object.get("observation_ms") {
        let duration = duration
            .as_u64()
            .ok_or_else(|| invalid("observation_ms must be a positive integer"))?;
        if duration == 0 || duration > 2_147_483_647 {
            return Err(invalid("observation_ms must be between 1 and 2147483647"));
        }
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<(), Failure> {
    if endpoint.starts_with("http://") {
        let rest = endpoint.strip_prefix("http://").unwrap_or_default();
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if path.is_empty() && valid_loopback_authority(authority) {
            return Ok(());
        }
    }

    if let Some(rest) = endpoint.strip_prefix("ws://") {
        let path_start = rest.find('/').ok_or_else(|| invalid_endpoint())?;
        let (authority, path) = rest.split_at(path_start);
        if valid_loopback_authority(authority)
            && path.starts_with("/devtools/browser/")
            && path.len() > "/devtools/browser/".len()
            && !path["/devtools/browser/".len()..]
                .chars()
                .any(|character| matches!(character, '/' | '?' | '#'))
        {
            return Ok(());
        }
    }

    Err(invalid_endpoint())
}

fn valid_loopback_authority(authority: &str) -> bool {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = match rest.find(']') {
            Some(end) => end,
            None => return false,
        };
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(port) => port,
            None => return false,
        };
        (&rest[..end], port)
    } else {
        match authority.rsplit_once(':') {
            Some(parts) => parts,
            None => return false,
        }
    };
    let loopback = host == "127.0.0.1" || host == "::1";
    let explicit_port =
        !port.is_empty() && port.chars().all(|character| character.is_ascii_digit());
    loopback && explicit_port
}

fn validate_origin(origin: &str) -> Result<(), Failure> {
    let scheme_end = origin.find("://").ok_or_else(|| invalid_origin())?;
    let scheme = &origin[..scheme_end];
    if scheme != "http" && scheme != "https" {
        return Err(invalid_origin());
    }
    let rest = &origin[scheme_end + 3..];
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty()
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.contains('*')
        || (path != "" && path != "/")
        || path.contains('?')
        || path.contains('#')
    {
        return Err(invalid_origin());
    }
    Ok(())
}

fn invalid_endpoint() -> Failure {
    invalid("cdp_endpoint must be a loopback HTTP endpoint or browser WebSocket")
}

fn invalid_origin() -> Failure {
    invalid("allowed_origins must contain exact HTTP(S) origins")
}

fn enable_observation<T: CdpSessionTransport>(transport: &mut T) -> Result<(), Failure> {
    for (method, params) in [
        ("Page.enable", Value::Object(Default::default())),
        ("Network.enable", Value::Object(Default::default())),
        (
            "Page.setLifecycleEventsEnabled",
            serde_json::json!({"enabled": true}),
        ),
    ] {
        transport
            .request(method, params)
            .map_err(|error| transport_failure(&error))?;
    }
    Ok(())
}

fn browser_version<T: CdpSessionTransport>(transport: &mut T) -> Value {
    transport
        .request("Browser.getVersion", Value::Object(Default::default()))
        .map(|version| {
            serde_json::json!({
                "product": version.get("product").and_then(Value::as_str).unwrap_or("unknown"),
                "protocol_version": version.get("protocolVersion").and_then(Value::as_str).unwrap_or("unknown"),
                "revision": version.get("revision").and_then(Value::as_str).unwrap_or("unknown"),
                "user_agent": version.get("userAgent").and_then(Value::as_str).unwrap_or("unknown"),
                "js_version": version.get("jsVersion").and_then(Value::as_str).unwrap_or("unknown"),
            })
        })
        .unwrap_or_else(|_| serde_json::json!({
            "product": "unknown",
            "protocol_version": "unknown",
            "revision": "unknown",
            "user_agent": "unknown",
            "js_version": "unknown",
        }))
}

fn main_frame(value: &Value) -> Option<&serde_json::Map<String, Value>> {
    value.pointer("/frameTree/frame")?.as_object()
}

fn observation_ms(input: &Value) -> u64 {
    input
        .get("observation_ms")
        .and_then(Value::as_u64)
        .unwrap_or(10_000)
}

fn timestamp() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = elapsed.as_secs();
    let millis = elapsed.subsec_millis();
    format!("{seconds}.{millis:03}Z")
}

fn approved_url(url: &str, allowed_origins: &[String]) -> String {
    if is_approved_url(url, allowed_origins) {
        url.to_owned()
    } else {
        String::new()
    }
}

fn is_approved_url(url: &str, allowed_origins: &[String]) -> bool {
    let Some(origin_end) = url.find("//") else {
        return false;
    };
    let authority_end = url[origin_end + 2..]
        .find(['/', '?', '#'])
        .map(|offset| origin_end + 2 + offset)
        .unwrap_or(url.len());
    let origin = &url[..authority_end];
    (url.starts_with("http://") || url.starts_with("https://"))
        && (allowed_origins.is_empty()
            || allowed_origins.iter().any(|candidate| candidate == origin))
}

fn target_mismatch() -> Failure {
    Failure::new(
        "target_changed",
        "target_changed",
        "the observation target differs from the connected target".into(),
        false,
        "Retry after reconnecting to the caller-selected page target.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn protocol_failure(reason: &str) -> Failure {
    Failure::new(
        "protocol_error",
        "protocol_error",
        reason.into(),
        false,
        "Retry with a responsive CDP page target.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn transport_failure(reason: &str) -> Failure {
    protocol_failure(&format!("CDP transport failed: {reason}"))
}

fn cancelled_failure() -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        "web session observation was cancelled".into(),
        true,
        "Retry the observation when the caller is ready.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

struct TimelineCapture {
    allowed_origins: Vec<String>,
    main_frame_id: String,
    final_url: Option<String>,
    timeline: Vec<Value>,
    sequence: u64,
    pending_reload: bool,
    scope_excluded: bool,
    end_reason: Option<&'static str>,
}

impl TimelineCapture {
    fn new(allowed_origins: Vec<String>, main_frame_id: String, initial_url: String) -> Self {
        Self {
            allowed_origins,
            main_frame_id,
            final_url: (!initial_url.is_empty()).then_some(initial_url),
            timeline: Vec::new(),
            sequence: 0,
            pending_reload: false,
            scope_excluded: false,
            end_reason: None,
        }
    }

    fn ingest(&mut self, batch: CdpEventBatch) {
        let CdpEventBatch {
            items, overflowed, ..
        } = batch;
        for event in items {
            self.ingest_event(event);
        }
        if overflowed {
            self.scope_excluded = true;
        }
    }

    fn ingest_event(&mut self, event: CdpEvent) {
        let method = event
            .value
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let params = event.value.get("params").cloned().unwrap_or(Value::Null);
        match method {
            "Page.frameRequestedNavigation" => self.navigation_requested(&params),
            "Page.frameNavigated" => self.navigation_committed(&params),
            "Page.navigatedWithinDocument" => self.same_document(&params),
            "Network.requestWillBeSent" => self.redirect(&params),
            "Network.loadingFailed" => self.loading_failed(&params),
            "Page.lifecycleEvent" => self.lifecycle(&params),
            "Inspector.targetCrashed" | "Target.detachedFromTarget" => {
                self.add(
                    "target_terminated",
                    &params,
                    None,
                    None,
                    Some("target_terminated"),
                );
                self.end_reason = Some("target_terminated");
            }
            _ => {}
        }
    }

    fn navigation_requested(&mut self, params: &Value) {
        if params.get("frameId").and_then(Value::as_str) != Some(&self.main_frame_id) {
            return;
        }
        let detail = params.get("reason").and_then(Value::as_str);
        self.pending_reload = detail == Some("reload");
        self.add(
            "navigation_requested",
            params,
            params.get("url").and_then(Value::as_str),
            None,
            detail,
        );
    }

    fn navigation_committed(&mut self, params: &Value) {
        let Some(frame) = params.get("frame").and_then(Value::as_object) else {
            return;
        };
        if frame.get("id").and_then(Value::as_str) != Some(&self.main_frame_id) {
            return;
        }
        let url = frame.get("url").and_then(Value::as_str);
        let event_type = if self.pending_reload {
            "same_origin_reload"
        } else {
            "navigation_committed"
        };
        self.add(
            event_type,
            params,
            url,
            None,
            frame.get("transitionType").and_then(Value::as_str),
        );
        self.pending_reload = false;
        self.update_scope(url);
    }

    fn same_document(&mut self, params: &Value) {
        if params.get("frameId").and_then(Value::as_str) != Some(&self.main_frame_id) {
            return;
        }
        let url = params.get("url").and_then(Value::as_str);
        self.add("same_document_navigation", params, url, None, None);
        self.update_scope(url);
    }

    fn redirect(&mut self, params: &Value) {
        if params.get("frameId").and_then(Value::as_str) != Some(&self.main_frame_id)
            || params.get("redirectResponse").is_none()
        {
            return;
        }
        let url = params.pointer("/request/url").and_then(Value::as_str);
        self.add(
            "redirect",
            params,
            url,
            params.get("requestId").and_then(Value::as_str),
            None,
        );
        if !url.is_some_and(|value| is_approved_url(value, &self.allowed_origins)) {
            self.exclude_scope();
        }
    }

    fn loading_failed(&mut self, params: &Value) {
        if params
            .get("frameId")
            .and_then(Value::as_str)
            .is_some_and(|value| value != self.main_frame_id)
        {
            return;
        }
        self.add(
            "load_failed",
            params,
            None,
            params.get("requestId").and_then(Value::as_str),
            params.get("errorText").and_then(Value::as_str),
        );
    }

    fn lifecycle(&mut self, params: &Value) {
        if params.get("frameId").and_then(Value::as_str) != Some(&self.main_frame_id) {
            return;
        }
        self.add(
            "lifecycle",
            params,
            None,
            None,
            params.get("name").and_then(Value::as_str),
        );
    }

    fn add(
        &mut self,
        event_type: &str,
        params: &Value,
        raw_url: Option<&str>,
        request_id: Option<&str>,
        detail: Option<&str>,
    ) {
        self.sequence = self.sequence.saturating_add(1);
        let approved = raw_url.filter(|url| is_approved_url(url, &self.allowed_origins));
        self.timeline.push(serde_json::json!({
            "sequence": self.sequence,
            "type": event_type,
            "timestamp": params.get("timestamp").and_then(Value::as_f64).unwrap_or(0.0).max(0.0),
            "frame_id": params.get("frameId").and_then(Value::as_str),
            "loader_id": params.get("loaderId").and_then(Value::as_str),
            "request_id": request_id,
            "url": approved,
            "destination_scope": raw_url.map(|url| if approved.is_some() { "approved" } else if is_http_url(url) { "outside_policy" } else { "unsupported" }),
            "detail": detail,
        }));
    }

    fn update_scope(&mut self, url: Option<&str>) {
        if let Some(url) = url.filter(|value| is_approved_url(value, &self.allowed_origins)) {
            self.final_url = Some(url.to_owned());
        } else {
            self.exclude_scope();
        }
    }

    fn exclude_scope(&mut self) {
        self.scope_excluded = true;
        self.final_url = None;
        self.end_reason = Some("target_left_scope");
    }
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web session result must be an object"));
    }
    Ok(result)
}

fn non_empty<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a caller-selected CDP page and a bounded navigation-aware observation window."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "cdp_endpoint": "http://127.0.0.1:9222",
            "allowed_origins": [],
            "target_id": "TARGET_ID",
            "observation_ms": 10000
        })
    }

    #[test]
    fn accepts_bounded_session_window() {
        validate_input(&input()).expect("valid web session input");
        assert!(retain_result(&input(), serde_json::json!({"timeline": []})).is_ok());
    }

    #[test]
    fn accepts_loopback_ipv6_session_endpoint() {
        let mut request = input();
        request["cdp_endpoint"] = serde_json::json!("http://[::1]:9222");

        validate_input(&request).expect("valid IPv6 loopback web session input");
    }

    #[test]
    fn rejects_zero_session_duration() {
        let mut invalid_input = input();
        invalid_input["observation_ms"] = serde_json::json!(0);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_missing_target() {
        let mut invalid_input = input();
        invalid_input["target_id"] = serde_json::json!("");
        assert!(validate_input(&invalid_input).is_err());
    }
}
