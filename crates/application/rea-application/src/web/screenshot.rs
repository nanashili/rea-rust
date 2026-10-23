//! Read-only CDP visible-viewport screenshot capture.
//!
//! The transport is injected so the application layer never owns a socket,
//! browser session, or target lifecycle. Adapters provide timeout and
//! cancellation-aware implementations of `CdpTransport`.

use base64::Engine;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const OPERATION: &str = "capture_web_screenshot";
const MAX_PNG_BYTES: usize = 256 * 1024 * 1024;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// The adapter owns the CDP connection and must enforce its configured
/// timeout/cancellation policy for every request.
pub trait CdpTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web screenshot input must be an object"))?;
    reject_unknown_fields(object, &["cdp_endpoint", "allowed_origins", "target_id"])?;
    let endpoint = non_empty(object.get("cdp_endpoint"), "cdp_endpoint")?;
    if !valid_cdp_endpoint(endpoint) {
        return Err(invalid("cdp_endpoint must be a loopback CDP endpoint"));
    }
    non_empty(object.get("target_id"), "target_id")?;
    validated_allowed_origins(object.get("allowed_origins"))?;
    Ok(())
}

/// Capture the selected target without navigation, evaluation, or page mutation.
/// `captured_at` is supplied by the adapter clock so this function remains deterministic.
pub fn capture(
    input: &Value,
    transport: &mut dyn CdpTransport,
    captured_at: &str,
) -> Result<Value, Failure> {
    validate_input(input)?;
    let request = input.as_object().expect("validated object");
    let target_id = request
        .get("target_id")
        .and_then(Value::as_str)
        .expect("validated target")
        .trim();
    let allowed_origins = validated_allowed_origins(request.get("allowed_origins"))?;

    request_cdp(transport, "Page.enable", serde_json::json!({}))?;
    let before = request_cdp(transport, "Page.getFrameTree", serde_json::json!({}))?;
    let before_url =
        main_frame_url(&before).ok_or_else(|| protocol_failure("missing main-frame URL"))?;
    let before_origin = origin(&before_url)
        .ok_or_else(|| unsupported_failure("target URL has no supported origin"))?;
    if !allowed_origins.is_empty()
        && !allowed_origins
            .iter()
            .any(|allowed| allowed == &before_origin)
    {
        return Err(denied_failure(&before_origin));
    }

    let screenshot = request_cdp(
        transport,
        "Page.captureScreenshot",
        serde_json::json!({"format":"png","fromSurface":true,"captureBeyondViewport":false}),
    )?;
    let encoded = screenshot
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_failure("Page.captureScreenshot returned no data"))?;
    let bytes = decode_png_bytes(encoded)?;
    let (width, height) = png_dimensions(&bytes)
        .ok_or_else(|| protocol_failure("captured screenshot is not a valid PNG"))?;

    let after = request_cdp(transport, "Page.getFrameTree", serde_json::json!({}))?;
    let after_url =
        main_frame_url(&after).ok_or_else(|| protocol_failure("missing final main-frame URL"))?;
    let after_origin = origin(&after_url)
        .ok_or_else(|| protocol_failure("final target URL has no supported origin"))?;
    if after_url != before_url
        || after_origin != before_origin
        || (!allowed_origins.is_empty()
            && !allowed_origins
                .iter()
                .any(|allowed| allowed == &after_origin))
    {
        return Err(Failure::new(
            "target_changed",
            "target_changed",
            "The selected page changed during screenshot capture.".into(),
            false,
            "Retry after the page reaches a stable state.".into(),
            BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
        ));
    }

    let version = request_cdp(transport, "Browser.getVersion", serde_json::json!({}))?;
    let browser = browser_identity(&version);
    Ok(serde_json::json!({
        "browser": browser,
        "target": {"target_id": target_id, "url": before_url, "origin": before_origin},
        "captured_at": captured_at,
        "viewport": {"width": width, "height": height},
        "artifact": artifact(&bytes),
        "completeness": complete_completeness(),
        "limitations": ["The screenshot contains the visible viewport, including on-screen content.", "REA does not scroll, evaluate JavaScript, or capture beyond the current viewport."]
    }))
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web screenshot result must be an object"));
    }
    Ok(result)
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), Failure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("web screenshot input contains an unknown field"));
    }
    Ok(())
}

fn valid_cdp_endpoint(value: &str) -> bool {
    if let Some(authority) = value.strip_prefix("http://") {
        return valid_loopback_authority(authority, true)
            && !authority.contains('/')
            && !authority.contains('?')
            && !authority.contains('#');
    }
    if let Some(rest) = value.strip_prefix("ws://") {
        let Some((authority, path)) = rest.split_once("/devtools/browser/") else {
            return false;
        };
        return valid_loopback_authority(authority, false)
            && !path.is_empty()
            && !path.contains('/')
            && !path.contains('?')
            && !path.contains('#');
    }
    false
}

fn valid_loopback_authority(value: &str, require_root_path: bool) -> bool {
    let (host, port) = if let Some(host_and_port) = value.strip_prefix('[') {
        let Some((host, port)) = host_and_port.split_once("]:") else {
            return false;
        };
        (host, port)
    } else {
        let Some((host, port)) = value.rsplit_once(':') else {
            return false;
        };
        (host, port)
    };
    let host_valid = matches!(host, "127.0.0.1" | "::1");
    let port_valid = port.parse::<u16>().is_ok();
    host_valid && port_valid && (require_root_path || !value.ends_with('/'))
}

fn validated_allowed_origins(value: Option<&Value>) -> Result<Vec<String>, Failure> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid("allowed_origins must be an array"))?;
    let mut origins = values
        .iter()
        .map(|value| {
            let origin = value
                .as_str()
                .ok_or_else(|| invalid("allowed_origins must contain strings"))?;
            exact_origin(origin)
                .ok_or_else(|| invalid("allowed_origins must contain exact HTTP origins"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    origins.sort();
    origins.dedup();
    Ok(origins)
}

fn exact_origin(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('@')
        || rest.contains('*')
    {
        return None;
    }
    Some(format!("{scheme}://{rest}"))
}

fn request_cdp(
    transport: &mut dyn CdpTransport,
    method: &str,
    params: Value,
) -> Result<Value, Failure> {
    transport.request(method, params).map_err(|message| {
        Failure::new(
            "provider_error",
            "provider",
            message,
            true,
            "Retry the bounded CDP screenshot capture.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("method", Detail::Text(method.into())),
            ]),
        )
    })
}
fn decode_png_bytes(encoded: &str) -> Result<Vec<u8>, Failure> {
    if encoded.is_empty() || !encoded.len().is_multiple_of(4) {
        return Err(protocol_failure(
            "CDP returned non-canonical screenshot data",
        ));
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine
        .decode(encoded)
        .map_err(|_| protocol_failure("CDP returned invalid screenshot data"))?;
    if engine.encode(&bytes) != encoded || bytes.len() > MAX_PNG_BYTES {
        return Err(protocol_failure(
            "CDP returned invalid or oversized screenshot data",
        ));
    }
    Ok(bytes)
}
fn artifact(bytes: &[u8]) -> Value {
    serde_json::json!({"sha256":Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),"bytes":bytes.len(),"media_type":"image/png","data_base64":base64::engine::general_purpose::STANDARD.encode(bytes)})
}
fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 24 || &bytes[..8] != PNG_SIGNATURE || &bytes[12..16] != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
    let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
    (width > 0 && height > 0).then_some((width, height))
}
fn main_frame_url(tree: &Value) -> Option<String> {
    tree.get("frameTree")?
        .get("frame")?
        .get("url")?
        .as_str()
        .map(str::to_owned)
}
fn origin(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map(|index| authority_start + index)
        .unwrap_or(url.len());
    (authority_end > authority_start).then(|| {
        format!(
            "{}://{}",
            &url[..scheme_end],
            &url[authority_start..authority_end]
        )
    })
}
fn browser_identity(version: &Value) -> Value {
    serde_json::json!({"product":version.get("product").and_then(Value::as_str).unwrap_or(""),"protocol_version":version.get("protocolVersion").and_then(Value::as_str).unwrap_or(""),"revision":version.get("revision").and_then(Value::as_str).unwrap_or(""),"user_agent":version.get("userAgent").and_then(Value::as_str).unwrap_or(""),"js_version":version.get("jsVersion").and_then(Value::as_str).unwrap_or("")})
}
fn complete_completeness() -> Value {
    serde_json::json!({"status":"complete_within_window","conditions":["complete_within_window"],"policy_filtered_sections":[],"attach_limited_sections":[],"truncated_sections":[],"unavailable_sections":[],"excluded":[],"dropped_events":{"scripts":0,"network_requests":0,"console_events":0,"websocket_connections":0,"websocket_frames":0,"webmcp_tools":0,"timeline_events":0,"total":0}})
}
fn protocol_failure(reason: &str) -> Failure {
    Failure::new(
        "protocol_error",
        "provider",
        reason.into(),
        true,
        "Retry the bounded CDP screenshot capture.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn unsupported_failure(reason: &str) -> Failure {
    Failure::new(
        "unsupported_target",
        "unsupported_target",
        reason.into(),
        false,
        "Select a page with an attributable HTTP or HTTPS origin.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn denied_failure(origin: &str) -> Failure {
    Failure::new(
        "target_not_allowed",
        "policy",
        "The selected page origin is outside the caller's allowed origins.".into(),
        false,
        "Add the exact page origin to allowed_origins or select another page.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("origin", Detail::Text(origin.into())),
        ]),
    )
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
        reason.into(),
        false,
        "Provide a caller-selected CDP page for a read-only visible-viewport PNG capture.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        calls: Vec<String>,
        responses: Vec<Value>,
    }
    impl CdpTransport for Fake {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, String> {
            self.calls.push(method.into());
            self.responses
                .pop()
                .ok_or_else(|| "missing response".into())
        }
    }
    fn input() -> Value {
        serde_json::json!({"cdp_endpoint":"http://127.0.0.1:9222","allowed_origins":["https://example.test"],"target_id":"target"})
    }
    fn fake_png() -> Vec<u8> {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
        bytes.extend_from_slice(&[0; 4]);
        bytes
    }
    #[test]
    fn validates_request() {
        validate_input(&input()).unwrap();
    }
    #[test]
    fn rejects_unapproved_origin() {
        let mut transport = Fake {
            calls: vec![],
            responses: vec![
                serde_json::json!({"jsVersion":"x"}),
                serde_json::json!({"frameTree":{"frame":{"url":"https://other.test/"}}}),
            ],
        };
        assert!(capture(&input(), &mut transport, "2026-01-01T00:00:00Z").is_err());
    }
    #[test]
    fn captures_selected_page_without_evaluation() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(fake_png());
        let mut transport = Fake {
            calls: vec![],
            responses: vec![
                serde_json::json!({"product":"Chrome","protocolVersion":"1","revision":"r","userAgent":"ua","jsVersion":"js"}),
                serde_json::json!({"frameTree":{"frame":{"url":"https://example.test/"}}}),
                serde_json::json!({"data":encoded}),
                serde_json::json!({"frameTree":{"frame":{"url":"https://example.test/"}}}),
                serde_json::json!({"frameTree":{"frame":{"url":"https://example.test/"}}}),
            ],
        };
        let result = capture(&input(), &mut transport, "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(result["target"]["target_id"], "target");
        assert!(
            !transport
                .calls
                .iter()
                .any(|method| method.contains("Runtime"))
        );
    }
}
