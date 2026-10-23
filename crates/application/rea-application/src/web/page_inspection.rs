//! Contract boundary for passive inspection of one browser page.
//!
//! The CDP provider owns DOM, accessibility, script, resource, network, and
//! storage parsing.  This boundary validates caller-selected scope and output
//! switches before retaining the provider's structured result.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Adapter-owned CDP request boundary. The adapter supplies timeout and
/// cancellation behavior; this application module only sequences safe calls.
pub trait CdpTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;
}

pub const OPERATION: &str = "inspect_web_page";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web page inspection input must be an object"))?;
    let endpoint = non_empty(object.get("cdp_endpoint"), "cdp_endpoint")?;
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return Err(invalid("cdp_endpoint must use HTTP or HTTPS"));
    }

    non_empty(object.get("target_id"), "target_id")?;
    validate_optional_origins(object.get("allowed_origins"))?;
    validate_optional_duration(object.get("observation_ms"), "observation_ms")?;

    for field in [
        "include_accessibility_text",
        "include_console_text",
        "include_json_body_shapes",
        "include_script_sources",
        "include_websocket_shapes",
        "include_storage_keys",
        "include_storage_fingerprints",
    ] {
        validate_optional_boolean(object.get(field), field)?;
    }

    let fingerprints = object
        .get("include_storage_fingerprints")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let keys = object
        .get("include_storage_keys")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if fingerprints && !keys {
        return Err(invalid(
            "include_storage_fingerprints requires include_storage_keys",
        ));
    }

    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web page inspection result must be an object"));
    }
    Ok(result)
}

/// Inspect one selected page without navigation, evaluation, or mutation.
/// Optional sections remain explicit and empty when the caller did not approve them.
pub fn inspect(
    input: &Value,
    transport: &mut dyn CdpTransport,
    started_at: &str,
    ended_at: &str,
) -> Result<Value, Failure> {
    validate_input(input)?;
    let input_object = input.as_object().expect("validated object");
    let target_id = input_object
        .get("target_id")
        .and_then(Value::as_str)
        .expect("validated target");
    let allowed = input_object
        .get("allowed_origins")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let observation_ms = input_object
        .get("observation_ms")
        .and_then(Value::as_u64)
        .unwrap_or(500);

    request(transport, "Page.enable", serde_json::json!({}))?;
    request(transport, "Runtime.enable", serde_json::json!({}))?;
    request(transport, "Debugger.enable", serde_json::json!({}))?;
    request(transport, "Network.enable", serde_json::json!({}))?;
    let frame_tree = request(transport, "Page.getFrameTree", serde_json::json!({}))?;
    let frame = frame_tree
        .get("frameTree")
        .and_then(|tree| tree.get("frame"))
        .ok_or_else(|| protocol_failure("missing main frame"))?;
    let initial_frame_identity = frame_identity(frame);
    let url = frame
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_failure("missing main-frame URL"))?;
    let safe_url = sanitize_url(url);
    let page_origin =
        origin(&safe_url).ok_or_else(|| unsupported_failure("target URL has no HTTP(S) origin"))?;
    let title = frame.get("name").and_then(Value::as_str).unwrap_or("");
    if !allowed.is_empty() && !allowed.iter().any(|value| *value == page_origin) {
        return Err(denied_failure(&page_origin));
    }

    let dom = request(
        transport,
        "DOM.getDocument",
        serde_json::json!({"depth":-1,"pierce":false}),
    )?;
    let event_listeners = root_event_listeners(transport, &dom);
    let dom_nodes = collect_dom_nodes(&dom);
    let dom_truncated = dom.get("root").map(count_dom_nodes).unwrap_or(0) > 10_000;
    let resource_tree = request(transport, "Page.getResourceTree", serde_json::json!({}))?;
    let resources_truncated = count_resources(&resource_tree) > 4_096;
    let storage_usage = optional_request(
        transport,
        "Storage.getUsageAndQuota",
        serde_json::json!({"origin": page_origin}),
    );
    let cookies = optional_request(
        transport,
        "Network.getCookies",
        serde_json::json!({"urls":[url]}),
    );
    let storage_keys = if input_object
        .get("include_storage_keys")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        Some(capture_storage_keys(transport, &page_origin))
    } else {
        None
    };
    let accessibility = if input_object
        .get("include_accessibility_text")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        request(
            transport,
            "Accessibility.getFullAXTree",
            serde_json::json!({}),
        )?
        .get("nodes")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()))
    } else {
        Value::Array(Vec::new())
    };
    let accessibility_nodes = collect_accessibility_nodes(
        &accessibility,
        input_object
            .get("include_accessibility_text")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    );
    let after_tree = request(transport, "Page.getFrameTree", serde_json::json!({}))?;
    let after_frame = after_tree
        .get("frameTree")
        .and_then(|tree| tree.get("frame"))
        .ok_or_else(|| protocol_failure("missing main frame after inspection"))?;
    let after_url = after_frame.get("url").and_then(Value::as_str).unwrap_or("");
    // A reload can retain the same URL while replacing the document.  Match
    // the frame identity as well as its URL so the result never combines DOM
    // facts from two different main-frame documents.
    if after_url != url || frame_identity(after_frame) != initial_frame_identity {
        return Err(Failure::new(
            "target_changed",
            "target_changed",
            "The selected page changed during inspection.".into(),
            false,
            "Retry after the page reaches a stable state.".into(),
            BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
        ));
    }
    let version = request(transport, "Browser.getVersion", serde_json::json!({}))?;
    let include_text = input_object
        .get("include_accessibility_text")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(serde_json::json!({
        "browser": browser_identity(&version),
        "target": {"target_id":target_id,"type":"page","title":title,"url":safe_url,"origin":page_origin,"attached":Value::Null},
        "capture_window":{"started_at":started_at,"ended_at":ended_at,"observation_ms":observation_ms},
        "completeness": completeness(
            input_object,
            storage_usage.is_some(),
            storage_keys.as_ref().is_none_or(|keys| keys.complete),
            dom_truncated,
            resources_truncated,
        ),
        "frames": collect_frames(&frame_tree, &allowed),
        "dom": {"total_nodes": dom.get("root").map(count_dom_nodes).unwrap_or(0), "nodes": dom_nodes},
        "accessibility": {"total_nodes": accessibility.as_array().map_or(0, Vec::len), "text_capture":{"status":if include_text {"included"} else {"not_approved"},"retained_bytes":0,"excluded_fields":if include_text {0} else {1}},"nodes":accessibility_nodes},
        "scripts":{"total":0,"items":[]},"resources":collect_resources(&resource_tree, &allowed),"network":{"requests":[],"websocket_connections":[],"coverage_started_at":started_at,"prior_activity_available":false},"console":{"events":[],"coverage_started_at":started_at,"prior_activity_available":false},"workers":[],"metadata":{"responses":[],"dom_urls":[],"agent_hints":[],"event_listeners":event_listeners,"excluded_dom_urls":0,"headers_allowlisted":true},"storage": storage_metadata(&page_origin, storage_usage.as_ref(), cookies.as_ref(), storage_keys.as_ref()),
        "limitations":["Observation starts when REA attaches; prior network and console activity is unavailable.","Remote page content is retained as untrusted observation data; no page scripts are evaluated.","Resource, script, network, console, worker, and storage detail is unavailable until the corresponding bounded capture is approved and supported by the adapter."]
    }))
}

fn request(
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
            "Retry the bounded CDP inspection.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("method", Detail::Text(method.into())),
            ]),
        )
    })
}
fn optional_request(
    transport: &mut dyn CdpTransport,
    method: &str,
    params: Value,
) -> Option<Value> {
    transport.request(method, params).ok()
}
fn root_event_listeners(transport: &mut dyn CdpTransport, dom: &Value) -> Vec<Value> {
    let Some(node_id) = dom
        .get("root")
        .and_then(|root| root.get("nodeId"))
        .and_then(Value::as_u64)
    else {
        return Vec::new();
    };
    let Some(remote) = optional_request(
        transport,
        "DOM.resolveNode",
        serde_json::json!({"nodeId":node_id}),
    ) else {
        return Vec::new();
    };
    let Some(object_id) = remote
        .get("object")
        .and_then(|object| object.get("objectId"))
        .and_then(Value::as_str)
    else {
        return Vec::new();
    };
    let Some(response) = optional_request(
        transport,
        "DOMDebugger.getEventListeners",
        serde_json::json!({"objectId":object_id}),
    ) else {
        return Vec::new();
    };
    response.get("listeners").and_then(Value::as_array).map(|listeners| listeners.iter().take(2048).filter_map(|listener| Some(serde_json::json!({"type":listener.get("type")?.as_str(),"use_capture":listener.get("useCapture").and_then(Value::as_bool),"passive":listener.get("passive").and_then(Value::as_bool),"once":listener.get("once").and_then(Value::as_bool),"script_id":listener.get("scriptId"),"line_number":listener.get("lineNumber"),"column_number":listener.get("columnNumber")}))).collect()).unwrap_or_default()
}
fn origin(url: &str) -> Option<String> {
    let scheme = url.find("://")?;
    let start = scheme + 3;
    let end = url[start..]
        .find(['/', '?', '#'])
        .map(|index| start + index)
        .unwrap_or(url.len());
    (end > start).then(|| format!("{}://{}", &url[..scheme], &url[start..end]))
}

fn frame_identity(frame: &Value) -> (Option<&str>, Option<&str>) {
    (
        frame.get("id").and_then(Value::as_str),
        frame.get("loaderId").and_then(Value::as_str),
    )
}
fn sanitize_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_owned();
    };
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map(|index| authority_start + index)
        .unwrap_or(url.len());
    let authority = &url[authority_start..authority_end];
    let Some(at) = authority.rfind('@') else {
        return url.to_owned();
    };
    format!(
        "{}{}{}",
        &url[..authority_start],
        &authority[at + 1..],
        &url[authority_end..]
    )
}
fn browser_identity(version: &Value) -> Value {
    serde_json::json!({"product":version.get("product").and_then(Value::as_str).unwrap_or(""),"protocol_version":version.get("protocolVersion").and_then(Value::as_str).unwrap_or(""),"revision":version.get("revision").and_then(Value::as_str).unwrap_or(""),"user_agent":version.get("userAgent").and_then(Value::as_str).unwrap_or(""),"js_version":version.get("jsVersion").and_then(Value::as_str).unwrap_or("")})
}
fn collect_frames(tree: &Value, allowed: &[&str]) -> Vec<Value> {
    let mut frames = Vec::new();
    if let Some(root) = tree.get("frameTree") {
        collect_frame(root, None, allowed, &mut frames);
    }
    frames
}
fn collect_frame(tree: &Value, parent: Option<&str>, allowed: &[&str], frames: &mut Vec<Value>) {
    let Some(frame) = tree.get("frame") else {
        return;
    };
    let raw_url = frame.get("url").and_then(Value::as_str).unwrap_or("");
    let url = sanitize_url(raw_url);
    let frame_origin = origin(&url);
    if allowed.is_empty()
        || frame_origin
            .as_deref()
            .is_some_and(|value| allowed.iter().any(|allowed| *allowed == value))
    {
        frames.push(serde_json::json!({"frame_id":frame.get("id").and_then(Value::as_str).unwrap_or(""),"parent_frame_id":parent,"url":url,"origin":frame_origin,"attached":true,"opener_target_id":frame.get("openerId"),}));
    }
    if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
        let current = frame.get("id").and_then(Value::as_str);
        for child in children {
            collect_frame(child, current, allowed, frames);
        }
    }
}
fn collect_resources(tree: &Value, allowed: &[&str]) -> Vec<Value> {
    let mut resources = Vec::new();
    if let Some(root) = tree.get("frameTree") {
        collect_frame_resources(root, allowed, &mut resources);
    }
    resources.sort_by(|left, right| {
        left["url"]
            .as_str()
            .unwrap_or("")
            .cmp(right["url"].as_str().unwrap_or(""))
    });
    resources
}
fn collect_frame_resources(tree: &Value, allowed: &[&str], output: &mut Vec<Value>) {
    if let Some(items) = tree.get("resources").and_then(Value::as_array) {
        for resource in items {
            if output.len() >= 4_096 {
                break;
            }
            let raw_url = resource.get("url").and_then(Value::as_str).unwrap_or("");
            let url = sanitize_url(raw_url);
            let resource_origin = origin(&url);
            if !allowed.is_empty()
                && !resource_origin
                    .as_deref()
                    .is_some_and(|value| allowed.iter().any(|allowed| *allowed == value))
            {
                continue;
            }
            let digest = Sha256::digest(url.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            output.push(serde_json::json!({"resource_key":format!("res_{digest}"),"url":url,"origin":resource_origin,"type":resource.get("type").and_then(Value::as_str).unwrap_or(""),"mime_type":resource.get("mimeType").and_then(Value::as_str).unwrap_or(""),"content_size":resource.get("encodedDataLength").and_then(Value::as_u64)}));
        }
    }
    if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
        for child in children {
            if output.len() >= 4_096 {
                break;
            }
            collect_frame_resources(child, allowed, output);
        }
    }
}
fn count_resources(tree: &Value) -> usize {
    if let Some(frame_tree) = tree.get("frameTree") {
        return count_resources(frame_tree);
    }
    let own_count = tree
        .get("resources")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let child_count = tree
        .get("childFrames")
        .and_then(Value::as_array)
        .map(|children| children.iter().map(count_resources).sum())
        .unwrap_or(0);
    own_count.saturating_add(child_count)
}
fn count_dom_nodes(value: &Value) -> usize {
    let children = value
        .get("children")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(count_dom_nodes).sum())
        .unwrap_or(0);
    1 + children
}
fn collect_dom_nodes(dom: &Value) -> Vec<Value> {
    let mut nodes = Vec::new();
    if let Some(root) = dom.get("root") {
        collect_dom_node(root, -1, &mut nodes);
    }
    nodes
}
fn collect_dom_node(node: &Value, parent_index: isize, output: &mut Vec<Value>) {
    if output.len() >= 10_000 {
        return;
    }
    let index = output.len();
    let attributes = node
        .get("attributes")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .enumerate()
                .filter_map(|(position, value)| {
                    if position % 2 == 0 {
                        value.as_str().map(str::to_owned)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    output.push(serde_json::json!({
        "index": index,
        "parent_index": parent_index,
        "node_type": node.get("nodeType").and_then(Value::as_u64).unwrap_or(0),
        "node_name": node.get("nodeName").and_then(Value::as_str).unwrap_or(""),
        "node_value_length": node.get("nodeValue").and_then(Value::as_str).map_or(0, str::len),
        "attribute_names": attributes,
    }));
    if let Some(children) = node.get("children").and_then(Value::as_array) {
        for child in children {
            if output.len() >= 10_000 {
                break;
            }
            collect_dom_node(child, index as isize, output);
        }
    }
}
fn collect_accessibility_nodes(nodes: &Value, include_text: bool) -> Vec<Value> {
    nodes.as_array().map(|items| items.iter().take(10_000).map(|node| {
        let text = |field: &str| node.get(field).and_then(|value| value.get("value")).and_then(Value::as_str).map(str::to_owned);
        let states = node.get("properties").and_then(Value::as_array).map(|properties| properties.iter().take(64).filter_map(|property| Some(serde_json::json!({"name":property.get("name")?.as_str()? ,"value":property.get("value")?.get("value").cloned().unwrap_or(Value::Null)}))).collect::<Vec<_>>()).unwrap_or_default();
        serde_json::json!({"node_id":node.get("nodeId").and_then(Value::as_str).unwrap_or(""),"parent_id":node.get("parentId").and_then(Value::as_str),"role":text("role"),"name":if include_text {text("name")} else {None},"description":if include_text {text("description")} else {None},"ignored":node.get("ignored").and_then(Value::as_bool).unwrap_or(false),"states":states})
    }).collect()).unwrap_or_default()
}
fn completeness(
    input: &serde_json::Map<String, Value>,
    storage_available: bool,
    storage_keys_available: bool,
    dom_truncated: bool,
    resources_truncated: bool,
) -> Value {
    let mut sections = Vec::new();
    sections.extend(["scripts", "network_requests", "console_events", "workers"]);
    if input
        .get("include_accessibility_text")
        .and_then(Value::as_bool)
        != Some(true)
    {
        sections.push("accessibility");
    }
    if input.get("include_storage_keys").and_then(Value::as_bool) != Some(true) {
        sections.push("storage_keys");
    }
    let mut unavailable = Vec::new();
    if !storage_available {
        unavailable.push("storage");
    }
    if input.get("include_storage_keys").and_then(Value::as_bool) == Some(true)
        && !storage_keys_available
    {
        unavailable.push("storage_keys");
    }
    let mut truncated = Vec::new();
    if dom_truncated {
        truncated.push("dom");
    }
    if resources_truncated {
        truncated.push("resources");
    }
    let complete = sections.is_empty() && unavailable.is_empty() && truncated.is_empty();
    serde_json::json!({"status":if complete{"complete_within_window"}else if truncated.is_empty(){"attach_limited"}else{"truncated"},"conditions":if complete{vec!["complete_within_window"]}else if truncated.is_empty(){vec!["attach_limited"]}else{vec!["truncated"]},"policy_filtered_sections":[],"attach_limited_sections":sections,"truncated_sections":truncated,"unavailable_sections":unavailable,"excluded":[],"dropped_events":{"scripts":0,"network_requests":0,"console_events":0,"websocket_connections":0,"websocket_frames":0,"webmcp_tools":0,"timeline_events":0,"total":0}})
}
struct StorageKeys {
    local: Vec<String>,
    session: Vec<String>,
    indexed_db: Vec<String>,
    caches: Vec<String>,
    complete: bool,
}
fn capture_storage_keys(transport: &mut dyn CdpTransport, origin: &str) -> StorageKeys {
    let local_response = optional_request(
        transport,
        "DOMStorage.getDOMStorageItems",
        serde_json::json!({"storageId":{"securityOrigin":origin,"isLocalStorage":true}}),
    );
    let session_response = optional_request(
        transport,
        "DOMStorage.getDOMStorageItems",
        serde_json::json!({"storageId":{"securityOrigin":origin,"isLocalStorage":false}}),
    );
    let indexed_db_response = optional_request(
        transport,
        "IndexedDB.requestDatabaseNames",
        serde_json::json!({"securityOrigin":origin}),
    );
    let caches_response = optional_request(
        transport,
        "CacheStorage.requestCacheNames",
        serde_json::json!({"securityOrigin":origin}),
    );
    StorageKeys {
        complete: local_response.is_some()
            && session_response.is_some()
            && indexed_db_response.is_some()
            && caches_response.is_some(),
        local: storage_item_keys(local_response),
        session: storage_item_keys(session_response),
        indexed_db: string_names(indexed_db_response, "databaseNames"),
        caches: string_names(caches_response, "caches"),
    }
}
fn storage_item_keys(response: Option<Value>) -> Vec<String> {
    response
        .and_then(|value| value.get("entries").cloned())
        .and_then(|value| value.as_array().cloned())
        .map(|entries| {
            entries
                .iter()
                .take(4096)
                .filter_map(|entry| entry.as_array()?.first()?.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
fn string_names(response: Option<Value>, field: &str) -> Vec<String> {
    response
        .and_then(|value| value.get(field).cloned())
        .and_then(|value| value.as_array().cloned())
        .map(|items| {
            items
                .iter()
                .take(4096)
                .filter_map(|item| {
                    item.get("cacheName")
                        .and_then(Value::as_str)
                        .or_else(|| item.as_str())
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}
fn storage_metadata(
    origin: &str,
    usage: Option<&Value>,
    cookies: Option<&Value>,
    keys: Option<&StorageKeys>,
) -> Value {
    let usage_bytes = usage
        .and_then(|value| value.get("usage"))
        .and_then(Value::as_f64);
    let quota_bytes = usage
        .and_then(|value| value.get("quota"))
        .and_then(Value::as_f64);
    serde_json::json!({"origin":origin,"usage_bytes":usage_bytes,"quota_bytes":quota_bytes,"local_storage_keys":keys.map(|value| value.local.clone()).unwrap_or_default(),"session_storage_keys":keys.map(|value| value.session.clone()).unwrap_or_default(),"indexed_db_names":keys.map(|value| value.indexed_db.clone()).unwrap_or_default(),"cache_names":keys.map(|value| value.caches.clone()).unwrap_or_default(),"cookie_metadata":cookie_metadata(cookies),"content_fingerprints":[],"fingerprint_algorithm":"sha256","fingerprints_complete":false,"values_redacted":true})
}
fn cookie_metadata(response: Option<&Value>) -> Vec<Value> {
    response.and_then(|value| value.get("cookies")).and_then(Value::as_array).map(|cookies| cookies.iter().take(1024).filter_map(|cookie| {
        let name = cookie.get("name").and_then(Value::as_str)?;
        let domain = cookie.get("domain").and_then(Value::as_str)?;
        let path = cookie.get("path").and_then(Value::as_str)?;
        if name.len() > 4096 || domain.len() > 4096 || path.len() > 4096 {
            return None;
        }
        Some(serde_json::json!({"name":name,"domain":domain,"path":path,"secure":cookie.get("secure").and_then(Value::as_bool),"http_only":cookie.get("httpOnly").and_then(Value::as_bool),"same_site":cookie.get("sameSite"),"expires":cookie.get("expires")}))
    }).collect()).unwrap_or_default()
}
fn protocol_failure(reason: &str) -> Failure {
    Failure::new(
        "protocol_error",
        "provider",
        reason.into(),
        true,
        "Retry the bounded CDP inspection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn unsupported_failure(reason: &str) -> Failure {
    Failure::new(
        "unsupported_target",
        "unsupported_target",
        reason.into(),
        false,
        "Select a page with an HTTP(S) origin.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn denied_failure(origin: &str) -> Failure {
    Failure::new(
        "target_not_allowed",
        "policy",
        "The selected page origin is outside the caller's allowed origins.".into(),
        false,
        "Add the exact origin to allowed_origins or select another page.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("origin", Detail::Text(origin.into())),
        ]),
    )
}

fn validate_optional_origins(value: Option<&Value>) -> Result<(), Failure> {
    let Some(origins) = value else {
        return Ok(());
    };
    let origins = origins
        .as_array()
        .ok_or_else(|| invalid("allowed_origins must be an array"))?;
    for origin in origins {
        let origin = non_empty(Some(origin), "allowed_origins[]")?;
        let remainder = origin
            .split_once("://")
            .map(|(_, remainder)| remainder)
            .unwrap_or_default();
        if !(origin.starts_with("http://") || origin.starts_with("https://"))
            || remainder.is_empty()
            || remainder.contains('/')
            || remainder.contains('?')
            || remainder.contains('#')
        {
            return Err(invalid(
                "allowed_origins must contain exact HTTP(S) origins",
            ));
        }
    }
    Ok(())
}

fn validate_optional_duration(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let duration = value
        .as_u64()
        .ok_or_else(|| invalid(&format!("{field} must be a non-negative integer")))?;
    if duration > 2_147_483_647 {
        return Err(invalid(&format!("{field} exceeds the supported deadline")));
    }
    Ok(())
}

fn validate_optional_boolean(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if let Some(value) = value {
        if !value.is_boolean() {
            return Err(invalid(&format!("{field} must be a boolean")));
        }
    }
    Ok(())
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
        "Provide a caller-selected CDP page, an optional exact-origin scope, and bounded passive inspection options.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "cdp_endpoint": "http://127.0.0.1:9222",
            "allowed_origins": ["https://app.example.test"],
            "target_id": "page-1",
            "observation_ms": 500,
            "include_accessibility_text": true,
            "include_script_sources": true,
            "include_storage_keys": true,
            "include_storage_fingerprints": true
        })
    }

    #[test]
    fn accepts_scoped_page_inspection() {
        validate_input(&input()).expect("valid web page inspection input");
        assert!(retain_result(&input(), serde_json::json!({"frames": []})).is_ok());
    }

    #[test]
    fn rejects_fingerprints_without_keys() {
        let mut invalid_input = input();
        invalid_input["include_storage_keys"] = serde_json::json!(false);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_unbounded_observation() {
        let mut invalid_input = input();
        invalid_input["observation_ms"] = serde_json::json!(2_147_483_648_u64);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_non_object_result() {
        assert!(retain_result(&input(), serde_json::json!([])).is_err());
    }

    #[test]
    fn redacts_url_userinfo_before_projection() {
        assert_eq!(
            sanitize_url("https://user:secret@example.test/path"),
            "https://example.test/path"
        );
    }

    struct StorageFailureTransport {
        frame_tree_calls: usize,
    }

    impl CdpTransport for StorageFailureTransport {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, String> {
            if matches!(
                method,
                "DOMStorage.getDOMStorageItems"
                    | "IndexedDB.requestDatabaseNames"
                    | "CacheStorage.requestCacheNames"
            ) {
                return Err("storage inspection unavailable".into());
            }
            Ok(match method {
                "Page.getFrameTree" => {
                    self.frame_tree_calls += 1;
                    if self.frame_tree_calls == 1 {
                        serde_json::json!({"frameTree":{"frame":{"url":"https://app.example.test/","name":"Example"}}})
                    } else {
                        serde_json::json!({"frameTree":{"frame":{"url":"https://app.example.test/"}}})
                    }
                }
                "DOM.getDocument" => serde_json::json!({
                    "root": {"nodeId": 1, "nodeType": 9, "nodeName": "#document"}
                }),
                "DOM.resolveNode" => serde_json::json!({
                    "object": {"objectId": "root-object"}
                }),
                "DOMDebugger.getEventListeners" => serde_json::json!({"listeners": []}),
                "Page.getResourceTree" => {
                    serde_json::json!({"frameTree":{"frame":{"url":"https://app.example.test/"}}})
                }
                "Network.getCookies" => serde_json::json!({"cookies": []}),
                "Accessibility.getFullAXTree" => serde_json::json!({"nodes": []}),
                "Browser.getVersion" => serde_json::json!({"product":"Chrome"}),
                _ => serde_json::json!({}),
            })
        }
    }

    #[test]
    fn marks_approved_storage_keys_unavailable_when_transport_fails() {
        let mut transport = StorageFailureTransport {
            frame_tree_calls: 0,
        };
        let result = inspect(
            &input(),
            &mut transport,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
        )
        .expect("inspection result");
        assert_eq!(
            result["completeness"]["unavailable_sections"]
                .as_array()
                .expect("unavailable sections")
                .iter()
                .filter_map(Value::as_str)
                .find(|section| *section == "storage_keys"),
            Some("storage_keys")
        );
        assert!(
            result["storage"]["local_storage_keys"]
                .as_array()
                .expect("storage keys")
                .is_empty()
        );
    }

    struct FakeTransport {
        methods: Vec<String>,
        fail_storage_keys: bool,
        frame_tree_calls: usize,
        loader_changed: bool,
    }

    impl CdpTransport for FakeTransport {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, String> {
            self.methods.push(method.to_owned());
            if self.fail_storage_keys
                && matches!(
                    method,
                    "DOMStorage.getDOMStorageItems"
                        | "IndexedDB.requestDatabaseNames"
                        | "CacheStorage.requestCacheNames"
                )
            {
                return Err("storage inspection unavailable".into());
            }
            Ok(match method {
                "Page.getFrameTree" => {
                    self.frame_tree_calls += 1;
                    if self.frame_tree_calls == 1 {
                        serde_json::json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1","name":"Example page","url":"https://app.example.test/"}}})
                    } else {
                        serde_json::json!({"frameTree":{"frame":{"id":"frame-1","loaderId":if self.loader_changed {"loader-2"} else {"loader-1"},"url":"https://app.example.test/"}}})
                    }
                }
                "DOM.getDocument" => serde_json::json!({
                    "root":{"nodeId":1,"nodeType":9,"nodeName":"#document","children":[{"nodeType":1,"nodeName":"HTML","nodeValue":"","attributes":["lang","en"],"children":[]}]}
                }),
                "DOM.resolveNode" => serde_json::json!({"object":{"objectId":"root-object"}}),
                "DOMDebugger.getEventListeners" => serde_json::json!({"listeners": []}),
                "Page.getResourceTree" => {
                    serde_json::json!({"frameTree":{"frame":{"url":"https://app.example.test/"},"resources":[]}})
                }
                "Storage.getUsageAndQuota" => serde_json::json!({"usage":12,"quota":100}),
                "Network.getCookies" => {
                    serde_json::json!({"cookies":[{"name":"session","domain":"app.example.test","path":"/","secure":true,"httpOnly":true,"sameSite":"Lax","expires":0,"value":"redacted"}]})
                }
                "DOMStorage.getDOMStorageItems" => serde_json::json!({"entries": []}),
                "IndexedDB.requestDatabaseNames" => serde_json::json!({"databaseNames": []}),
                "CacheStorage.requestCacheNames" => serde_json::json!({"caches": []}),
                "Accessibility.getFullAXTree" => {
                    serde_json::json!({"nodes":[{"nodeId":"ax-1","role":{"value":"button"},"name":{"value":"Submit"},"ignored":false,"properties":[]}]})
                }
                "Browser.getVersion" => {
                    serde_json::json!({"product":"Chrome","protocolVersion":"1","revision":"r","userAgent":"ua","jsVersion":"js"})
                }
                _ => serde_json::json!({}),
            })
        }
    }

    struct ResourceBoundTransport {
        frame_tree_calls: usize,
        resource_tree: Value,
    }

    impl CdpTransport for ResourceBoundTransport {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, String> {
            Ok(match method {
                "Page.getFrameTree" => {
                    self.frame_tree_calls += 1;
                    serde_json::json!({"frameTree":{"frame":{"url":"https://app.example.test/","name":if self.frame_tree_calls == 1 {"Example"} else {""}}}})
                }
                "DOM.getDocument" => serde_json::json!({
                    "root": {"nodeId": 1, "nodeType": 9, "nodeName": "#document"}
                }),
                "DOM.resolveNode" => serde_json::json!({
                    "object": {"objectId": "root-object"}
                }),
                "DOMDebugger.getEventListeners" => serde_json::json!({"listeners": []}),
                "Page.getResourceTree" => self.resource_tree.clone(),
                "Browser.getVersion" => serde_json::json!({"product":"Chrome"}),
                _ => serde_json::json!({}),
            })
        }
    }

    #[test]
    fn bounds_resources_and_reports_resource_truncation() {
        let resources = (0..4_097)
            .map(|index| {
                serde_json::json!({
                    "url": format!("https://app.example.test/resource-{index}"),
                    "type": "Script",
                    "mimeType": "text/javascript"
                })
            })
            .collect::<Vec<_>>();
        let mut transport = ResourceBoundTransport {
            frame_tree_calls: 0,
            resource_tree: serde_json::json!({
                "frameTree": {
                    "frame": {"url":"https://app.example.test/"},
                    "resources": resources
                }
            }),
        };
        let result = inspect(
            &input(),
            &mut transport,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
        )
        .expect("inspection result");
        assert_eq!(result["resources"].as_array().map(Vec::len), Some(4_096));
        assert!(
            result["completeness"]["truncated_sections"]
                .as_array()
                .expect("truncated sections")
                .iter()
                .any(|section| section == "resources")
        );
    }

    #[test]
    fn inspects_authorized_page_without_evaluation() {
        let mut transport = FakeTransport {
            methods: Vec::new(),
            fail_storage_keys: false,
            frame_tree_calls: 0,
            loader_changed: false,
        };
        let result = inspect(
            &input(),
            &mut transport,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
        )
        .unwrap();
        assert_eq!(result["target"]["target_id"], "page-1");
        assert_eq!(result["target"]["title"], "Example page");
        assert_eq!(result["dom"]["nodes"].as_array().map(Vec::len), Some(2));
        assert_eq!(result["accessibility"]["nodes"][0]["name"], "Submit");
        assert!(
            transport
                .methods
                .iter()
                .all(|method| !method.starts_with("Runtime.evaluate"))
        );
    }

    #[test]
    fn rejects_main_frame_reload_even_when_url_is_unchanged() {
        let mut transport = FakeTransport {
            methods: Vec::new(),
            fail_storage_keys: false,
            frame_tree_calls: 0,
            loader_changed: true,
        };

        let error = inspect(
            &input(),
            &mut transport,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
        )
        .expect_err("loader identity change must invalidate the capture");

        assert_eq!(error.code(), "target_changed");
    }
}
