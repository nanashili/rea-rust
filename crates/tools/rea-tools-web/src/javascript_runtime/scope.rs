//! V8 Inspector discovery and runtime-location authorization.
//!
//! Compatibility owners: `src/inspector/V8InspectorEndpoint.ts`
//! (`discoverV8Inspector`, `validatedInspectorWebSocket`) and
//! `src/inspector/JavaScriptRuntimeScope.ts`.
use crate::cdp::{discovery, file_scope, observation_error, urls};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};

pub(crate) struct Target {
    pub id: String,
    pub kind: String,
    pub url: String,
    pub attached: Option<bool>,
    pub web_socket_url: Option<String>,
}

pub(crate) struct Discovery {
    /// `{product, protocol_version, v8_version}`.
    pub runtime: Value,
    pub product: String,
    pub targets: Vec<Target>,
}

/// `discoverV8Inspector`.
pub(crate) fn discover(
    endpoint: &str,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Discovery, AnalysisError> {
    let version = discovery::read_cdp_json(endpoint, "/json/version", operation, cancellation)?;
    let targets = discovery::read_cdp_json(endpoint, "/json/list", operation, cancellation)?;
    let invalid = || observation_error(operation, "invalid_endpoint_response", None);
    let version = version.as_object().ok_or_else(invalid)?;
    let non_empty = |key: &str| {
        version
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    let product = non_empty("Browser").ok_or_else(invalid)?;
    let protocol = non_empty("Protocol-Version").ok_or_else(invalid)?;
    let v8_version = match version.get("V8-Version") {
        None => Value::Null,
        Some(Value::String(text)) => Value::String(text.clone()),
        Some(_) => return Err(invalid()),
    };
    let targets = targets
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|item| {
            let object = item.as_object()?;
            let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_owned);
            let id = text("id").filter(|id| !id.is_empty())?;
            let kind = text("type").filter(|kind| !kind.is_empty())?;
            let url = text("url")?;
            let attached = match object.get("attached") {
                None | Some(Value::Null) => None,
                Some(Value::Bool(value)) => Some(*value),
                Some(_) => return None,
            };
            let web_socket_url =
                validated_web_socket(endpoint, &id, object.get("webSocketDebuggerUrl"));
            Some(Target {
                id,
                kind,
                url,
                attached,
                web_socket_url,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(invalid)?;
    let mut runtime = Map::new();
    runtime.insert("product".into(), Value::String(product.clone()));
    runtime.insert("protocol_version".into(), Value::String(protocol));
    runtime.insert("v8_version".into(), v8_version);
    Ok(Discovery {
        runtime: Value::Object(runtime),
        product,
        targets,
    })
}

/// `validatedInspectorWebSocket`.
fn validated_web_socket(
    endpoint: &str,
    target_id: &str,
    reported: Option<&Value>,
) -> Option<String> {
    let reported = reported?.as_str().filter(|text| !text.is_empty())?;
    let mut socket = urls::parse(reported)?;
    let trusted = urls::parse(endpoint)?;
    let path = socket.path().to_owned();
    let allowed = [
        format!("/{target_id}"),
        format!("/devtools/node/{target_id}"),
        format!("/devtools/page/{target_id}"),
    ];
    if socket.scheme() != "ws"
        || urls::port(&socket) != urls::port(&trusted)
        || !socket.username().is_empty()
        || socket.password().is_some()
        || urls::declares_query_or_fragment(&socket)
        || !allowed.contains(&path)
    {
        return None;
    }
    socket.set_host(trusted.host_str()).ok()?;
    Some(socket.as_str().to_owned())
}

/// A runtime location decision; denials share the `unsupported_location` bucket.
pub(crate) enum Decision {
    Allowed(Value),
    Denied,
}

impl Decision {
    pub(crate) fn is_builtin(location: &Value) -> bool {
        location["kind"] == "builtin"
    }
}

/// `authorizeRuntimeLocation`.
pub(crate) fn authorize_location(
    value: &str,
    cancellation: &Cancellation,
    operation: &str,
) -> Result<Decision, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    if value.starts_with("file:") {
        let path = file_scope::authorized_file(value, cancellation, operation)?;
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        return Ok(match path {
            Some(path) => Decision::Allowed(json!({ "kind": "file", "file_path": path })),
            None => Decision::Denied,
        });
    }
    Ok(project_reported_url(value))
}

/// `projectReportedRuntimeUrl`.
pub(crate) fn project_reported_url(value: &str) -> Decision {
    if value.starts_with("node:") {
        return Decision::Allowed(json!({ "kind": "builtin", "specifier": value }));
    }
    let Some(url) = urls::parse(value) else {
        return Decision::Denied;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return Decision::Denied;
    }
    let Some(origin) = urls::exact_origin(&urls::origin(&url)) else {
        return Decision::Denied;
    };
    Decision::Allowed(json!({
        "kind": "url",
        "origin": origin,
        "sanitized_url": urls::sanitize_browser_url(value).url,
    }))
}

/// `authorizeRuntimeTargetLocation`: Node's lossy discovery pathnames.
pub(crate) fn authorize_target_location(
    value: &str,
    kind: &str,
    product: &str,
    cancellation: &Cancellation,
    operation: &str,
) -> Result<Decision, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    let node_product = product
        .get(..9)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("node.js/v"));
    if kind != "node" || !node_product || !value.starts_with("file://") {
        return authorize_location(value, cancellation, operation);
    }
    let reported = &value["file://".len()..];
    let bytes = reported.as_bytes();
    let drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\' | b'_');
    if !reported.starts_with('/') && !drive {
        return authorize_location(value, cancellation, operation);
    }
    if !cfg!(windows) && !reported.contains(['_', '"', '\\']) && reported.starts_with('/') {
        if let Some(href) = path_to_file_url(reported) {
            if let Decision::Allowed(location) = authorize_location(&href, cancellation, operation)?
            {
                return Ok(Decision::Allowed(location));
            }
        }
    }
    Ok(Decision::Allowed(json!({
        "kind": "unresolved",
        "reported_url": value,
        "reason": "unverifiable-file-location",
    })))
}

/// `pathToFileURL(path).href` for an absolute POSIX path.
fn path_to_file_url(path: &str) -> Option<String> {
    // `path.resolve` collapses `.`/`..` and repeated or trailing separators.
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let resolved = format!("/{}", parts.join("/"));
    url::Url::from_file_path(&resolved)
        .ok()
        .map(|url| url.as_str().to_owned())
}
