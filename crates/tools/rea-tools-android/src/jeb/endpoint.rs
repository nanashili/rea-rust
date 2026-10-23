//! Caller-selected JEB MCP endpoint admission.
//!
//! Compatibility owner: `src/jeb/JebMcpEndpoint.ts`. Only the scheme, host and
//! port select the engine; credentials, non-`/mcp` paths, queries and
//! fragments are rejected rather than silently dropped.
use rea_core::analysis_error::{AnalysisError, InputIssue};

/// Default JEB MCP endpoint documented by the engine's headless client.
pub const DEFAULT_JEB_MCP_ENDPOINT: &str = "http://127.0.0.1:8425/mcp";

/// A normalized loopback JEB MCP endpoint.
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// Full normalized href, e.g. `http://127.0.0.1:8425/mcp`.
    href: String,
    /// `http` or `https`.
    pub scheme: String,
    /// Literal loopback host, `127.0.0.1` or `[::1]`.
    pub host: String,
    /// Host without brackets, used for the TCP connection (`127.0.0.1`, `::1`).
    pub connect_host: String,
    pub port: u16,
    /// Request-target path, `/mcp` or `/mcp/`.
    pub path: String,
}

impl Endpoint {
    /// Full normalized endpoint string (`url.toString()`).
    pub fn href(&self) -> &str {
        &self.href
    }

    /// Value for the HTTP `Host` header (`host[:port]`).
    pub fn host_header(&self) -> String {
        if self.is_default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn is_default_port(&self) -> bool {
        (self.scheme == "http" && self.port == 80) || (self.scheme == "https" && self.port == 443)
    }
}

/// `new AnalysisInputError("jeb_mcp_endpoint", { cause })`.
fn endpoint_error(cause: &str) -> AnalysisError {
    AnalysisError::input(
        "jeb_mcp_endpoint",
        vec![InputIssue {
            path: Vec::new(),
            reason: "invalid_value",
            message: Some(cause.to_owned()),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    )
}

/// Parsed URL components, mirroring the fields the WHATWG `URL` exposes.
struct ParsedUrl {
    scheme: String,
    username: String,
    password: String,
    host: String,
    connect_host: String,
    port: Option<u16>,
    path: String,
    has_query: bool,
    has_fragment: bool,
}

/// Parse an absolute URL into the components `parseJebMcpEndpoint` inspects.
///
/// This is deliberately a minimal absolute-URL parser: it accepts the loopback
/// shapes the engine endpoint can take and rejects anything that cannot be an
/// absolute http(s) URL, matching `new URL(...)` throwing for the rejected
/// cases this consumer cares about.
fn parse_absolute_url(value: &str) -> Option<ParsedUrl> {
    // Query and fragment are detected on the raw spelling so an empty one is
    // still observed (the TS `urlDeclaresQueryOrFragment` check on `href`).
    let has_fragment = value.contains('#');
    let before_fragment = value.split('#').next().unwrap_or("");
    let has_query = before_fragment.contains('?');
    let before_query = before_fragment.split('?').next().unwrap_or("");

    let (scheme, rest) = before_query.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    if !scheme
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
    {
        return None;
    }

    // Split authority from path at the first '/'.
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return None;
    }

    // Userinfo.
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo), host_port),
        None => (None, authority),
    };
    let (username, password) = match userinfo {
        Some(userinfo) => match userinfo.split_once(':') {
            Some((user, pass)) => (user.to_owned(), pass.to_owned()),
            None => (userinfo.to_owned(), String::new()),
        },
        None => (String::new(), String::new()),
    };

    // Host and optional port. Bracketed IPv6 literals keep their brackets in
    // the host spelling but not in the connect host.
    let (host, connect_host, port_str) = if let Some(rest) = host_port.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let port_str = after.strip_prefix(':').map(str::to_owned);
        if !after.is_empty() && port_str.is_none() {
            return None;
        }
        (format!("[{inner}]"), inner.to_owned(), port_str)
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), host.to_owned(), Some(port.to_owned())),
            None => (host_port.to_owned(), host_port.to_owned(), None),
        }
    };
    if host.is_empty() || connect_host.is_empty() {
        return None;
    }

    let port = match port_str {
        Some(port) if port.is_empty() => None,
        Some(port) => Some(port.parse::<u16>().ok()?),
        None => None,
    };

    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path.to_owned()
    };

    Some(ParsedUrl {
        scheme,
        username,
        password,
        host: host.to_ascii_lowercase(),
        connect_host,
        port,
        path,
        has_query,
        has_fragment,
    })
}

/// Normalize the caller-selected JEB MCP endpoint.
///
/// Compatibility owner: `parseJebMcpEndpoint`.
pub fn parse_jeb_mcp_endpoint(value: Option<&str>) -> Result<Endpoint, AnalysisError> {
    let raw = match value {
        Some(value) if !value.is_empty() => value,
        _ => DEFAULT_JEB_MCP_ENDPOINT,
    };

    let Some(url) = parse_absolute_url(raw) else {
        return Err(endpoint_error("Expected an absolute http(s) URL"));
    };

    if url.scheme != "http" && url.scheme != "https" {
        return Err(endpoint_error(
            "Only http and https JEB MCP endpoints are supported",
        ));
    }

    if url.host != "127.0.0.1" && url.host != "[::1]" {
        return Err(endpoint_error(
            "JEB MCP endpoint must use a literal loopback host (127.0.0.1 or ::1)",
        ));
    }

    if !url.username.is_empty() || !url.password.is_empty() {
        return Err(endpoint_error(
            "Embedding credentials in the JEB MCP endpoint is not supported; configure authentication with the engine",
        ));
    }

    if url.path != "/mcp" && url.path != "/mcp/" {
        return Err(endpoint_error("JEB MCP endpoint must use the /mcp route"));
    }

    if url.has_query || url.has_fragment {
        return Err(endpoint_error(
            "JEB MCP endpoint query strings and fragments are not supported",
        ));
    }

    let port = url
        .port
        .unwrap_or(if url.scheme == "https" { 443 } else { 80 });

    // The normalized href mirrors WHATWG `URL.toString()`: the default port is
    // omitted, and a lone trailing-slash root path stays as spelled.
    let authority =
        if (url.scheme == "http" && port == 80) || (url.scheme == "https" && port == 443) {
            url.host.clone()
        } else {
            format!("{}:{}", url.host, port)
        };
    let href = format!("{}://{}{}", url.scheme, authority, url.path);

    Ok(Endpoint {
        href,
        scheme: url.scheme,
        host: url.host,
        connect_host: url.connect_host,
        port,
        path: url.path,
    })
}
