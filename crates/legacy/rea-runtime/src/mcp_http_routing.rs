//! Deterministic route selection for the streamable HTTP MCP endpoint.

pub const MCP_HTTP_PATH: &str = "/mcp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub method: &'static str,
    pub path: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSelection {
    Mcp,
    Custom(usize),
    Missing,
    InvalidTarget,
}

/// Select the MCP endpoint before custom routes, matching the TypeScript router.
pub fn select_route(method: &str, path: &str, routes: &[Route]) -> RouteSelection {
    if path == MCP_HTTP_PATH {
        return RouteSelection::Mcp;
    }

    routes
        .iter()
        .position(|route| route.method == method && route.path == path)
        .map_or(RouteSelection::Missing, RouteSelection::Custom)
}

/// Select a route from an origin-form HTTP target, removing its query string.
///
/// The Node bridge rejects absolute-form and authority-form targets before
/// routing; returning `InvalidTarget` keeps that boundary explicit for callers.
pub fn select_request_target(method: &str, target: &str, routes: &[Route]) -> RouteSelection {
    let Ok(path) = validate_request_target(method, target) else {
        return RouteSelection::InvalidTarget;
    };
    select_route(method, path, routes)
}

/// Select a route while preserving the adapter response for bridge-level failures.
pub fn select_request_target_response(
    method: &str,
    target: &str,
    routes: &[Route],
) -> Result<RouteSelection, axum::http::Response<axum::body::Body>> {
    let path = validate_request_target(method, target)
        .map_err(crate::mcp_http_rejections::RequestRejection::response)?;
    Ok(select_route(method, path, routes))
}

/// Validate the bridge boundary while retaining the exact rejection for the adapter.
pub fn validate_request_target<'a>(
    method: &str,
    target: &'a str,
) -> Result<&'a str, crate::mcp_http_rejections::RequestRejection> {
    if !crate::mcp_http_methods::accepts_fetch_method(method) {
        return Err(
            crate::mcp_http_rejections::RequestRejection::UnsupportedMethod(method.to_owned()),
        );
    }

    request_path(target).ok_or(crate::mcp_http_rejections::RequestRejection::UnsupportedTarget)
}

fn request_path(target: &str) -> Option<&str> {
    if !target.starts_with('/')
        || target.starts_with("//")
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return None;
    }
    Some(target.split_once('?').map_or(target, |(path, _)| path))
}

/// Build the public endpoint URL emitted after a successful listener bind.
pub fn endpoint_url(host: &str, port: u16) -> String {
    let formatted_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    format!("http://{formatted_host}:{port}{MCP_HTTP_PATH}")
}

#[cfg(test)]
mod tests {
    use super::{
        Route, RouteSelection, endpoint_url, select_request_target, select_request_target_response,
        select_route, validate_request_target,
    };
    use crate::mcp_http_rejections::RequestRejection;
    use axum::{body::to_bytes, http::StatusCode};

    const HEALTH: Route = Route {
        method: "GET",
        path: "/health",
    };

    #[test]
    fn reserves_mcp_path_before_custom_routes() {
        let routes = [
            Route {
                method: "GET",
                path: "/mcp",
            },
            HEALTH,
        ];

        assert_eq!(select_route("GET", "/mcp", &routes), RouteSelection::Mcp);
        assert_eq!(
            select_route("GET", "/health", &routes),
            RouteSelection::Custom(1)
        );
        assert_eq!(
            select_route("POST", "/health", &routes),
            RouteSelection::Missing
        );
    }

    #[test]
    fn formats_ipv4_and_ipv6_endpoint_urls() {
        assert_eq!(endpoint_url("127.0.0.1", 8425), "http://127.0.0.1:8425/mcp");
        assert_eq!(endpoint_url("::1", 8425), "http://[::1]:8425/mcp");
        assert_eq!(endpoint_url("[::1]", 8425), "http://[::1]:8425/mcp");
    }

    #[test]
    fn routes_origin_form_targets_without_query_parameters() {
        assert_eq!(
            select_request_target("GET", "/health?ready=true", &[HEALTH]),
            RouteSelection::Custom(0)
        );
        assert_eq!(
            select_request_target("GET", "https://example.test/health", &[HEALTH]),
            RouteSelection::InvalidTarget
        );
        assert_eq!(
            select_request_target("GET", "//example.test/health", &[HEALTH]),
            RouteSelection::InvalidTarget
        );
    }

    #[test]
    fn rejects_forbidden_methods_before_route_matching() {
        assert_eq!(
            select_request_target("TRACE", "/health", &[HEALTH]),
            RouteSelection::InvalidTarget
        );
        assert_eq!(
            validate_request_target("TRACE", "/health"),
            Err(RequestRejection::UnsupportedMethod("TRACE".into()))
        );
    }

    #[test]
    fn preserves_target_rejection_for_the_http_adapter() {
        assert_eq!(
            validate_request_target("GET", "https://example.test/health"),
            Err(RequestRejection::UnsupportedTarget)
        );
    }

    #[tokio::test]
    async fn returns_the_method_rejection_response_at_the_route_boundary() {
        let response = select_request_target_response("TRACE", "/health", &[HEALTH])
            .expect_err("TRACE must be rejected before routing");

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Unsupported method TRACE"},"id":null}"#
        );
    }

    #[tokio::test]
    async fn returns_the_target_rejection_response_at_the_route_boundary() {
        let response =
            select_request_target_response("GET", "https://example.test/health", &[HEALTH])
                .expect_err("absolute-form targets must be rejected before routing");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Unsupported request target"},"id":null}"#
        );
    }
}
