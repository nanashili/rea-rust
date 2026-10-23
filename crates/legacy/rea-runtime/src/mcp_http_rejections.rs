//! HTTP request rejection responses produced before MCP routing.

use axum::{body::Body, http::Response, http::StatusCode};

use crate::mcp_http_errors::json_rpc_error;

/// A request can fail before a Web `Request` reaches the MCP router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestRejection {
    /// The request target was not an origin-form path.
    UnsupportedTarget,
    /// The method is accepted by `node:http` but rejected by the Web Request bridge.
    UnsupportedMethod(String),
}

impl RequestRejection {
    /// The status and JSON-RPC message used by the TypeScript bridge.
    pub fn response(self) -> Response<Body> {
        match self {
            Self::UnsupportedTarget => json_rpc_error(
                StatusCode::BAD_REQUEST,
                -32600,
                "Unsupported request target",
            ),
            Self::UnsupportedMethod(method) => json_rpc_error(
                StatusCode::METHOD_NOT_ALLOWED,
                -32600,
                format!("Unsupported method {method}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RequestRejection;
    use axum::{body::to_bytes, http::StatusCode};

    #[tokio::test]
    async fn rejects_unsupported_targets_with_bad_request() {
        let response = RequestRejection::UnsupportedTarget.response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Unsupported request target"},"id":null}"#
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_methods_with_method_not_allowed() {
        let response = RequestRejection::UnsupportedMethod("TRACE".into()).response();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Unsupported method TRACE"},"id":null}"#
        );
    }
}
