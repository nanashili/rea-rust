//! JSON-RPC HTTP error responses shared by the native MCP transport adapters.

use axum::{
    Json,
    body::Body,
    http::{Response, StatusCode},
    response::IntoResponse,
};
use serde_json::json;

/// Build the out-of-session JSON-RPC error shape used by the TypeScript server.
pub fn json_rpc_error(status: StatusCode, code: i32, message: impl Into<String>) -> Response<Body> {
    (
        status,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message.into(),
            },
            "id": null,
        })),
    )
        .into_response()
}

pub fn shutting_down() -> Response<Body> {
    json_rpc_error(
        StatusCode::SERVICE_UNAVAILABLE,
        -32000,
        "Server shutting down",
    )
}

pub fn session_not_found() -> Response<Body> {
    json_rpc_error(StatusCode::NOT_FOUND, -32001, "Session not found")
}

#[cfg(test)]
mod tests {
    use super::json_rpc_error;
    use axum::{body::to_bytes, http::StatusCode};

    #[tokio::test]
    async fn preserves_the_typescript_json_rpc_error_envelope() {
        let response = json_rpc_error(StatusCode::SERVICE_UNAVAILABLE, -32000, "capacity");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"capacity"},"id":null}"#
        );
    }
}
