//! Session dispatch classification for streamable HTTP requests.

use crate::mcp_http_initialize::is_initialize_post;

/// The session transition implied by one request's transport metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDispatch {
    /// A lone initialize may replace the currently active client.
    ReplaceActive,
    /// A session id was supplied; dispatch remains attached to that session.
    ExistingSession,
    /// No session id was supplied, but the request was not a valid initializer.
    Unsessioned,
}

/// Classify replacement eligibility without consuming or mutating a session.
pub fn classify_session_dispatch(
    method: &str,
    has_session_id: bool,
    has_streamable_headers: bool,
    body: &[u8],
    max_body_bytes: usize,
) -> SessionDispatch {
    if is_initialize_post(
        method,
        has_session_id,
        has_streamable_headers,
        body,
        max_body_bytes,
    ) {
        return SessionDispatch::ReplaceActive;
    }

    if has_session_id {
        SessionDispatch::ExistingSession
    } else {
        SessionDispatch::Unsessioned
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionDispatch, classify_session_dispatch};

    const INITIALIZE: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
    const TOOL_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call"}"#;

    #[test]
    fn classifies_only_a_valid_initializer_as_replacement() {
        assert_eq!(
            classify_session_dispatch("POST", false, true, INITIALIZE, 1024),
            SessionDispatch::ReplaceActive
        );
        assert_eq!(
            classify_session_dispatch("POST", true, true, INITIALIZE, 1024),
            SessionDispatch::ExistingSession
        );
    }

    #[test]
    fn preserves_non_initializer_requests_as_unsessioned_or_existing() {
        assert_eq!(
            classify_session_dispatch("POST", false, true, TOOL_CALL, 1024),
            SessionDispatch::Unsessioned
        );
        assert_eq!(
            classify_session_dispatch("POST", true, true, TOOL_CALL, 1024),
            SessionDispatch::ExistingSession
        );
    }
}
