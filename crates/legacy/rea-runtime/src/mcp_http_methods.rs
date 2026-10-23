//! Fetch-compatible request-method validation for the HTTP bridge.

/// Node's Web `Request` bridge rejects these methods before MCP routing.
pub fn accepts_fetch_method(method: &str) -> bool {
    !method.is_empty()
        && !method.eq_ignore_ascii_case("CONNECT")
        && !method.eq_ignore_ascii_case("TRACE")
        && !method.eq_ignore_ascii_case("TRACK")
        && method
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b' ' | b'"' | b'(' | b')'))
}

#[cfg(test)]
mod tests {
    use super::accepts_fetch_method;

    #[test]
    fn accepts_methods_that_can_reach_the_web_request_bridge() {
        for method in ["GET", "HEAD", "POST", "DELETE", "OPTIONS", "PATCH", "X-MCP"] {
            assert!(
                accepts_fetch_method(method),
                "unexpected rejection: {method}"
            );
        }
    }

    #[test]
    fn rejects_fetch_forbidden_and_malformed_methods() {
        for method in ["CONNECT", "TRACE", "TRACK", "", "BAD METHOD", "BAD\nMETHOD"] {
            assert!(
                !accepts_fetch_method(method),
                "unexpected acceptance: {method:?}"
            );
        }
    }
}
