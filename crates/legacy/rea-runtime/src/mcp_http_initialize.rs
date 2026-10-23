//! Bounded detection of the session-opening initialize request.

use serde_json::Value;

/// Decide whether a request is eligible to replace the current HTTP session.
///
/// The probe intentionally receives the already validated streamable-header
/// result. A failed probe must leave the current session in place.
pub fn is_initialize_post(
    method: &str,
    has_session_id: bool,
    has_streamable_headers: bool,
    body: &[u8],
    max_body_bytes: usize,
) -> bool {
    if method != "POST" || has_session_id || !has_streamable_headers || body.len() > max_body_bytes
    {
        return false;
    }

    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };

    match &value {
        Value::Array(messages) if messages.len() == 1 => {
            messages.first().is_some_and(is_initialize_message)
        }
        Value::Object(_) => is_initialize_message(&value),
        _ => false,
    }
}

fn is_initialize_message(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|message| message.get("method"))
        .and_then(Value::as_str)
        == Some("initialize")
}

#[cfg(test)]
mod tests {
    use super::is_initialize_post;

    const INITIALIZE: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;

    #[test]
    fn accepts_a_lone_initialize_without_a_session() {
        assert!(is_initialize_post("POST", false, true, INITIALIZE, 1024));
        assert!(is_initialize_post(
            "POST",
            false,
            true,
            br#"[{"jsonrpc":"2.0","id":1,"method":"initialize"}]"#,
            1024
        ));
    }

    #[test]
    fn rejects_requests_that_cannot_replace_a_session() {
        for (method, has_session, has_headers, body) in [
            ("GET", false, true, INITIALIZE),
            ("POST", true, true, INITIALIZE),
            ("POST", false, false, INITIALIZE),
            ("POST", false, true, br#"{"method":"tools/list"}"#),
            (
                "POST",
                false,
                true,
                br#"[{"method":"initialize"},{"method":"ping"}]"#,
            ),
            ("POST", false, true, br#"not-json"#),
        ] {
            assert!(
                !is_initialize_post(method, has_session, has_headers, body, 1024),
                "unexpected initialize probe acceptance for {method}"
            );
        }
    }

    #[test]
    fn rejects_a_body_over_the_probe_bound() {
        assert!(!is_initialize_post("POST", false, true, INITIALIZE, 8));
    }
}
