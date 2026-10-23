//! Header admission for streamable MCP POST requests.

use axum::http::HeaderMap;

/// Check the SDK-compatible Accept and JSON content-type requirements.
pub fn accepts_streamable_post(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get("accept").and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let accepted = split_unquoted(accept, ',')
        .into_iter()
        .filter(|range| quality(range) > 0.0)
        .map(media_type)
        .collect::<std::collections::HashSet<_>>();

    accepted.contains("application/json")
        && accepted.contains("text/event-stream")
        && accept.contains("application/json")
        && accept.contains("text/event-stream")
        && headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(is_json_content_type)
}

fn split_unquoted(value: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == separator && !quoted {
            parts.push(current);
            current = String::new();
            continue;
        }
        current.push(character);
    }
    parts.push(current);
    parts
}

fn media_type(value: String) -> String {
    split_unquoted(&value, ';')
        .first()
        .map_or_else(String::new, |media| media.trim().to_ascii_lowercase())
}

fn quality(value: &str) -> f64 {
    let parameter = split_unquoted(value, ';')
        .into_iter()
        .skip(1)
        .find_map(|parameter| {
            let (name, value) = parameter.split_once('=')?;
            (name.trim().eq_ignore_ascii_case("q")).then_some(value.trim().to_owned())
        });
    parameter
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
        .unwrap_or(1.0)
}

fn is_json_content_type(value: &str) -> bool {
    split_unquoted(value, ';')
        .first()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

#[cfg(test)]
mod tests {
    use super::accepts_streamable_post;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    fn headers(accept: &str, content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_str(accept).unwrap(),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_str(content_type).unwrap(),
        );
        headers
    }

    #[test]
    fn accepts_required_media_types_and_json_parameters() {
        assert!(accepts_streamable_post(&headers(
            "application/json, text/event-stream",
            "application/json; charset=utf-8"
        )));
    }

    #[test]
    fn rejects_zero_weight_or_case_mismatched_sdk_media_ranges() {
        assert!(!accepts_streamable_post(&headers(
            "application/json;q=0, text/event-stream",
            "application/json"
        )));
        assert!(!accepts_streamable_post(&headers(
            "Application/JSON, text/event-stream",
            "application/json"
        )));
    }

    #[test]
    fn honors_quoted_commas_and_invalid_quality_as_default_weight() {
        assert!(accepts_streamable_post(&headers(
            "application/json; note=\"a,b\", text/event-stream; q=invalid",
            "application/json"
        )));
    }

    #[test]
    fn keeps_semicolons_inside_quoted_parameters_out_of_media_type_parsing() {
        assert!(accepts_streamable_post(&headers(
            "application/json; note=\"a;b\", text/event-stream",
            "application/json; note=\"a;b\""
        )));
    }
}
