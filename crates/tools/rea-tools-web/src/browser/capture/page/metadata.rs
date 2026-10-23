//! Allowlisted response metadata: `src/browser/CdpSafeMetadata.ts`
//! (`safeResponseMetadata`) and `src/browser/StructuredFieldToken.ts`.
//! Raw headers are read once here and discarded.
use super::super::values::{self, Record};
use crate::cdp::json_text::js_number_string;
use crate::cdp::urls;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

/// ECMAScript `WhiteSpace` + `LineTerminator` (`\s`, `String.prototype.trim`).
pub(super) fn is_js_space(character: char) -> bool {
    (character.is_whitespace() && character != '\u{85}') || character == '\u{FEFF}'
}

const JS_SPACE_CLASS: &str = r"[\t\n\x0B\x0C\r \u{A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}\u{FEFF}]";

fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_space)
}

/// `text.split(/\s+/u)`.
fn split_js_space(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_space = false;
    for (index, character) in text.char_indices() {
        if is_js_space(character) {
            if !in_space {
                parts.push(&text[start..index]);
                in_space = true;
            }
        } else if in_space {
            start = index;
            in_space = false;
        }
    }
    if in_space {
        parts.push("");
    } else {
        parts.push(&text[start..]);
    }
    parts
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("metadata pattern"))
}

fn is_token_name(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

fn agent_hint(mechanism: &str, declaration: &str, url: Option<String>) -> Value {
    json!({ "mechanism": mechanism, "declaration": declaration, "url": url, "trust": "page-declared-untrusted" })
}

const AGENT_RELS: [&str; 4] = ["mcp", "model-context", "ai-plugin", "service-desc"];
const AGENT_HEADERS: [&str; 3] = ["x-model-context", "x-webmcp", "mcp-server"];
const WELL_KNOWN: [&str; 3] = [
    "/.well-known/ai-plugin.json",
    "/.well-known/mcp",
    "/.well-known/model-context",
];

/// `safeResponseMetadata`.
pub(super) fn safe_response_metadata(
    request_id: &str,
    url: &str,
    response: &Record,
    origins: &BTreeSet<String>,
) -> (Value, Vec<Value>) {
    let headers = normalized_headers(response.get("headers"));
    let header = |name: &str| headers.get(name).map(String::as_str);
    let links = parse_links(header("link"), url, origins);
    let csp = parse_csp(header("content-security-policy"), url, origins);
    let mut hints = Vec::new();
    for link in &links {
        let rels: Vec<&str> = link["rel"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if rels.iter().any(|rel| AGENT_RELS.contains(rel)) {
            hints.push(agent_hint(
                "link_rel",
                &rels.join(" "),
                link["href"].as_str().map(str::to_owned),
            ));
        }
    }
    for name in AGENT_HEADERS {
        if headers.contains_key(name) {
            hints.push(agent_hint("response_header", name, None));
        }
    }
    if let Some(parsed) = urls::parse(url) {
        let path = parsed.path().to_lowercase();
        if WELL_KNOWN.contains(&path.as_str()) {
            hints.push(agent_hint(
                "well_known_resource",
                &path,
                Some(urls::sanitize_browser_url(url).url),
            ));
        }
    }
    let metadata = json!({
        "request_id": request_id,
        "url": url,
        "mime_type": bounded(values::string(response.get("mimeType"))),
        "content_length": content_length(header("content-length")),
        "content_encoding": bounded(header("content-encoding")),
        "csp": csp,
        "links": links,
        "policies": {
            "coop": structured_field_token(header("cross-origin-opener-policy")),
            "coep": structured_field_token(header("cross-origin-embedder-policy")),
            "corp": policy_token(header("cross-origin-resource-policy")),
            "referrer_policy": referrer_policy(header("referrer-policy")),
            "x_content_type_options": policy_token(header("x-content-type-options")),
            "permissions_policy_features": permission_features(header("permissions-policy")),
        },
    });
    (metadata, hints)
}

fn normalized_headers(value: Option<&Value>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for (name, raw) in values::record(value).into_iter().flatten() {
        let header = match raw {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => number
                .as_f64()
                .filter(|value| value.is_finite())
                .map(js_number_string),
            _ => None,
        };
        if let Some(header) = header {
            headers.insert(name.to_lowercase(), header);
        }
    }
    headers
}

fn parse_csp(value: Option<&str>, base: &str, origins: &BTreeSet<String>) -> Value {
    let mut directives = Vec::new();
    let (mut nonces, mut hashes) = (0_u64, 0_u64);
    for raw in value.unwrap_or("").split(';') {
        let parts = split_js_space(js_trim(raw));
        let name = parts.first().copied().unwrap_or("").to_lowercase();
        if !is_token_name(&name) {
            continue;
        }
        let mut sources = Vec::new();
        for token in &parts[1..] {
            let lower = token.to_lowercase();
            if lower.starts_with("'nonce-") {
                nonces += 1;
                continue;
            }
            if lower.starts_with("'sha256-")
                || lower.starts_with("'sha384-")
                || lower.starts_with("'sha512-")
            {
                hashes += 1;
                continue;
            }
            sources.push(csp_source(token, base, origins));
        }
        directives.push(json!({ "name": name, "sources": sources }));
    }
    json!({ "directives": directives, "nonce_count": nonces, "hash_count": hashes })
}

fn csp_source(token: &str, base: &str, origins: &BTreeSet<String>) -> Value {
    static KEYWORD: OnceLock<Regex> = OnceLock::new();
    static SCHEME: OnceLock<Regex> = OnceLock::new();
    let lower = token.to_lowercase();
    if regex(&KEYWORD, r"^'[a-z0-9\-]+'$").is_match(&lower) {
        return json!({ "kind": "keyword", "value": lower });
    }
    if regex(&SCHEME, r"^[a-z][a-z0-9+.\-]*:$").is_match(&lower) {
        return json!({ "kind": "scheme", "value": lower });
    }
    match csp_host_source_origin(token, base) {
        None => json!({ "kind": "other", "value": null }),
        Some(Some(origin)) if origins.contains(&origin) => {
            json!({ "kind": "approved_origin", "value": origin })
        }
        Some(_) => json!({ "kind": "external_origin", "value": null }),
    }
}

/// `cspHostSourceOrigin`: `None` is "not a host-source", `Some(None)` a
/// wildcard set of origins.
fn csp_host_source_origin(token: &str, base: &str) -> Option<Option<String>> {
    static SOURCE: OnceLock<Regex> = OnceLock::new();
    static SCHEME: OnceLock<Regex> = OnceLock::new();
    static AUTHORITY: OnceLock<Regex> = OnceLock::new();
    let captures = regex(
        &SOURCE,
        r"(?i)^(?:([a-z][a-z0-9+.\-]*)://)?([^/?#]+)(?:/[^?#]*)?$",
    )
    .captures(token)?;
    let authority = captures.get(2)?.as_str();
    if authority.is_empty() {
        return None;
    }
    let scheme = match captures.get(1) {
        Some(scheme) => scheme.as_str().to_lowercase(),
        None => urls::parse(base)?.scheme().to_lowercase(),
    };
    if !regex(&SCHEME, r"^[a-z][a-z0-9+.\-]*$").is_match(&scheme) {
        return None;
    }
    if !regex(
        &AUTHORITY,
        r"(?i)^(?:\*|(?:\*\.)?[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.?)(?::(?:\*|[0-9]+))?$",
    )
    .is_match(authority)
    {
        return None;
    }
    if authority.contains('*') {
        return Some(None);
    }
    let parsed = urls::parse(&format!("{scheme}://{authority}"))?;
    let origin = urls::origin(&parsed);
    (parsed.username().is_empty()
        && parsed.password().is_none_or(str::is_empty)
        && parsed.path() == "/"
        && origin != "null")
        .then_some(Some(origin))
}

fn parse_links(value: Option<&str>, base: &str, origins: &BTreeSet<String>) -> Vec<Value> {
    static ENTRY: OnceLock<Regex> = OnceLock::new();
    let entry_pattern = ENTRY.get_or_init(|| {
        Regex::new(&format!(
            r"^{JS_SPACE_CLASS}*<([^>]*)>([^\n\r\u{{2028}}\u{{2029}}]*)$"
        ))
        .expect("link pattern")
    });
    let mut links = Vec::new();
    let text = value.unwrap_or("");
    for line in split_lines(text) {
        for entry in split_link_header(line, ',') {
            let Some(captures) = entry_pattern.captures(entry) else {
                continue;
            };
            let parameters = link_parameters(captures.get(2).map_or("", |group| group.as_str()));
            let (href, scope) = safe_destination(
                captures.get(1).map_or("", |group| group.as_str()),
                base,
                origins,
            );
            let rel: Vec<String> = split_js_space(
                &parameters
                    .get("rel")
                    .cloned()
                    .unwrap_or_default()
                    .to_lowercase(),
            )
            .into_iter()
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
            links.push(json!({
                "href": href,
                "destination_scope": scope,
                "rel": rel,
                "as": bounded(parameters.get("as").map(String::as_str)),
                "type": bounded(parameters.get("type").map(String::as_str)),
                "crossorigin": bounded(parameters.get("crossorigin").map(String::as_str)),
            }));
        }
    }
    links
}

/// `value.split(/\r?\n/u)`.
fn split_lines(text: &str) -> Vec<&str> {
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>()
        .into_iter()
        .collect()
}

fn split_link_header(value: &str, delimiter: char) -> Vec<&str> {
    let mut entries = Vec::new();
    let (mut start, mut quoted, mut escaped, mut target) = (0, false, false, false);
    for (index, character) in value.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        if character == '"' && !target {
            quoted = true;
        } else if delimiter == ',' && character == '<' {
            target = true;
        } else if delimiter == ',' && character == '>' {
            target = false;
        } else if character == delimiter && !target {
            entries.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    entries.push(&value[start..]);
    entries
}

fn link_parameters(value: &str) -> HashMap<String, String> {
    let mut parameters = HashMap::new();
    for raw in split_link_header(value, ';').into_iter().skip(1) {
        let separator = raw.find('=');
        let name = js_trim(separator.map_or(raw, |at| &raw[..at])).to_lowercase();
        if !is_token_name(&name) {
            continue;
        }
        let parameter = separator.map_or("", |at| js_trim(&raw[at + 1..]));
        parameters.insert(name, unquote(parameter).to_owned());
    }
    parameters
}

fn safe_destination(value: &str, base: &str, origins: &BTreeSet<String>) -> (Value, &'static str) {
    let Some(parsed) = urls::parse_with_base(value, base) else {
        return (json!(value), "unsupported");
    };
    let sanitized = urls::sanitize_browser_url(parsed.as_str()).url;
    if !matches!(parsed.scheme(), "http" | "https") {
        return (json!(sanitized), "unsupported");
    }
    if !origins.contains(&urls::origin(&parsed)) {
        return (json!(sanitized), "outside_policy");
    }
    (json!(sanitized), "approved")
}

fn permission_features(value: Option<&str>) -> Vec<String> {
    let features: BTreeSet<String> = value
        .unwrap_or("")
        .split(',')
        .map(|entry| js_trim(entry.split('=').next().unwrap_or("")).to_lowercase())
        .filter(|feature| is_token_name(feature))
        .collect();
    features.into_iter().collect()
}

const REFERRER_POLICIES: [&str; 8] = [
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "origin",
    "strict-origin",
    "origin-when-cross-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
];

fn referrer_policy(value: Option<&str>) -> Option<String> {
    let mut policy = None;
    for raw in value.unwrap_or("").split(',') {
        let token = js_trim(raw).to_lowercase();
        if token.is_empty() {
            continue;
        }
        if !token
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '-')
        {
            return None;
        }
        if REFERRER_POLICIES.contains(&token.as_str()) {
            policy = Some(token);
        }
    }
    policy
}

fn policy_token(value: Option<&str>) -> Option<String> {
    let token = js_trim(value.unwrap_or("")).to_lowercase();
    let mut characters = token.chars();
    (characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '.' | '-')
        }))
    .then_some(token)
}

fn content_length(value: Option<&str>) -> Value {
    let token = js_trim(value.unwrap_or(""));
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Value::Null;
    }
    match token.parse::<f64>() {
        Ok(length) if length <= 9_007_199_254_740_991.0 => json!(length as u64),
        _ => Value::Null,
    }
}

fn bounded(value: Option<&str>) -> Option<String> {
    value.map(|text| js_trim(text).to_lowercase())
}

fn unquote(value: &str) -> &str {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        &value[1..value.len() - 1]
    } else if value == "\"" {
        // `'"'.startsWith('"') && '"'.endsWith('"')` slices to "".
        ""
    } else {
        value
    }
}

/// `structuredFieldToken` (RFC 9651 sections 4.2.3–4.2.10).
fn structured_field_token(value: Option<&str>) -> Option<String> {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    static KEY: OnceLock<Regex> = OnceLock::new();
    static BARE: OnceLock<Regex> = OnceLock::new();
    let token = regex(&TOKEN, r"^[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/\-]*");
    let key = regex(&KEY, r"^[a-z*][a-z0-9_.*\-]*");
    let bare = regex(
        &BARE,
        r#"^(?:[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/\-]*|"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\["\\])*"|-?[0-9]{1,12}\.[0-9]{1,3}|-?[0-9]{1,15}|\?[01]|@-?[0-9]{1,15}|:(?P<bytes>[A-Za-z0-9+/]*={0,2}):|%"(?P<display>(?:[\x20-\x21\x23-\x24\x26-\x7e]|%[0-9a-f]{2})*)")"#,
    );
    let value = value?;
    let bytes = value.as_bytes();
    let mut cursor = 0;
    while bytes.get(cursor) == Some(&b' ') {
        cursor += 1;
    }
    let declared = token.find(&value[cursor..])?;
    let declared_text = declared.as_str().to_owned();
    cursor += declared.end();
    while bytes.get(cursor) == Some(&b';') {
        cursor += 1;
        while bytes.get(cursor) == Some(&b' ') {
            cursor += 1;
        }
        let matched = key.find(&value[cursor..])?;
        cursor += matched.end();
        if bytes.get(cursor) != Some(&b'=') {
            continue;
        }
        let parameter = bare.captures(&value[cursor + 1..])?;
        cursor += 1 + parameter.get(0)?.end();
        if let Some(encoded) = parameter.name("bytes") {
            let encoded = encoded.as_str();
            let invalid = if encoded.ends_with('=') {
                encoded.len() % 4 != 0
            } else {
                encoded.len() % 4 == 1
            };
            if invalid {
                return None;
            }
        }
        if let Some(display) = parameter.name("display") {
            if !percent_utf8(display.as_str()) {
                return None;
            }
        }
    }
    while bytes.get(cursor) == Some(&b' ') {
        cursor += 1;
    }
    (cursor == bytes.len()).then_some(declared_text)
}

/// `decodeURIComponent` succeeds on percent-checked display text.
fn percent_utf8(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(byte) = text
                .get(index + 1..index + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            else {
                return false;
            };
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    std::str::from_utf8(&decoded).is_ok()
}
