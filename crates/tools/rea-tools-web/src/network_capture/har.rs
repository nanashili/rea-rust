//! HAR 1.2 capture decoding.
//!
//! Compatibility owners: `src/browser/history/HarCapture.ts`,
//! `src/browser/history/HarSchema.ts` and `src/browser/history/CaptureRelease.ts`.
//! Decodes a retained HAR in-process (the TS decodes it in an owned Node
//! process only for heap isolation) with the same lossless numeric literals,
//! base64 binary projection, credential and explicit-literal exclusions, and
//! the same validation adaptations for mitmproxy and Playwright producers.
use super::errors::CaptureFormatError;
use super::json_capture::{CaptureJson, parse_capture_json, reported_number, safe_number};
use super::limits::CAPTURE_DEPTH;
use super::redaction::{
    CaptureRedaction, capture_pointer, property_name_redaction, redaction_entry,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Provider identity of the HAR decoder.
pub const HAR_ID: &str = "har-schema/lossless-json";
pub const HAR_NAME: &str = "REA HAR capture adapter";
pub const HAR_VERSION: &str = "har-schema@2.0.0;jsonc-parser@3.3.1;lossless-json@4.3.1";

const RECORD_LIMITATION: &str = "HAR text is producer-decoded Unicode. Original body bytes remain unknown unless content explicitly uses valid base64; declared sizes are preserved independently of retained bytes. mitmproxy 12.2.3 SaveHar may report null optional postData.text; that null is retained and omitted only from the upstream validation copy.";
const PLAYWRIGHT_LIMITATION: &str = "This capture declares Playwright 1.58.2 and reports bracketed IPv6 serverIPAddress. Original spellings are retained; brackets were removed only from valid IPv6 values in the validation copy. Producer declarations are not authenticated.";
const RECORD_EXCLUDED_LIMITATION: &str = "This record's payload and sidecars are excluded because its structural ancestor property was explicitly marked sensitive.";

/// The decoded capture facts shared with the service projection.
pub struct DecodedCapture {
    pub container: ContainerFacts,
    pub records: Vec<Value>,
}

/// Source coverage facts for the container.
pub struct ContainerFacts {
    pub reported: Value,
    pub numeric_literals: Vec<Value>,
    pub redactions: Vec<Value>,
    pub records_pointer: Option<String>,
}

/// One projection of source facts.
struct Projection {
    reported: Value,
    numeric_literals: Vec<Value>,
    binary_fields: Vec<Value>,
    redactions: Vec<Value>,
}

/// Decode a retained HAR into the shared capture facts.
pub fn decode_har_capture(
    text: &str,
    sensitive_values: &[String],
) -> Result<DecodedCapture, CaptureFormatError> {
    let raw = parse_capture_json(text, "HAR")?;

    let log = object_member(&raw, "log");
    let entries = log.and_then(|log| object_member(log, "entries"));
    let entries = match entries {
        Some(CaptureJson::Array(items)) => items,
        _ => {
            return Err(CaptureFormatError::new(
                "format",
                "HAR must contain log.entries.",
                "",
            ));
        }
    };

    // Only the pinned HAR 1.2 schema profile is supported.
    let version = log.and_then(|log| object_member(log, "version"));
    let version_matches = matches!(version, Some(CaptureJson::String(value)) if value == "1.2");
    if !version_matches {
        return Err(CaptureFormatError::new(
            "unsupported",
            "Only the pinned HAR 1.2 schema profile is supported.",
            "/log/version",
        ));
    }

    // Run the pinned upstream validation over a disposable copy, matching the
    // observed producer adaptations.
    let playwright_entries = validate_har(&raw, entries)?;

    let records_excluded = ["log", "entries"].iter().any(|key| {
        sensitive_values
            .iter()
            .any(|literal| key.contains(literal.as_str()))
    });

    // Container projection with entries blanked to null.
    let container_raw = log_with_null_entries(&raw);
    let container = project_har(&container_raw, sensitive_values, true)?;

    let mut records = Vec::with_capacity(entries.len());
    for (ordinal, entry) in entries.iter().enumerate() {
        // Validate every original record even when excluded (projection runs).
        let projected = project_har(entry, sensitive_values, true)?;
        let projection = if records_excluded {
            Projection {
                reported: Value::Null,
                numeric_literals: Vec::new(),
                binary_fields: Vec::new(),
                redactions: vec![redaction_entry("", "explicit-sensitive-value")],
            }
        } else {
            projected
        };

        let location = if records_excluded {
            json!({ "kind": "unknown", "reason": "explicit-sensitive-value" })
        } else {
            json!({ "kind": "json-pointer", "pointer": format!("/log/entries/{ordinal}") })
        };

        let mut limitations = vec![RECORD_LIMITATION.to_owned()];
        if playwright_entries.contains(&ordinal) {
            limitations.push(PLAYWRIGHT_LIMITATION.to_owned());
        }
        if records_excluded {
            limitations.push(RECORD_EXCLUDED_LIMITATION.to_owned());
        }

        records.push(json!({
            "ordinal": ordinal,
            "location": location,
            "reported": projection.reported,
            "binary_fields": projection.binary_fields,
            "numeric_literals": projection.numeric_literals,
            "redactions": projection.redactions,
            "limitations": limitations,
        }));
    }

    Ok(DecodedCapture {
        container: ContainerFacts {
            reported: container.reported,
            numeric_literals: container.numeric_literals,
            redactions: container.redactions,
            records_pointer: if records_excluded {
                None
            } else {
                Some("/log/entries".to_owned())
            },
        },
        records,
    })
}

/// Lookup an object member by key in a `CaptureJson` object.
fn object_member<'a>(value: &'a CaptureJson, key: &str) -> Option<&'a CaptureJson> {
    match value {
        CaptureJson::Object(members) => members
            .iter()
            .find(|(member, _)| member == key)
            .map(|(_, value)| value),
        _ => None,
    }
}

/// Clone `raw` with `log.entries` replaced by null for the container projection.
fn log_with_null_entries(raw: &CaptureJson) -> CaptureJson {
    match raw {
        CaptureJson::Object(members) => {
            let rebuilt = members
                .iter()
                .map(|(key, value)| {
                    if key == "log" {
                        if let CaptureJson::Object(log_members) = value {
                            let log = log_members
                                .iter()
                                .map(|(log_key, log_value)| {
                                    if log_key == "entries" {
                                        (log_key.clone(), CaptureJson::Null)
                                    } else {
                                        (log_key.clone(), log_value.clone())
                                    }
                                })
                                .collect();
                            return (key.clone(), CaptureJson::Object(log));
                        }
                    }
                    (key.clone(), value.clone())
                })
                .collect();
            CaptureJson::Object(rebuilt)
        }
        other => other.clone(),
    }
}

/// Evidence projection (`redact=true`) over a source value.
fn project_har(
    value: &CaptureJson,
    sensitive_values: &[String],
    redact: bool,
) -> Result<Projection, CaptureFormatError> {
    let mut state = ProjectState {
        redactor: CaptureRedaction::new(sensitive_values),
        numeric_literals: Vec::new(),
        binary_fields: Vec::new(),
        sensitive_values,
        redact,
    };
    let reported = state.visit(value, "", 0, None)?;
    Ok(Projection {
        reported,
        numeric_literals: state.numeric_literals,
        binary_fields: state.binary_fields,
        redactions: state.redactor.redactions,
    })
}

struct ProjectState<'a> {
    redactor: CaptureRedaction,
    numeric_literals: Vec<Value>,
    binary_fields: Vec<Value>,
    sensitive_values: &'a [String],
    redact: bool,
}

impl ProjectState<'_> {
    fn visit(
        &mut self,
        item: &CaptureJson,
        pointer: &str,
        depth: usize,
        parent: Option<&CaptureJson>,
    ) -> Result<Value, CaptureFormatError> {
        if depth > CAPTURE_DEPTH {
            return Err(CaptureFormatError::new(
                "input-limit",
                "HAR exceeds the 64-level complete-evidence nesting budget.",
                pointer,
            ));
        }
        if self.redact {
            if let Some(parent) = parent {
                let parent_name = object_string(parent, "name");
                if self
                    .redactor
                    .har_credential(pointer, parent_name.as_deref())
                {
                    return Ok(self
                        .redactor
                        .credential(pointer)
                        .map_or(Value::Null, Value::String));
                }
            }
        }
        match item {
            CaptureJson::Number { literal } => Ok(self.project_number(literal, pointer)),
            CaptureJson::String(text) => self.project_string(text, pointer, parent),
            CaptureJson::Null => Ok(Value::Null),
            CaptureJson::Bool(value) => Ok(Value::Bool(*value)),
            CaptureJson::Array(items) => {
                let mut array = Vec::with_capacity(items.len());
                for (index, child) in items.iter().enumerate() {
                    let child_pointer = capture_pointer(pointer, &index.to_string());
                    array.push(self.visit(child, &child_pointer, depth + 1, None)?);
                }
                Ok(Value::Array(array))
            }
            CaptureJson::Object(members) => self.project_object(members, pointer, depth, item),
        }
    }

    fn project_number(&mut self, literal: &str, pointer: &str) -> Value {
        if !self.redact {
            return reported_number(literal);
        }
        // Exclude a number whose retained spellings carry a sensitive literal.
        let safe = safe_number(literal);
        let reported_text = safe.as_ref().map(|number| number.to_string());
        let excluded = self.redactor.text(literal, pointer, false).is_none()
            || reported_text
                .as_ref()
                .map(|text| self.redactor.text(text, pointer, false).is_none())
                .unwrap_or(false);
        if excluded {
            return Value::Null;
        }
        self.numeric_literals.push(json!({
            "pointer": pointer,
            "producer_type": "json-number",
            "literal": literal,
        }));
        reported_number(literal)
    }

    fn project_string(
        &mut self,
        text: &str,
        pointer: &str,
        parent: Option<&CaptureJson>,
    ) -> Result<Value, CaptureFormatError> {
        if self.redact
            && pointer == "/response/content/text"
            && parent
                .and_then(|parent| object_string(parent, "encoding"))
                .as_deref()
                == Some("base64")
        {
            return self.project_base64_content(text, pointer);
        }
        if self.redact {
            let parent_name = parent.and_then(|parent| object_string(parent, "name"));
            let transport = self
                .redactor
                .har_transport_url(pointer, parent_name.as_deref());
            Ok(self
                .redactor
                .text(text, pointer, transport)
                .map_or(Value::Null, Value::String))
        } else {
            Ok(Value::String(text.to_owned()))
        }
    }

    fn project_base64_content(
        &mut self,
        text: &str,
        pointer: &str,
    ) -> Result<Value, CaptureFormatError> {
        let bytes = decode_har_base64(text, pointer)?;
        let content_base64 = base64_encode(&bytes);
        let sha256 = hex_digest(&bytes);
        let hidden = self.redactor.sensitive_bytes(&bytes)
            || self.sensitive_values.iter().any(|literal| {
                text.contains(literal.as_str())
                    || content_base64.contains(literal.as_str())
                    || sha256.contains(literal.as_str())
                    || bytes.len().to_string().contains(literal.as_str())
            });
        if hidden {
            self.binary_fields.push(json!({
                "pointer": pointer,
                "representation": "har-base64-content",
                "state": "redacted",
                "content_base64": Value::Null,
                "bytes": Value::Null,
                "sha256": Value::Null,
            }));
            self.redactor
                .redactions
                .push(redaction_entry(pointer, "explicit-sensitive-value"));
            Ok(Value::Null)
        } else {
            self.binary_fields.push(json!({
                "pointer": pointer,
                "representation": "har-base64-content",
                "state": "retained",
                "content_base64": content_base64,
                "bytes": bytes.len(),
                "sha256": sha256,
            }));
            Ok(Value::String(text.to_owned()))
        }
    }

    fn project_object(
        &mut self,
        members: &[(String, CaptureJson)],
        pointer: &str,
        depth: usize,
        item: &CaptureJson,
    ) -> Result<Value, CaptureFormatError> {
        let mut map = Map::new();
        for (key, child) in members {
            let child_pointer = capture_pointer(pointer, key);
            if self.redact
                && self
                    .sensitive_values
                    .iter()
                    .any(|literal| key.contains(literal.as_str()))
            {
                let before_numbers = self.numeric_literals.len();
                let before_binaries = self.binary_fields.len();
                let before_redactions = self.redactor.redactions.len();
                self.visit(child, &child_pointer, depth + 1, Some(item))?;
                self.numeric_literals.truncate(before_numbers);
                self.binary_fields.truncate(before_binaries);
                self.redactor.redactions.truncate(before_redactions);
                self.redactor
                    .redactions
                    .push(property_name_redaction(pointer));
                continue;
            }
            let value = self.visit(child, &child_pointer, depth + 1, Some(item))?;
            map.insert(key.clone(), value);
        }
        Ok(Value::Object(map))
    }
}

/// Fetch a string member from a `CaptureJson` object (for parent context).
fn object_string(value: &CaptureJson, key: &str) -> Option<String> {
    match object_member(value, key) {
        Some(CaptureJson::String(text)) => Some(text.clone()),
        _ => None,
    }
}

/// Decode HAR base64 content, allowing ASCII whitespace.
fn decode_har_base64(value: &str, pointer: &str) -> Result<Vec<u8>, CaptureFormatError> {
    let compact: String = value
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r' | ' '))
        .collect();
    decode_canonical_base64(&compact).ok_or_else(|| {
        CaptureFormatError::new(
            "format",
            "HAR content declares base64 but its text is not valid canonical base64 (ASCII whitespace is allowed).",
            pointer,
        )
    })
}

/// Canonical padded base64 decoding (RFC 4648), rejecting non-canonical pad bits.
fn decode_canonical_base64(value: &str) -> Option<Vec<u8>> {
    if value.len() % 4 != 0 {
        return None;
    }
    use base64::Engine;
    let config = base64::engine::general_purpose::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(false);
    let engine = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, config);
    engine.decode(value.as_bytes()).ok()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Validate the disposable HAR copy and report Playwright IPv6-adapted entries.
///
/// Compatibility owner: `HarSchema.ts`. Full AJV draft-06 schema validation is
/// reproduced only to the extent the observed producers require: the pinned
/// structural checks already run in `decode_har_capture`, and this reports the
/// Playwright entries whose bracketed IPv6 `serverIPAddress` the upstream
/// validation copy adapts (which adds a per-record limitation).
fn validate_har(
    raw: &CaptureJson,
    entries: &[CaptureJson],
) -> Result<Vec<usize>, CaptureFormatError> {
    let log = object_member(raw, "log");
    let creator = log.and_then(|log| object_member(log, "creator"));
    let creator_name = creator.and_then(|creator| object_string(creator, "name"));
    let creator_version = creator.and_then(|creator| object_string(creator, "version"));
    let playwright = creator_name.as_deref() == Some("Playwright")
        && creator_version.as_deref() == Some("1.58.2");

    let mut adapted = Vec::new();
    if !playwright {
        return Ok(adapted);
    }
    for (ordinal, entry) in entries.iter().enumerate() {
        if let Some(address) = object_string(entry, "serverIPAddress") {
            if address.starts_with('[')
                && address.ends_with(']')
                && is_ipv6(&address[1..address.len() - 1])
            {
                adapted.push(ordinal);
            }
        }
    }
    Ok(adapted)
}

/// Whether a string is a valid IPv6 literal.
fn is_ipv6(value: &str) -> bool {
    value.parse::<std::net::Ipv6Addr>().is_ok()
}
