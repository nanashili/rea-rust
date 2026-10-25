//! Resolved secret values kept only for one in-memory scenario session.
//!
//! Compatibility owner: `src/browser/BrowserScenarioSecrets.ts`. Lengths that
//! feed allocation estimates are UTF-16 code units, matching the JavaScript
//! owner; substring searches are byte searches over UTF-8, which select the
//! same matches because every pattern is itself valid UTF-8.
use super::input::{Scenario, ScenarioUrl, ScenarioValue};
use crate::cdp::urls;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use url::form_urlencoded;

const REDACTION_PREFIX: &str = "[REDACTED:";

#[derive(Clone)]
struct Pattern {
    text: String,
    search: String,
    percent_insensitive: bool,
}

#[derive(Clone)]
struct Replacement {
    id: String,
    pattern: Pattern,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Spellings {
    Url,
    Text,
}

fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

/// `encodeURIComponent`.
pub(crate) fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn normalize_percent(value: &str) -> String {
    if !value.contains('%') {
        return value.to_owned();
    }
    String::from_utf8(normalize_percent_bytes(value.as_bytes()))
        .unwrap_or_else(|_| value.to_owned())
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn normalize_percent_bytes(value: &[u8]) -> Vec<u8> {
    let mut normalized = value.to_vec();
    let mut index = 0;
    while index + 2 < normalized.len() {
        if normalized[index] == b'%'
            && is_hex(normalized[index + 1])
            && is_hex(normalized[index + 2])
        {
            normalized[index + 1] = normalized[index + 1].to_ascii_lowercase();
            normalized[index + 2] = normalized[index + 2].to_ascii_lowercase();
            index += 2;
        }
        index += 1;
    }
    normalized
}

fn patterns_for(secret: &str, spellings: Spellings) -> Vec<Pattern> {
    if secret.is_empty() {
        return Vec::new();
    }
    let mut patterns = vec![Pattern {
        text: secret.to_owned(),
        search: secret.to_owned(),
        percent_insensitive: false,
    }];
    let mut encoded = Vec::new();
    for text in [
        encode_uri_component(secret),
        form_urlencoded::byte_serialize(secret.as_bytes()).collect::<String>(),
    ] {
        if !encoded.contains(&text) {
            encoded.push(text);
        }
    }
    for text in encoded {
        patterns.push(Pattern {
            search: normalize_percent(&text),
            text,
            percent_insensitive: true,
        });
    }
    if spellings == Spellings::Text {
        let json = serde_json::to_string(secret).unwrap_or_default();
        let inner = json[1..json.len().saturating_sub(1).max(1)].to_owned();
        patterns.push(Pattern {
            text: inner.clone(),
            search: inner,
            percent_insensitive: false,
        });
    }
    let mut seen = BTreeSet::new();
    patterns
        .into_iter()
        .filter(|pattern| {
            !pattern.text.is_empty()
                && seen.insert(format!(
                    "{}:{}",
                    if pattern.percent_insensitive {
                        "percent"
                    } else {
                        "literal"
                    },
                    pattern.text
                ))
        })
        .collect()
}

fn declared_patterns(values: &[(String, String)], spellings: Spellings) -> Vec<Pattern> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .flat_map(|(_, secret)| patterns_for(secret, spellings))
        .filter(|pattern| {
            seen.insert(format!(
                "{}:{}",
                if pattern.percent_insensitive {
                    "percent"
                } else {
                    "literal"
                },
                pattern.text
            ))
        })
        .collect()
}

fn replacements_for(values: &[(String, String)], spellings: Spellings) -> Vec<Replacement> {
    let mut replacements: Vec<Replacement> = values
        .iter()
        .flat_map(|(id, secret)| {
            patterns_for(secret, spellings)
                .into_iter()
                .map(|pattern| Replacement {
                    id: id.clone(),
                    pattern,
                })
        })
        .collect();
    // Array.prototype.sort is stable, like `sort_by`.
    replacements.sort_by(|left, right| {
        utf16_len(&right.pattern.text)
            .cmp(&utf16_len(&left.pattern.text))
            .then_with(|| left.id.cmp(&right.id))
    });
    replacements
}

fn pattern_matches(value: &str, normalized: &str, pattern: &Pattern) -> bool {
    if pattern.percent_insensitive {
        normalized
    } else {
        value
    }
    .contains(&pattern.search)
}

fn contains_pattern(value: &str, normalized: &str, patterns: &[Pattern]) -> bool {
    patterns
        .iter()
        .any(|pattern| pattern_matches(value, normalized, pattern))
}

fn redaction_marker(id: &str, patterns: &[Pattern]) -> String {
    let first = format!("{REDACTION_PREFIX}{id}]");
    [first.as_str(), "[REDACTED]", "…", ""]
        .into_iter()
        .find(|candidate| {
            let normalized = normalize_percent(candidate);
            patterns
                .iter()
                .all(|pattern| !pattern_matches(candidate, &normalized, pattern))
        })
        .unwrap_or("")
        .to_owned()
}

fn find_from(haystack: &[u8], needle: &[u8], offset: usize) -> Option<usize> {
    if needle.is_empty() {
        return (offset <= haystack.len()).then_some(offset);
    }
    if offset > haystack.len() || needle.len() > haystack.len() {
        return None;
    }
    haystack[offset..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| position + offset)
}

fn replace_literals(value: &str, replacements: &[Replacement], patterns: &[Pattern]) -> String {
    let normalized = if replacements
        .iter()
        .any(|item| item.pattern.percent_insensitive)
    {
        normalize_percent(value)
    } else {
        value.to_owned()
    };
    let mut parts = String::new();
    let mut replaced = false;
    let mut offset = 0;
    while offset < value.len() {
        let mut next: Option<(&Replacement, usize)> = None;
        for replacement in replacements {
            let view = if replacement.pattern.percent_insensitive {
                normalized.as_bytes()
            } else {
                value.as_bytes()
            };
            if let Some(index) = find_from(view, replacement.pattern.search.as_bytes(), offset) {
                let better = match next {
                    None => true,
                    Some((current, current_index)) => {
                        index < current_index
                            || (index == current_index
                                && utf16_len(&replacement.pattern.text)
                                    > utf16_len(&current.pattern.text))
                    }
                };
                if better {
                    next = Some((replacement, index));
                }
            }
        }
        let Some((replacement, index)) = next else {
            break;
        };
        parts.push_str(&value[offset..index]);
        parts.push_str(&redaction_marker(&replacement.id, patterns));
        replaced = true;
        offset = index + replacement.pattern.text.len();
    }
    if !replaced {
        return value.to_owned();
    }
    parts.push_str(&value[offset.min(value.len())..]);
    parts
}

/// Declared secrets of one scenario, resolved from the caller environment.
#[derive(Clone)]
pub(crate) struct Secrets {
    values: BTreeMap<String, String>,
    url_patterns: Vec<Pattern>,
    text_patterns: Vec<Pattern>,
    url_replacements: Vec<Replacement>,
    text_replacements: Vec<Replacement>,
    cost_per_character: f64,
}

impl Secrets {
    pub(crate) fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// `BrowserScenarioSecrets.resolve`: `None` when any declared variable is unset.
    pub(crate) fn resolve(
        scenario: &Scenario,
        environment: &BTreeMap<String, String>,
    ) -> Option<Self> {
        let mut ordered = Vec::new();
        for declaration in &scenario.secrets {
            let value = environment.get(&declaration.environment_variable)?;
            ordered.push((declaration.secret_id.clone(), value.clone()));
        }
        Some(Self::new(ordered))
    }

    fn new(ordered: Vec<(String, String)>) -> Self {
        let url_patterns = declared_patterns(&ordered, Spellings::Url);
        let text_patterns = declared_patterns(&ordered, Spellings::Text);
        let url_replacements = replacements_for(&ordered, Spellings::Url);
        let text_replacements = replacements_for(&ordered, Spellings::Text);
        let mut cost_per_character: f64 = 8.0;
        for (replacements, patterns) in [
            (&text_replacements, &text_patterns),
            (&url_replacements, &url_patterns),
        ] {
            for replacement in replacements {
                let marker = redaction_marker(&replacement.id, patterns);
                cost_per_character = cost_per_character.max(
                    8.0 + (marker.len() as f64 * 8.0 + 128.0)
                        / utf16_len(&replacement.pattern.text) as f64,
                );
            }
        }
        Self {
            values: ordered.into_iter().collect(),
            url_patterns,
            text_patterns,
            url_replacements,
            text_replacements,
            cost_per_character,
        }
    }

    pub(crate) fn value(&self, source: &ScenarioValue) -> String {
        match source {
            ScenarioValue::Literal(value) => value.clone(),
            ScenarioValue::Secret(id) => self.values.get(id).cloned().unwrap_or_default(),
        }
    }

    /// `url(destination)`: append declared query entries with URLSearchParams.
    pub(crate) fn url(&self, destination: &ScenarioUrl) -> String {
        let Ok(mut url) = url::Url::parse(&destination.url) else {
            return destination.url.clone();
        };
        if !destination.query.is_empty() {
            // URLSearchParams re-serializes the whole query on append.
            let existing: Vec<(String, String)> = url
                .query_pairs()
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect();
            let mut serializer = form_urlencoded::Serializer::new(String::new());
            for (name, value) in &existing {
                serializer.append_pair(name, value);
            }
            for (name, value) in &destination.query {
                serializer.append_pair(name, &self.value(value));
            }
            url.set_query(Some(&serializer.finish()));
        }
        url.as_str().to_owned()
    }

    pub(crate) fn redaction_allocation_cost(&self, length: usize) -> usize {
        (length as f64 * self.cost_per_character).ceil() as usize
    }

    /// UTF-16 based cost of one string.
    pub(crate) fn redaction_cost_of(&self, value: &str) -> usize {
        self.redaction_allocation_cost(utf16_len(value))
    }

    pub(crate) fn redact(&self, value: &str) -> String {
        if self.text_patterns.is_empty() {
            return value.to_owned();
        }
        let output = replace_literals(value, &self.text_replacements, &self.text_patterns);
        if contains_pattern(&output, &normalize_percent(&output), &self.text_patterns) {
            String::new()
        } else {
            output
        }
    }

    /// Replace declared UTF-8, URI/form and JSON-escaped spellings in bytes.
    pub(crate) fn redact_bytes(&self, value: &[u8]) -> Vec<u8> {
        if self.text_patterns.is_empty() {
            return value.to_vec();
        }
        let percent = self
            .text_replacements
            .iter()
            .any(|item| item.pattern.percent_insensitive);
        let normalized = if percent && value.contains(&b'%') {
            normalize_percent_bytes(value)
        } else {
            value.to_vec()
        };
        let mut candidates: Vec<(&Replacement, Vec<u8>, Option<usize>)> = self
            .text_replacements
            .iter()
            .map(|replacement| {
                let view = if replacement.pattern.percent_insensitive {
                    &normalized[..]
                } else {
                    value
                };
                let marker = redaction_marker(&replacement.id, &self.text_patterns).into_bytes();
                let index = find_from(view, replacement.pattern.search.as_bytes(), 0);
                (replacement, marker, index)
            })
            .collect();
        candidates.sort_by(|left, right| {
            right
                .0
                .pattern
                .search
                .len()
                .cmp(&left.0.pattern.search.len())
                .then_with(|| left.0.id.cmp(&right.0.id))
        });
        let mut parts: Vec<u8> = Vec::new();
        let mut replaced = false;
        let mut offset = 0;
        loop {
            let mut next: Option<usize> = None;
            for candidate in &mut candidates {
                if let Some(index) = candidate.2
                    && index < offset
                {
                    let view = if candidate.0.pattern.percent_insensitive {
                        &normalized[..]
                    } else {
                        value
                    };
                    candidate.2 = find_from(view, candidate.0.pattern.search.as_bytes(), offset);
                }
            }
            for (position, candidate) in candidates.iter().enumerate() {
                let Some(index) = candidate.2 else { continue };
                next = match next {
                    None => Some(position),
                    Some(current) => {
                        let current_index = candidates[current].2.unwrap_or(usize::MAX);
                        if index < current_index
                            || (index == current_index
                                && candidate.0.pattern.search.len()
                                    > candidates[current].0.pattern.search.len())
                        {
                            Some(position)
                        } else {
                            Some(current)
                        }
                    }
                };
            }
            let Some(position) = next else { break };
            let index = candidates[position].2.unwrap_or(offset);
            parts.extend_from_slice(&value[offset..index]);
            parts.extend_from_slice(&candidates[position].1);
            replaced = true;
            offset = index + candidates[position].0.pattern.search.len();
        }
        if !replaced {
            return value.to_vec();
        }
        parts.extend_from_slice(&value[offset.min(value.len())..]);
        let normalized_redacted = if percent && parts.contains(&b'%') {
            normalize_percent_bytes(&parts)
        } else {
            parts.clone()
        };
        let leaked = candidates.iter().any(|candidate| {
            let view = if candidate.0.pattern.percent_insensitive {
                &normalized_redacted[..]
            } else {
                &parts[..]
            };
            find_from(view, candidate.0.pattern.search.as_bytes(), 0).is_some()
        });
        if leaked { Vec::new() } else { parts }
    }

    /// `sanitizeUrl`: remove declared secrets from one URL and report it.
    pub(crate) fn sanitize_url(&self, value: &str) -> Value {
        if self.url_patterns.is_empty() {
            return sanitized_url_value(value, false);
        }
        let output = replace_literals(value, &self.url_replacements, &self.url_patterns);
        if contains_pattern(&output, &normalize_percent(&output), &self.url_patterns) {
            return json!({ "url": "", "origin": null, "query_parameter_names": [], "redacted": true });
        }
        sanitized_url_value(&output, output != value)
    }

    pub(crate) fn fingerprint(&self, value: &str) -> Value {
        if !self.text_patterns.is_empty()
            && contains_pattern(value, &normalize_percent(value), &self.text_patterns)
        {
            return json!({ "value_state": "redacted-secret", "value_sha256": null });
        }
        json!({ "value_state": "hashed", "value_sha256": sha256_hex(value.as_bytes()) })
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// WHATWG form-query names of `url.search`, preserving order and repeats.
fn query_names(url: &url::Url) -> Vec<Value> {
    url.query()
        .map(|query| {
            form_urlencoded::parse(query.as_bytes())
                .map(|(name, _)| Value::String(name.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

/// `sanitizeBrowserUrl` with the scenario's extra redaction flag.
pub(crate) fn sanitized_url_value(value: &str, redacted_by_secret: bool) -> Value {
    let Some(parsed) = urls::parse(value) else {
        return json!({ "url": value, "origin": null, "query_parameter_names": [], "redacted": redacted_by_secret });
    };
    let sanitized = urls::sanitize_browser_url(value);
    let had_credentials =
        !parsed.username().is_empty() || parsed.password().is_some_and(|p| !p.is_empty());
    json!({
        "url": sanitized.url,
        "origin": sanitized.origin,
        "query_parameter_names": query_names(&parsed),
        "redacted": had_credentials || redacted_by_secret,
    })
}
