//! Captured-text normalization under caller-selected rules.
//!
//! Compatibility owner: `ProcessNormalization.ts`. Stages run in the
//! original order (paths, ports, PIDs, literal patterns), each bounded by
//! the remaining byte budget so an over-budget intermediate is never kept.
//!
//! The original regular expressions use look-around, which the `regex`
//! crate does not support; each matcher below is the look-around-free part
//! followed by the explicit boundary check. Backtracking cannot rescue a
//! failed boundary for these patterns (a shorter port or endpoint is always
//! followed by a digit or `:`), so rejecting the greedy candidate and
//! resuming at the next character is equivalent.

use super::scenario::Scenario;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::OnceLock;

/// `BoundedProcessTextNormalization`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bounded {
    Normalized(String),
    OverBudget,
}

/// One stage result (`BoundedStageResult`).
enum Stage {
    Bounded(String),
    Unchanged,
    OverBudget,
}

/// Capture-local normalizer with the selected path aliases.
pub struct Normalizer {
    paths: Option<(Regex, HashMap<String, String>)>,
    ports: bool,
    pids: bool,
    patterns: Vec<(String, String)>,
}

fn endpoint_matcher() -> &'static Regex {
    static MATCHER: OnceLock<Regex> = OnceLock::new();
    MATCHER.get_or_init(|| {
        Regex::new(
            r#"(?i)((?-u:\b)[a-z][a-z0-9+.\-]*://[^\s\x{FEFF}/?#"'<>]+|(?-u:\b)localhost|(?-u:\b)(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\[[0-9a-f:.%]+\]):([0-9]{1,5})"#,
        )
        .expect("valid endpoint matcher")
    })
}

fn field_matcher() -> &'static Regex {
    static MATCHER: OnceLock<Regex> = OnceLock::new();
    MATCHER.get_or_init(|| {
        Regex::new(r#"(?i)((?-u:\b)(?:port|tcp_port|udp_port|listen)(?-u:\b)["']?[\s\x{FEFF}]*[:=][\s\x{FEFF}]*)([0-9]{1,5})"#)
            .expect("valid field matcher")
    })
}

fn continues_word(character: char) -> bool {
    character.is_alphabetic() || character.is_numeric() || character == '_'
}

/// The negative look-ahead after a port: `(?![\p{L}\p{N}_<extra>]|\.(?:[\p{L}\p{N}_]|$))`.
fn port_boundary(rest: &str, extra: &[char]) -> bool {
    let mut characters = rest.chars();
    match characters.next() {
        None => true,
        Some(character) if continues_word(character) || extra.contains(&character) => false,
        // A period that ends the chunk may continue in the next chunk.
        Some('.') => characters.next().is_some_and(|next| !continues_word(next)),
        Some(_) => true,
    }
}

/// Node `net.isIP(...) !== 0`.
fn is_ip(text: &str) -> bool {
    let octet = |part: &str| {
        !part.is_empty()
            && part.len() <= 3
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
            && part.parse::<u16>().is_ok_and(|value| value <= 255)
    };
    let parts: Vec<_> = text.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|part| octet(part)) {
        return true;
    }
    let (address, zone) = match text.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (text, None),
    };
    if zone.is_some_and(|zone| zone.is_empty() || !zone.chars().all(|c| c.is_ascii_alphanumeric() || "-.:".contains(c))) {
        return false;
    }
    address.parse::<Ipv6Addr>().is_ok()
}

const SPECIAL_SCHEMES: [&str; 6] = ["http", "https", "ws", "wss", "ftp", "file"];

/// `URL.canParse(endpoint + ":" + port)` for the endpoint shapes the matcher admits.
fn url_can_parse(endpoint: &str, port: &str) -> bool {
    let Some((scheme, rest)) = endpoint.split_once("://") else {
        return false;
    };
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    let hostport = format!("{authority}:{port}");
    let (host, port_text) = if let Some(bracketed) = hostport.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some((address, tail)) if address.parse::<Ipv6Addr>().is_ok() => (address.to_owned(), tail.strip_prefix(':').unwrap_or("x").to_owned()),
            _ => return false,
        }
    } else {
        match hostport.split_once(':') {
            Some((host, port)) => (host.to_owned(), port.to_owned()),
            None => return false,
        }
    };
    let port_ok = port_text.is_empty() || (port_text.bytes().all(|byte| byte.is_ascii_digit()) && port_text.parse::<u32>().is_ok_and(|port| port <= 65_535));
    if !port_ok {
        return false;
    }
    if SPECIAL_SCHEMES.contains(&scheme.as_str()) {
        if scheme == "file" {
            return false;
        }
        !host.is_empty() && !host.chars().any(|c| " #%/:<>?@[\\]^|".contains(c) || c.is_control())
    } else {
        !host.chars().any(|c| " #/:<>?@[\\]^|".contains(c) || c.is_control())
    }
}

/// Replace every boundary-respecting match; returns the text and whether
/// any replacement differed from its match.
fn replace_ports(value: &str, matcher: &Regex, extra: &[char], replace: impl Fn(&str, &str, &str) -> String) -> (String, bool) {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    let mut start = 0;
    let mut changed = false;
    while start <= value.len() {
        let Some(captures) = matcher.captures_at(value, start) else {
            break;
        };
        let whole = captures.get(0).expect("match");
        let rest = &value[whole.end()..];
        if !port_boundary(rest, extra) {
            // Resume after the first character of the failed candidate.
            start = whole.start() + value[whole.start()..].chars().next().map_or(1, char::len_utf8);
            continue;
        }
        let replacement = replace(whole.as_str(), &captures[1], &captures[2]);
        changed |= replacement != whole.as_str();
        output.push_str(&value[cursor..whole.start()]);
        output.push_str(&replacement);
        cursor = whole.end();
        start = if whole.end() == whole.start() { whole.end() + 1 } else { whole.end() };
    }
    output.push_str(&value[cursor..]);
    (output, changed)
}

fn endpoint_replacement(whole: &str, endpoint: &str, port: &str) -> String {
    if port.parse::<u32>().unwrap_or(u32::MAX) > 65_535 {
        return whole.to_owned();
    }
    let is_endpoint = if endpoint.contains("://") {
        url_can_parse(endpoint, port)
    } else {
        endpoint.eq_ignore_ascii_case("localhost") || is_ip(endpoint.trim_start_matches('[').trim_end_matches(']'))
    };
    if is_endpoint { format!("{endpoint}:<port>") } else { whole.to_owned() }
}

fn field_replacement(whole: &str, prefix: &str, port: &str) -> String {
    if port.parse::<u32>().unwrap_or(u32::MAX) <= 65_535 {
        format!("{prefix}<port>")
    } else {
        whole.to_owned()
    }
}

/// Replace each maximal ASCII digit run equal to one token
/// (`(?<!\d)(?:tokens)(?!\d)`).
fn replace_pid_tokens(value: &str, tokens: &[String]) -> (String, bool) {
    if tokens.is_empty() {
        return (value.to_owned(), false);
    }
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut changed = false;
    let mut index = 0;
    let mut cursor = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if tokens.iter().any(|token| token.as_str() == &value[start..index]) {
                output.push_str(&value[cursor..start]);
                output.push_str("<pid>");
                cursor = index;
                changed = true;
            }
        } else {
            index += 1;
        }
    }
    output.push_str(&value[cursor..]);
    (output, changed)
}

fn pid_tokens(identifiers: &[i64]) -> Vec<String> {
    let mut tokens: Vec<i64> = identifiers.iter().copied().filter(|identifier| *identifier > 0).collect();
    tokens.sort_unstable_by(|left, right| right.cmp(left));
    tokens.dedup();
    tokens.into_iter().map(|token| token.to_string()).collect()
}

/// `boundedLiteralReplace` / `String.prototype.replaceAll(literal)`.
fn replace_literal(value: &str, pattern: &str, replacement: &str) -> Option<String> {
    if pattern.is_empty() {
        if replacement.is_empty() {
            return None;
        }
        // JavaScript inserts between UTF-16 units; Rust strings hold scalar
        // values, so astral characters are not split.
        let mut output = String::from(replacement);
        for character in value.chars() {
            output.push(character);
            output.push_str(replacement);
        }
        return Some(output);
    }
    if pattern == replacement || !value.contains(pattern) {
        return None;
    }
    Some(value.replace(pattern, replacement))
}

fn bounded(result: (String, bool), max_bytes: u64) -> Stage {
    let (value, changed) = result;
    if (value.len() as u64) > max_bytes {
        return if changed { Stage::OverBudget } else { Stage::Unchanged };
    }
    if changed { Stage::Bounded(value) } else { Stage::Unchanged }
}

impl Normalizer {
    /// `createBoundedProcessTextNormalizer` / `createProcessTextNormalizer`.
    pub fn new(scenario: &Scenario, temporary_root: &str) -> Self {
        let paths = scenario.normalize_paths.then(|| {
            let mut aliases: Vec<(String, String)> = Vec::new();
            let mut selected = vec![
                (temporary_root.to_owned(), "<temporary-root>".to_owned()),
                (scenario.working_directory.clone(), "<working-directory>".to_owned()),
                (scenario.executable.clone(), "<executable>".to_owned()),
            ];
            for (index, root) in scenario.filesystem_observation_paths.iter().enumerate() {
                selected.push((root.clone(), format!("<filesystem-root-{index}>")));
            }
            for (path, alias) in selected {
                if !path.is_empty() && !aliases.iter().any(|(existing, _)| *existing == path) {
                    aliases.push((path, alias));
                }
            }
            // Longest original path first; the sort is stable like Array#sort.
            // JavaScript compares UTF-16 lengths.
            aliases.sort_by_key(|(path, _)| std::cmp::Reverse(path.encode_utf16().count()));
            let pattern = aliases.iter().map(|(path, _)| regex::escape(path)).collect::<Vec<_>>().join("|");
            (Regex::new(&pattern).expect("escaped literal alternation"), aliases.into_iter().collect())
        });
        Self {
            paths,
            ports: scenario.normalize_ports,
            pids: scenario.normalize_pids,
            patterns: scenario.patterns.iter().map(|pattern| (pattern.pattern.clone(), pattern.replacement.clone())).collect(),
        }
    }

    fn replace_paths(&self, value: &str) -> (String, bool) {
        let Some((matcher, aliases)) = &self.paths else {
            return (value.to_owned(), false);
        };
        let mut changed = false;
        let output = matcher
            .replace_all(value, |captures: &regex::Captures<'_>| {
                let matched = &captures[0];
                let alias = aliases.get(matched).cloned().unwrap_or_else(|| matched.to_owned());
                changed |= alias != matched;
                alias
            })
            .into_owned();
        (output, changed)
    }

    fn replace_ports_all(value: &str) -> (String, bool) {
        let (endpoint, first) = replace_ports(value, endpoint_matcher(), &['@', ':'], endpoint_replacement);
        let (field, second) = replace_ports(&endpoint, field_matcher(), &[], field_replacement);
        (field, first || second)
    }

    /// Bounded normalization of one payload with the live root PID.
    pub fn bounded(&self, value: &str, max_bytes: u64, root_pid: i64) -> Bounded {
        let mut normalized = value.to_owned();
        let apply = |stage: Stage, normalized: &mut String| match stage {
            Stage::OverBudget => false,
            Stage::Bounded(value) => {
                *normalized = value;
                true
            }
            Stage::Unchanged => true,
        };
        if self.paths.is_some() && !apply(bounded(self.replace_paths(&normalized), max_bytes), &mut normalized) {
            return Bounded::OverBudget;
        }
        if self.ports {
            let (endpoint, changed) = replace_ports(&normalized, endpoint_matcher(), &['@', ':'], endpoint_replacement);
            if !apply(bounded((endpoint, changed), max_bytes), &mut normalized) {
                return Bounded::OverBudget;
            }
            let (field, changed) = replace_ports(&normalized, field_matcher(), &[], field_replacement);
            if !apply(bounded((field, changed), max_bytes), &mut normalized) {
                return Bounded::OverBudget;
            }
        }
        if self.pids && root_pid > 0 && !apply(bounded(replace_pid_tokens(&normalized, &pid_tokens(&[root_pid])), max_bytes), &mut normalized) {
            return Bounded::OverBudget;
        }
        for (pattern, replacement) in &self.patterns {
            if let Some(replaced) = replace_literal(&normalized, pattern, replacement) {
                if replaced.len() as u64 > max_bytes {
                    return Bounded::OverBudget;
                }
                normalized = replaced;
            }
        }
        if normalized.len() as u64 <= max_bytes { Bounded::Normalized(normalized) } else { Bounded::OverBudget }
    }

    /// Unbounded normalization (`createProcessTextNormalizer`).
    pub fn text(&self, value: &str, root_pid: i64) -> String {
        let mut normalized = self.replace_paths(value).0;
        if self.ports {
            normalized = Self::replace_ports_all(&normalized).0;
        }
        if self.pids {
            normalized = replace_pid_tokens(&normalized, &pid_tokens(&[root_pid])).0;
        }
        for (pattern, replacement) in &self.patterns {
            if let Some(replaced) = replace_literal(&normalized, pattern, replacement) {
                normalized = replaced;
            }
        }
        normalized
    }
}

/// `normalizeProcessElapsedTime`.
pub fn bucket(elapsed_ms: u64, bucket_ms: u64) -> u64 {
    elapsed_ms / bucket_ms * bucket_ms
}

/// One raw process sample before normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSample {
    pub at_ms: u64,
    pub pid: i64,
    pub parent_pid: i64,
    pub command: String,
    pub process_group_id: Option<i64>,
    pub session_id: Option<i64>,
}

/// JavaScript `String.prototype.trim`.
fn js_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}')
}

/// `normalizeProcessSamples`.
pub fn normalize_samples(samples: &[RawSample], scenario: &Scenario, root_pid: i64) -> Vec<Value> {
    let mut identifiers = vec![root_pid];
    for sample in samples {
        identifiers.extend([sample.pid, sample.parent_pid, sample.process_group_id.unwrap_or(0), sample.session_id.unwrap_or(0)]);
    }
    let mut mapping: HashMap<i64, i64> = HashMap::new();
    for identifier in &identifiers {
        if *identifier > 0 && !mapping.contains_key(identifier) {
            let next = mapping.len() as i64 + 1;
            mapping.insert(*identifier, next);
        }
    }
    let normalizer = Normalizer::new(scenario, "<no-temporary-root>");
    let sample_tokens = pid_tokens(&identifiers);
    let pids = scenario.normalize_pids;
    let map = |identifier: i64, fallback: i64| mapping.get(&identifier).copied().unwrap_or(fallback);
    samples
        .iter()
        .map(|sample| {
            let mut command = normalizer.text(&sample.command, root_pid);
            if pids {
                command = replace_pid_tokens(&command, &sample_tokens).0;
            }
            json!({
                "at_ms": bucket(sample.at_ms, scenario.time_bucket_ms),
                "pid": if pids { map(sample.pid, 1) } else { sample.pid },
                "parent_pid": if pids { map(sample.parent_pid, 0) } else { sample.parent_pid },
                "process_group_id": match sample.process_group_id { Some(id) if pids => json!(map(id, 0)), other => json!(other) },
                "session_id": match sample.session_id { Some(id) if pids => json!(map(id, 0)), other => json!(other) },
                "command": js_trim(&command),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::scenario::Scenario;

    fn scenario(normalization: Value) -> Scenario {
        Scenario::from_input(&json!({
            "executable": "/bin/sh", "arguments": [], "working_directory": "/private/tmp", "environment": {},
            "filesystem_observation_paths": ["/private/tmp/data"], "terminal": {"columns": 80, "rows": 24, "scrollback": 1000},
            "events": [], "timeout_ms": 30000, "idle_timeout_ms": 30000, "settle_ms": 100, "finalization_ms": 0,
            "limits": {"output_bytes": 1000000, "files": 10000, "file_bytes": 10000000, "processes": 1000, "filesystem_depth": 16},
            "normalization": normalization,
        }))
    }

    #[test]
    fn normalizes_like_the_oracle_capture() {
        let scenario = scenario(json!({"paths": true, "pids": true, "ports": true, "time_bucket_ms": 10, "patterns": [{"pattern": "SECRET-TOKEN", "replacement": "<tok>"}]}));
        let normalizer = Normalizer::new(&scenario, "/var/folders/x/rea-process-1");
        let raw = "pid=53032 port=8080 http://localhost:3000/x 127.0.0.1:22 SECRET-TOKEN\r\n/private/tmp\r\n";
        assert_eq!(
            normalizer.bounded(raw, 1_000_000, 53032),
            Bounded::Normalized("pid=<pid> port=<port> http://localhost:<port>/x 127.0.0.1:<port> <tok>\r\n<working-directory>\r\n".to_owned())
        );
        // The longest selected path wins at one position.
        assert_eq!(normalizer.text("/private/tmp/data/a", -1), "<filesystem-root-0>/a");
    }

    #[test]
    fn port_boundaries_follow_the_lookahead() {
        let scenario = scenario(json!({"paths": false, "pids": false, "ports": true, "time_bucket_ms": 10, "patterns": []}));
        let normalizer = Normalizer::new(&scenario, "");
        assert_eq!(normalizer.text("v1.2.3.4:80 10.0.0.1:443. 10.0.0.1:443.5 10.0.0.1:443.", -1), "v1.2.3.4:80 10.0.0.1:<port>. 10.0.0.1:443.5 10.0.0.1:443.");
        assert_eq!(normalizer.text("localhost:80a localhost:80.x localhost:99999", -1), "localhost:80a localhost:80.x localhost:99999");
        assert_eq!(normalizer.text("[::1]:8080 listen = 22", -1), "[::1]:<port> listen = <port>");
        assert_eq!(normalizer.text("localhost:80.", -1), "localhost:80.");
    }

    #[test]
    fn pid_tokens_match_whole_digit_runs_only() {
        assert_eq!(replace_pid_tokens("1234 12345 a1234b 91234", &pid_tokens(&[1234])).0, "<pid> 12345 a<pid>b 91234");
    }

    #[test]
    fn bounded_stages_reject_over_budget_intermediates() {
        let scenario = scenario(json!({"paths": false, "pids": false, "ports": false, "time_bucket_ms": 10, "patterns": [{"pattern": "a", "replacement": "aaaa"}]}));
        let normalizer = Normalizer::new(&scenario, "");
        assert_eq!(normalizer.bounded("aa", 5, -1), Bounded::OverBudget);
        assert_eq!(normalizer.bounded("bb", 2, -1), Bounded::Normalized("bb".to_owned()));
        assert_eq!(normalizer.bounded("bbb", 2, -1), Bounded::OverBudget);
    }
}
