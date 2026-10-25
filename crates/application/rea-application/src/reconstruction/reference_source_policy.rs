//! Canonical, root-scoped source import policy.
//!
//! The TypeScript importer uses the `ignore` package for its root `.gitignore`,
//! default exclusions, caller exclusions, and configured secret patterns. This
//! module keeps that interpretation in one native owner so traversal does not
//! reimplement ad-hoc prefix or wildcard checks.

use rea_core::cancellation::Cancellation;
use rea_host::fs::stable_directory::DirectoryEntryKind;
use serde_json::Value;

use super::reference_source_reader::{MAX_SOURCE_FILE_BYTES, SourceTreeReader};

pub const DEFAULT_IGNORES: &[&str] = &[
    ".git/",
    ".git/hooks/",
    "node_modules/",
    "dist/",
    "build/",
    "coverage/",
    "htmlcov/",
    ".coverage",
    "*.log",
];

#[derive(Clone, Debug)]
struct Pattern {
    text: String,
    negated: bool,
    directory_only: bool,
    anchored: bool,
    parts: Vec<String>,
}

#[derive(Clone, Debug)]
struct Rule {
    pattern: Pattern,
    reason: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct SourceImportPolicy {
    rules: Vec<Rule>,
    secrets: Vec<Pattern>,
}

impl SourceImportPolicy {
    /// Return the last matching rule for a root-relative path.
    pub fn match_path(&self, path: &str, kind: DirectoryEntryKind) -> Option<(&str, &'static str)> {
        let is_directory = kind == DirectoryEntryKind::Directory;
        if let Some(pattern) =
            last_match(&self.secrets, path, is_directory).filter(|pattern| !pattern.negated)
        {
            return Some((pattern.text.as_str(), "configured-secret"));
        }
        self.rules
            .iter()
            .rev()
            .find(|rule| pattern_matches(&rule.pattern, path, is_directory))
            .and_then(|rule| {
                (!rule.pattern.negated).then_some((rule.pattern.text.as_str(), rule.reason))
            })
    }

    pub fn excludes(&self, path: &str, kind: DirectoryEntryKind) -> bool {
        self.match_path(path, kind).is_some_and(|(_, reason)| {
            reason == "configured-secret"
                || reason == "project-ignored"
                || reason == "default-ignored"
                || reason == "caller-excluded"
        })
    }
}

/// Build policy without pathname reads. The root `.gitignore` is admitted and
/// read through the same stable directory handle as the source inventory.
pub fn build(
    reader: &SourceTreeReader,
    input: &Value,
    cancellation: &Cancellation,
) -> Result<SourceImportPolicy, String> {
    ensure_active(cancellation)?;
    let object = input
        .as_object()
        .ok_or_else(|| "input must be an object".to_owned())?;
    let mut policy = SourceImportPolicy::default();

    if let Some(policy_value) = object.get("policy") {
        let policy_object = policy_value
            .as_object()
            .ok_or_else(|| "policy must be an object".to_owned())?;
        let patterns = first_string_array(policy_object, &["secretPatterns", "secret_patterns"])?;
        for pattern in patterns {
            if let Some(parsed) = parse_pattern(pattern)? {
                policy.secrets.push(parsed);
            }
        }
    }

    let root_entry = reader
        .inspect_entry(".gitignore", cancellation)
        .map_err(|error| format!("could not inspect source ignore policy: {error}"))?;
    if let Some(entry) = root_entry {
        if entry.kind != DirectoryEntryKind::Regular {
            return Err("source .gitignore is not a regular file".to_owned());
        }
        let text = reader
            .read_entry_bounded(&entry, cancellation)
            .map_err(|error| format!("could not read source .gitignore: {error}"))?;
        if text.len() > MAX_SOURCE_FILE_BYTES {
            return Err("source .gitignore exceeds the bounded policy read limit".to_owned());
        }
        let text = std::str::from_utf8(&text)
            .map_err(|_| "source .gitignore is not valid UTF-8".to_owned())?;
        for line in text.lines() {
            if let Some(pattern) = parse_pattern(line)? {
                policy.rules.push(Rule {
                    pattern,
                    reason: "project-ignored",
                });
            }
        }
    }
    for pattern in DEFAULT_IGNORES {
        add_rule(&mut policy.rules, pattern, "default-ignored")?;
    }
    for pattern in first_string_array(object, &["excludePaths", "exclude_paths"])? {
        add_rule(&mut policy.rules, pattern, "caller-excluded")?;
        if !pattern.ends_with('/') {
            add_rule(&mut policy.rules, &format!("{pattern}/"), "caller-excluded")?;
        }
    }
    Ok(policy)
}

fn first_string_array<'a>(
    object: &'a serde_json::Map<String, Value>,
    names: &[&str],
) -> Result<Vec<&'a str>, String> {
    let Some(value) = names.iter().find_map(|name| object.get(*name)) else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| format!("{} must be an array", names[0]))?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .ok_or_else(|| format!("{}[{index}] must be a string", names[0]))
        })
        .collect()
}

fn add_rule(rules: &mut Vec<Rule>, text: &str, reason: &'static str) -> Result<(), String> {
    if let Some(pattern) = parse_pattern(text)? {
        rules.push(Rule { pattern, reason });
    }
    Ok(())
}

fn parse_pattern(line: &str) -> Result<Option<Pattern>, String> {
    let mut text = line.trim_end_matches(['\r', '\n']).to_owned();
    if text.is_empty() || text.starts_with('#') {
        return Ok(None);
    }
    let source_text = text.clone();
    if text.starts_with('\\') && text.get(1..2) == Some("#") {
        text.remove(0);
    }
    let negated = text.starts_with('!') && !text.starts_with("\\!");
    if negated {
        text.remove(0);
    } else if text.starts_with("\\!") {
        text.remove(0);
    }
    let directory_only = text.ends_with('/') && text != "/";
    if directory_only {
        text.pop();
    }
    while text.starts_with("./") {
        text.drain(..2);
    }
    if text.is_empty() {
        return Ok(None);
    }
    let anchored = text.starts_with('/') || text.contains('/');
    let text = text.trim_start_matches('/').to_owned();
    let parts = text.split('/').map(str::to_owned).collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(format!("invalid empty source policy pattern: {line}"));
    }
    Ok(Some(Pattern {
        text: source_text,
        negated,
        directory_only,
        anchored,
        parts,
    }))
}

fn last_match<'a>(patterns: &'a [Pattern], path: &str, is_directory: bool) -> Option<&'a Pattern> {
    patterns
        .iter()
        .rev()
        .find(|pattern| pattern_matches(pattern, path, is_directory))
}

fn pattern_matches(pattern: &Pattern, path: &str, is_directory: bool) -> bool {
    if pattern.directory_only && !is_directory {
        return false;
    }
    let components = path.split('/').collect::<Vec<_>>();
    if pattern.anchored {
        return components_match(&pattern.parts, &components);
    }
    components
        .iter()
        .enumerate()
        .any(|(index, _)| components_match(&pattern.parts, &components[index..]))
}

fn components_match(pattern: &[String], path: &[&str]) -> bool {
    let mut current = vec![false; path.len() + 1];
    current[0] = true;
    for component_pattern in pattern {
        let mut next = vec![false; path.len() + 1];
        if component_pattern == "**" {
            for (index, matched) in current.iter().copied().enumerate() {
                if matched {
                    next[index] = true;
                }
            }
            for index in 0..path.len() {
                if next[index] {
                    next[index + 1] = true;
                }
            }
        } else {
            for index in 0..path.len() {
                if current[index] && glob_match(component_pattern, path[index]) {
                    next[index + 1] = true;
                }
            }
        }
        current = next;
    }
    current[path.len()]
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.encode_utf16().collect::<Vec<_>>();
    let value = value.encode_utf16().collect::<Vec<_>>();
    let mut current = vec![false; pattern.len() + 1];
    current[0] = true;
    epsilon_closure(&pattern, &mut current);
    for character in &value {
        let mut next = vec![false; pattern.len() + 1];
        for index in 0..pattern.len() {
            if !current[index] {
                continue;
            }
            if pattern[index] == u16::from(b'*') {
                next[index] = true;
            } else if pattern[index] == u16::from(b'\\') {
                if index + 1 < pattern.len() && pattern[index + 1] == *character {
                    next[index + 2] = true;
                } else if index + 1 == pattern.len() && *character == u16::from(b'\\') {
                    next[index + 1] = true;
                }
            } else if pattern[index] == u16::from(b'?') && *character != u16::from(b'/') {
                next[index + 1] = true;
            } else if pattern[index] == u16::from(b'[') {
                if let Some((end, matched)) = character_class(&pattern[index..], *character) {
                    if matched {
                        next[index + end] = true;
                    }
                } else if *character == u16::from(b'[') {
                    next[index + 1] = true;
                }
            } else if pattern[index] == *character {
                next[index + 1] = true;
            }
        }
        epsilon_closure(&pattern, &mut next);
        current = next;
    }
    current[pattern.len()]
}

fn epsilon_closure(pattern: &[u16], states: &mut [bool]) {
    for index in 0..pattern.len() {
        if states[index] && pattern[index] == u16::from(b'*') {
            states[index + 1] = true;
        }
    }
}

fn character_class(pattern: &[u16], value: u16) -> Option<(usize, bool)> {
    let mut index = 1;
    let negated = pattern
        .get(index)
        .is_some_and(|character| *character == u16::from(b'!'))
        || pattern
            .get(index)
            .is_some_and(|character| *character == u16::from(b'^'));
    if negated {
        index += 1;
    }
    let mut matched = false;
    while index < pattern.len() {
        if pattern[index] == u16::from(b']') {
            index += 1;
            return Some((index, if negated { !matched } else { matched }));
        }
        let first = if pattern[index] == u16::from(b'\\') && index + 1 < pattern.len() {
            index += 1;
            pattern[index]
        } else {
            pattern[index]
        };
        index += 1;
        if index + 1 < pattern.len()
            && pattern[index] == u16::from(b'-')
            && pattern[index + 1] != u16::from(b']')
        {
            index += 1;
            let last = if pattern[index] == u16::from(b'\\') && index + 1 < pattern.len() {
                index += 1;
                pattern[index]
            } else {
                pattern[index]
            };
            index += 1;
            matched |= first <= value && value <= last;
        } else {
            matched |= first == value;
        }
    }
    None
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), String> {
    cancellation.reason().map_or(Ok(()), |reason| {
        Err(format!("operation cancelled: {reason}"))
    })
}

#[cfg(test)]
mod tests {
    use super::{Pattern, Rule, SourceImportPolicy, parse_pattern, pattern_matches};
    use rea_host::fs::stable_directory::DirectoryEntryKind;

    fn rule(line: &str, reason: &'static str) -> Rule {
        Rule {
            pattern: parse_pattern(line).unwrap().unwrap(),
            reason,
        }
    }

    #[test]
    fn later_caller_rule_overrides_default_rule() {
        let policy = SourceImportPolicy {
            rules: vec![
                rule("*.log", "default-ignored"),
                rule("!keep.log", "caller-excluded"),
            ],
            secrets: Vec::new(),
        };
        assert!(!policy.excludes("keep.log", DirectoryEntryKind::Regular));
        assert!(policy.excludes("other.log", DirectoryEntryKind::Regular));
    }

    #[test]
    fn escaped_wildcard_is_literal() {
        let pattern = parse_pattern(r"\*.log").unwrap().unwrap();
        assert!(pattern_matches(&pattern, "*.log", false));
        assert!(!pattern_matches(&pattern, "error.log", false));
    }

    #[test]
    fn unclosed_character_class_is_literal() {
        let pattern = parse_pattern("file[").unwrap().unwrap();
        assert!(pattern_matches(&pattern, "file[", false));
        assert!(!pattern_matches(&pattern, "filea", false));
    }

    #[test]
    fn wildcard_and_class_match_utf16_source_names() {
        let wildcard = parse_pattern("?.ts").unwrap().unwrap();
        let class = parse_pattern("[é].ts").unwrap().unwrap();
        assert!(pattern_matches(&wildcard, "é.ts", false));
        assert!(pattern_matches(&class, "é.ts", false));
        assert!(!pattern_matches(&class, "e.ts", false));
    }

    #[test]
    fn double_star_matches_nested_components() {
        let pattern = parse_pattern("cache/**/debug.log").unwrap().unwrap();
        assert!(pattern_matches(&pattern, "cache/debug.log", false));
        assert!(pattern_matches(&pattern, "cache/a/b/debug.log", false));
        assert!(!pattern_matches(&pattern, "cache/a/debug.txt", false));
    }

    #[test]
    fn negating_child_does_not_resurrect_pruned_parent() {
        let policy = SourceImportPolicy {
            rules: vec![
                rule("vendor/", "project-ignored"),
                rule("!vendor/keep.rs", "project-ignored"),
            ],
            secrets: Vec::new(),
        };
        assert!(policy.excludes("vendor", DirectoryEntryKind::Directory));
        assert!(!policy.excludes("vendor/keep.rs", DirectoryEntryKind::Regular));
    }

    #[test]
    fn unclosed_escape_remains_literal() {
        let pattern = Pattern {
            text: "name\\".to_owned(),
            negated: false,
            directory_only: false,
            anchored: false,
            parts: vec!["name\\".to_owned()],
        };
        assert!(pattern_matches(&pattern, "name\\", false));
    }
}
