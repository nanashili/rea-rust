//! Opt-in template rules, parameter names and tool names for manifests.
//!
//! Compatibility owner: `src/domain/analysisView/environmentManifestRules.ts`.
//! Group identity in the original is object identity; here it is the index of
//! a group within the slice being merged.
use super::super::web_network::ordering::{compare, composite_key};
use super::super::web_network::routes::ROUTE_RULES;
use crate::common::json::js_len;
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

/// `TEMPLATE_RULES`.
pub const TEMPLATE_RULES: [&str; 3] = ["after-uid-literal", "opaque-token", "sibling-variance"];
/// `SIBLING_VARIANCE_SEGMENT_LIMIT`.
pub const SIBLING_VARIANCE_SEGMENT_LIMIT: usize = 32;
const TOOL_NAME_LIMIT: usize = 60;
const STOP_WORDS: [&str; 12] = [
    "search", "settings", "errors", "list", "members", "versions", "health", "merged", "usage",
    "checks", "dto", "markdown",
];
const DROPPED_NAME_LITERALS: [&str; 4] = ["api", "apis", "namespaces", "default"];

fn stop_word(value: &str) -> bool {
    STOP_WORDS.contains(&value)
}

/// `RoutePart`.
#[derive(Clone)]
pub enum Part {
    Literal(String),
    Param {
        rule: &'static str,
        values: BTreeSet<String>,
    },
}

impl Part {
    fn param(rule: &'static str, values: impl IntoIterator<Item = String>) -> Self {
        Part::Param {
            rule,
            values: values.into_iter().collect(),
        }
    }

    fn is_param(&self) -> bool {
        matches!(self, Part::Param { .. })
    }

    /// `partKey`.
    fn key(&self) -> Value {
        match self {
            Part::Literal(value) => json!(value),
            Part::Param { rule, .. } => json!(["param", rule]),
        }
    }
}

/// `ToolGroup`: one candidate tool on the primary origin.
#[derive(Clone)]
pub struct ToolGroup {
    pub method: String,
    pub origin: String,
    pub api_surface_template: String,
    pub parts: Vec<Part>,
    /// Record positions in admission order; the first is the earliest record.
    pub positions: Vec<usize>,
    pub statuses: Vec<f64>,
    pub content_types: BTreeSet<String>,
    pub query_names: BTreeSet<String>,
    pub body_shape: Option<Value>,
}

impl ToolGroup {
    fn with_parts(&self, parts: Vec<Part>) -> Self {
        Self {
            parts,
            ..self.clone()
        }
    }

    fn first_position(&self) -> f64 {
        self.positions
            .first()
            .map_or(f64::INFINITY, |position| *position as f64)
    }

    fn literal_at(&self, position: usize) -> &str {
        match self.parts.get(position) {
            Some(Part::Literal(value)) => value,
            _ => "",
        }
    }
}

/// `earliest`: index of the group with the earliest first record.
fn earliest(groups: &[&ToolGroup]) -> usize {
    let mut best = 0;
    for (index, group) in groups.iter().enumerate().skip(1) {
        if group.first_position() < groups[best].first_position() {
            best = index;
        }
    }
    best
}

/// `mergeGroups(groups, shape)`.
fn merge_groups(groups: &[&ToolGroup], shape: Option<&ToolGroup>) -> ToolGroup {
    if groups.len() == 1 {
        return groups[0].clone();
    }
    let primary = groups[earliest(groups)];
    let shape = shape.unwrap_or(primary);
    let parts = shape
        .parts
        .iter()
        .enumerate()
        .map(|(index, part)| match part {
            Part::Literal(_) => part.clone(),
            Part::Param { rule, .. } => Part::param(
                rule,
                groups
                    .iter()
                    .flat_map(|group| match group.parts.get(index) {
                        None => Vec::new(),
                        Some(Part::Param { values, .. }) => values.iter().cloned().collect(),
                        Some(Part::Literal(value)) => vec![value.clone()],
                    }),
            ),
        })
        .collect();
    let mut positions: Vec<usize> = groups
        .iter()
        .flat_map(|group| group.positions.iter().copied())
        .collect();
    positions.sort_unstable();
    let mut statuses: Vec<f64> = Vec::new();
    for status in groups
        .iter()
        .flat_map(|group| group.statuses.iter().copied())
    {
        if !statuses.contains(&status) {
            statuses.push(status);
        }
    }
    ToolGroup {
        method: primary.method.clone(),
        origin: primary.origin.clone(),
        api_surface_template: primary.api_surface_template.clone(),
        parts,
        positions,
        statuses,
        content_types: groups
            .iter()
            .flat_map(|group| group.content_types.iter().cloned())
            .collect(),
        query_names: groups
            .iter()
            .flat_map(|group| group.query_names.iter().cloned())
            .collect(),
        body_shape: primary.body_shape.clone(),
    }
}

/// Insertion-ordered buckets keyed by a composite key.
fn bucketed<T>(items: Vec<T>, key: impl Fn(&T) -> String) -> Vec<Vec<T>> {
    let mut buckets: Vec<Vec<T>> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for item in items {
        let item_key = key(&item);
        match index.get(&item_key) {
            Some(at) => buckets[*at].push(item),
            None => {
                index.insert(item_key, buckets.len());
                buckets.push(vec![item]);
            }
        }
    }
    buckets
}

/// `rebucket`.
fn rebucket(groups: Vec<ToolGroup>) -> Vec<ToolGroup> {
    bucketed(groups, |group| {
        let mut parts = vec![json!(group.method), json!(group.origin)];
        parts.extend(group.parts.iter().map(Part::key));
        composite_key(&parts)
    })
    .into_iter()
    .map(|bucket| merge_groups(&bucket.iter().collect::<Vec<_>>(), None))
    .collect()
}

/// `templateAfterUidLiteral`.
fn template_after_uid_literal(parts: &[Part]) -> Vec<Part> {
    parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            match (
                part,
                index
                    .checked_sub(1)
                    .and_then(|previous| parts.get(previous)),
            ) {
                (Part::Literal(value), Some(Part::Literal(previous)))
                    if previous == "uid" && !stop_word(value) =>
                {
                    Part::param("after-uid-literal", [value.clone()])
                }
                _ => part.clone(),
            }
        })
        .collect()
}

/// `^v\d`.
fn version_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.first() == Some(&b'v') && bytes.get(1).is_some_and(u8::is_ascii_digit)
}

/// `^(?=.*\d)(?=.*[a-z])[a-z0-9]{12,}$`.
fn opaque_token(value: &str) -> bool {
    value.len() >= 12
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().any(|byte| byte.is_ascii_digit())
        && value.bytes().any(|byte| byte.is_ascii_lowercase())
}

/// `templateOpaqueTokens`.
fn template_opaque_tokens(parts: &[Part]) -> Vec<Part> {
    parts
        .iter()
        .map(|part| match part {
            Part::Literal(value) if opaque_token(value) && !version_token(value) => {
                Part::param("opaque-token", [value.clone()])
            }
            _ => part.clone(),
        })
        .collect()
}

/// `identifierLikeSiblings`: indexes into `literal`, in the original Set order.
fn identifier_like_siblings(literal: &[&ToolGroup], position: usize) -> Vec<usize> {
    let mut eligible: Vec<usize> = Vec::new();
    let previous = literal.first().and_then(|group| {
        position
            .checked_sub(1)
            .and_then(|previous| group.parts.get(previous))
    });
    let plural = matches!(previous, Some(Part::Literal(value)) if value.ends_with('s'));
    let mut hyphenated = Vec::new();
    for (index, group) in literal.iter().enumerate() {
        let value = group.literal_at(position);
        if stop_word(value) {
            continue;
        }
        if value.contains(|character: char| character.is_ascii_digit() || character == ':') {
            eligible.push(index);
        }
        if plural && value.contains('-') {
            hyphenated.push(index);
        }
    }
    if hyphenated.len() >= 3 {
        for index in hyphenated {
            if !eligible.contains(&index) {
                eligible.push(index);
            }
        }
    }
    eligible
}

fn opt_in_param_at(group: &ToolGroup, position: usize) -> bool {
    matches!(group.parts.get(position), Some(Part::Param { rule, .. }) if TEMPLATE_RULES.contains(rule))
}

/// `mergeLiteralSiblings`.
fn merge_literal_siblings(literal: &[&ToolGroup], position: usize) -> Vec<ToolGroup> {
    let eligible = identifier_like_siblings(literal, position);
    if eligible.len() < 2 {
        return literal.iter().map(|group| (*group).clone()).collect();
    }
    let groups: Vec<&ToolGroup> = eligible.iter().map(|index| literal[*index]).collect();
    let first = earliest(&groups);
    let shape = groups[first].with_parts(
        groups[first]
            .parts
            .iter()
            .enumerate()
            .map(|(index, part)| {
                if index == position {
                    Part::param(
                        "sibling-variance",
                        [groups[first].literal_at(position).to_owned()],
                    )
                } else {
                    part.clone()
                }
            })
            .collect(),
    );
    let members: Vec<&ToolGroup> = groups
        .iter()
        .enumerate()
        .map(|(index, group)| if index == first { &shape } else { *group })
        .collect();
    let mut output = vec![merge_groups(&members, Some(&shape))];
    output.extend(
        literal
            .iter()
            .enumerate()
            .filter(|(index, _)| !eligible.contains(index))
            .map(|(_, group)| (*group).clone()),
    );
    output
}

/// `mergeSiblings`.
fn merge_siblings(bucket: Vec<ToolGroup>, position: usize) -> Vec<ToolGroup> {
    if bucket.len() < 2 {
        return bucket;
    }
    let templated: Vec<&ToolGroup> = bucket
        .iter()
        .filter(|group| group.parts.get(position).is_some_and(Part::is_param))
        .collect();
    let literal: Vec<&ToolGroup> = bucket
        .iter()
        .filter(|group| matches!(group.parts.get(position), Some(Part::Literal(_))))
        .collect();
    let targets: Vec<&ToolGroup> = templated
        .iter()
        .copied()
        .filter(|group| opt_in_param_at(group, position))
        .collect();
    if targets.is_empty() {
        let mut output: Vec<ToolGroup> = templated.iter().map(|group| (*group).clone()).collect();
        output.extend(merge_literal_siblings(&literal, position));
        return output;
    }
    let target = targets[earliest(&targets)];
    let foldable: Vec<usize> = literal
        .iter()
        .enumerate()
        .filter(|(_, group)| !stop_word(group.literal_at(position)))
        .map(|(index, _)| index)
        .collect();
    let mut members = vec![target];
    members.extend(foldable.iter().map(|index| literal[*index]));
    let mut output = vec![merge_groups(&members, Some(target))];
    output.extend(
        templated
            .iter()
            .filter(|group| !std::ptr::eq(**group, target))
            .map(|group| (*group).clone()),
    );
    output.extend(
        literal
            .iter()
            .enumerate()
            .filter(|(index, _)| !foldable.contains(index))
            .map(|(_, group)| (*group).clone()),
    );
    output
}

/// `mergeSiblingVariance`.
fn merge_sibling_variance(groups: Vec<ToolGroup>) -> Vec<ToolGroup> {
    let (mut current, beyond_limit): (Vec<ToolGroup>, Vec<ToolGroup>) = groups
        .into_iter()
        .partition(|group| group.parts.len() <= SIBLING_VARIANCE_SEGMENT_LIMIT);
    let longest = current
        .iter()
        .map(|group| group.parts.len())
        .max()
        .unwrap_or(0);
    for position in 2..longest {
        let mut output = Vec::new();
        let mut eligible = Vec::new();
        for group in current {
            if position >= group.parts.len() {
                output.push(group);
            } else {
                eligible.push(group);
            }
        }
        for bucket in bucketed(eligible, |group| {
            let mut parts = vec![
                json!(group.method),
                json!(group.origin),
                json!(group.parts.len()),
            ];
            parts.extend(group.parts.iter().enumerate().map(|(index, part)| {
                if index == position {
                    Value::Null
                } else {
                    part.key()
                }
            }));
            composite_key(&parts)
        }) {
            output.extend(merge_siblings(bucket, position));
        }
        current = output;
    }
    current.extend(beyond_limit);
    current
}

/// `applyTemplateRules`: the selected opt-in rules in fixed order.
pub fn apply_template_rules(groups: Vec<ToolGroup>, rules: &HashSet<String>) -> Vec<ToolGroup> {
    let mut current = groups;
    if rules.contains("after-uid-literal") {
        current = current
            .iter()
            .map(|group| group.with_parts(template_after_uid_literal(&group.parts)))
            .collect();
    }
    if rules.contains("opaque-token") {
        current = current
            .iter()
            .map(|group| group.with_parts(template_opaque_tokens(&group.parts)))
            .collect();
    }
    current = rebucket(current);
    if rules.contains("sibling-variance") {
        current = merge_sibling_variance(current);
    }
    current
}

/// `sanitizeToken`.
fn sanitize_token(text: &str) -> String {
    let lower = text.to_lowercase();
    let mut output = String::new();
    let mut underscore = false;
    for character in lower.chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            output.push(character);
            underscore = false;
        } else if !underscore {
            output.push('_');
            underscore = true;
        }
    }
    let output = output.strip_prefix('_').unwrap_or(&output);
    output.strip_suffix('_').unwrap_or(output).to_owned()
}

/// `singular`.
fn singular(word: &str) -> String {
    if word.ends_with("ies") && js_len(word) > 3 {
        return format!("{}y", &word[..word.len() - 3]);
    }
    if word.ends_with('s') && !word.ends_with("ss") {
        return word[..word.len() - 1].to_owned();
    }
    word.to_owned()
}

fn param_base_name(parts: &[Part], index: usize) -> String {
    let Some(Part::Param { rule, .. }) = parts.get(index) else {
        return String::new();
    };
    match *rule {
        "numeric" => "id".into(),
        "uuid" => "uuid".into(),
        "hex" => "hash".into(),
        "iso-date" => "date".into(),
        "after-uid-literal" | "opaque-token" => "uid".into(),
        _ => {
            let stem = match index
                .checked_sub(1)
                .and_then(|previous| parts.get(previous))
            {
                Some(Part::Literal(previous)) => sanitize_token(&singular(previous)),
                _ => String::new(),
            };
            if stem.is_empty() {
                "id".into()
            } else {
                format!("{stem}_id")
            }
        }
    }
}

/// `parameterNames`: names in segment order with numeric suffixes for repeats.
pub fn parameter_names(parts: &[Part]) -> Vec<String> {
    let mut used: HashMap<String, usize> = HashMap::new();
    let mut names = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if !part.is_param() {
            continue;
        }
        let base = param_base_name(parts, index);
        let count = used.get(&base).copied().unwrap_or(0);
        used.insert(base.clone(), count + 1);
        names.push(if count == 0 {
            base
        } else {
            format!("{base}_{}", count + 1)
        });
    }
    names
}

/// `pathTemplate`.
pub fn path_template(parts: &[Part], names: &[String]) -> String {
    let mut next = 0;
    let rendered: Vec<String> = parts
        .iter()
        .map(|part| match part {
            Part::Literal(value) => value.clone(),
            Part::Param { rule, .. } => {
                let name = names.get(next).cloned().unwrap_or_default();
                next += 1;
                if ROUTE_RULES.contains(rule) {
                    format!("{{{rule}}}")
                } else {
                    format!("{{{name}}}")
                }
            }
        })
        .collect();
    format!("/{}", rendered.join("/"))
}

/// `ToolNameRegistry`.
#[derive(Default)]
pub struct ToolNameRegistry {
    used: HashSet<String>,
    next_suffix: HashMap<String, usize>,
}

/// `text.slice(0, limit).replace(/_+$/u, "")` over ASCII tool names.
fn truncate(text: &str, limit: usize) -> String {
    let units: Vec<u16> = text.encode_utf16().take(limit).collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('_')
        .to_owned()
}

/// `toolName`: deterministic and unique within a manifest.
pub fn tool_name(
    method: &str,
    parts: &[Part],
    names: &[String],
    registry: &mut ToolNameRegistry,
) -> String {
    let mut words = vec![method.to_lowercase()];
    for (index, part) in parts.iter().enumerate() {
        let Part::Literal(value) = part else {
            continue;
        };
        if value.is_empty()
            || DROPPED_NAME_LITERALS.contains(&value.as_str())
            || version_token(value)
            || (value == "uid" && parts.get(index + 1).is_some_and(Part::is_param))
        {
            continue;
        }
        words.push(value.split('.').next().unwrap_or_default().to_owned());
    }
    if !names.is_empty() {
        words.push("by".into());
        words.extend(names.iter().cloned());
    }
    let mut base = sanitize_token(&words.join("_"));
    if base.is_empty() {
        base = "tool".into();
    }
    let mut candidate = truncate(&base, TOOL_NAME_LIMIT);
    if registry.used.contains(&candidate) {
        let mut suffix = 2usize;
        loop {
            let tail = format!("_{suffix}");
            let prefix = truncate(&base, TOOL_NAME_LIMIT - tail.len());
            let namespace = composite_key(&[json!(prefix), json!(tail.len())]);
            let next = registry
                .next_suffix
                .get(&namespace)
                .copied()
                .unwrap_or(suffix);
            if next > suffix {
                suffix = next;
                continue;
            }
            candidate = format!("{prefix}{tail}");
            registry.next_suffix.insert(namespace, suffix + 1);
            if !registry.used.contains(&candidate) {
                break;
            }
            suffix += 1;
        }
    }
    registry.used.insert(candidate.clone());
    candidate
}

/// `compareTools`: template, then method.
pub fn compare_tools(left: (&str, &str), right: (&str, &str)) -> Ordering {
    compare(left.0, right.0).then_with(|| compare(left.1, right.1))
}
