//! Bounded projection for installed sigrok decoder discovery.
//!
//! The provider adapter owns process execution and executable identity.  This
//! module owns the strict request shape, the 0.7.2 text grammar, paging, and
//! the resulting typed facts.  It deliberately accepts producer output rather
//! than invoking a decoder so callers can keep execution and Evidence
//! ownership at the provider boundary.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_signal_decoders";
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_LINE_SEPARATORS: usize = 65_536;
const DEFAULT_LIMIT: u64 = 50;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    #[serde(default)]
    pub decoder: Option<String>,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_limit")]
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    pub configured_path: String,
    pub path: String,
    pub sha256: String,
    pub version_banner: String,
    pub version_diagnostics: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimiter {
    pub configured_path: String,
    pub path: String,
    pub sha256: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub command_timeout_ms: u64,
    pub address_space_bytes: u64,
    pub file_bytes: u64,
    pub cpu_seconds: u64,
}

/// Facts captured by the process owner after its command has completed.
/// Unknown values stay absent instead of being guessed from paths or banners.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryMetadata {
    pub diagnostics: String,
    pub tool: ToolIdentity,
    pub resource_limiter: ResourceLimiter,
    pub limits: Limits,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Decoder {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelpLine {
    pub line_number: u64,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutputWindow {
    pub unit: String,
    pub examined: u64,
    pub matching: u64,
    pub returned: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Report {
    pub selection: Selection,
    pub decoders: Vec<Decoder>,
    pub help_lines: Vec<HelpLine>,
    pub output_window: OutputWindow,
    pub diagnostics: String,
    pub tool: ToolIdentity,
    pub resource_limiter: ResourceLimiter,
    pub limits: Limits,
    pub hardware_acquisition: String,
}

/// Parse a completed sigrok discovery response and return its normalized JSON.
/// The text is treated as producer-owned evidence; help lines are retained
/// literally and decoder names are never interpreted as schemas.
pub fn inspect(input: &Value, stdout: &str, metadata: DiscoveryMetadata) -> Result<Value, Failure> {
    let selection = parse_selection(input)?;
    let report = parse_output(selection, stdout, metadata)?;
    serde_json::to_value(report)
        .map_err(|error| invalid(&format!("discovery report is not serializable: {error}")))
}

/// Validate only the caller-selected request, for adapters that perform
/// process setup separately.
pub fn validate_input(input: &Value) -> Result<Selection, Failure> {
    parse_selection(input)
}

fn parse_selection(input: &Value) -> Result<Selection, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("inspect_signal_decoders input must be an object"))?;
    let selection: Selection = serde_json::from_value(Value::Object(object.clone()))
        .map_err(|error| invalid(&format!("invalid decoder discovery input: {error}")))?;

    if let Some(decoder) = &selection.decoder {
        if decoder.is_empty()
            || decoder.len() > 256
            || !decoder
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-'))
        {
            return Err(invalid("decoder must be a 1-256 character decoder ID"));
        }
    }
    if selection.query.encode_utf16().count() > 8192 {
        return Err(invalid("query must be at most 8192 characters"));
    }
    if selection.offset > MAX_SAFE_INTEGER {
        return Err(invalid("offset must be at most Number.MAX_SAFE_INTEGER"));
    }
    let invalid_limit = selection
        .limit
        .is_some_and(|limit| limit == 0 || limit > MAX_SAFE_INTEGER);
    if invalid_limit {
        return Err(invalid(
            "limit must be a positive integer at most Number.MAX_SAFE_INTEGER or null",
        ));
    }
    Ok(selection)
}

fn parse_output(
    selection: Selection,
    stdout: &str,
    metadata: DiscoveryMetadata,
) -> Result<Report, Failure> {
    if stdout.len() > MAX_OUTPUT_BYTES {
        return Err(resource(
            "producer output exceeds the 4 MiB discovery limit",
        ));
    }

    let lines = split_lines(stdout)?;
    let query = selection.query.to_lowercase();
    let catalog = selection.decoder.is_none();
    let (decoders, help_lines) = if catalog {
        (parse_catalog(&lines)?, Vec::new())
    } else {
        let expected = format!("ID: {}", selection.decoder.as_deref().unwrap_or_default());
        if lines.first().map(String::as_str) != Some(expected.as_str()) {
            return Err(invalid(
                "decoder help does not identify the selected decoder",
            ));
        }
        (
            Vec::new(),
            lines
                .iter()
                .enumerate()
                .map(|(index, text)| HelpLine {
                    line_number: index as u64 + 1,
                    text: text.clone(),
                })
                .collect(),
        )
    };

    if catalog && decoders.is_empty() {
        return Err(invalid("sigrok returned an empty decoder catalog"));
    }

    let matching = if catalog {
        decoders
            .iter()
            .filter(|decoder| {
                format!("{} {}", decoder.id, decoder.name)
                    .to_lowercase()
                    .contains(&query)
            })
            .count() as u64
    } else {
        help_lines
            .iter()
            .filter(|line| line.text.to_lowercase().contains(&query))
            .count() as u64
    };
    let examined = if catalog {
        decoders.len()
    } else {
        help_lines.len()
    } as u64;
    let start = selection.offset.min(matching);
    let remaining = matching.saturating_sub(start);
    let count = selection.limit.unwrap_or(remaining).min(remaining);
    let end = start.saturating_add(count);

    let paged_decoders = if catalog {
        decoders
            .into_iter()
            .filter(|decoder| {
                format!("{} {}", decoder.id, decoder.name)
                    .to_lowercase()
                    .contains(&query)
            })
            .skip(start as usize)
            .take(count as usize)
            .collect()
    } else {
        Vec::new()
    };
    let paged_help = if catalog {
        Vec::new()
    } else {
        help_lines
            .into_iter()
            .filter(|line| line.text.to_lowercase().contains(&query))
            .skip(start as usize)
            .take(count as usize)
            .collect()
    };

    Ok(Report {
        selection,
        decoders: paged_decoders,
        help_lines: paged_help,
        output_window: OutputWindow {
            unit: if catalog {
                "decoders".to_owned()
            } else {
                "help-lines".to_owned()
            },
            examined,
            matching,
            returned: count,
            has_more: end < matching,
        },
        diagnostics: metadata.diagnostics,
        tool: metadata.tool,
        resource_limiter: metadata.resource_limiter,
        limits: metadata.limits,
        hardware_acquisition: "not-performed".to_owned(),
    })
}

fn split_lines(stdout: &str) -> Result<Vec<String>, Failure> {
    let separators = stdout.bytes().filter(|byte| *byte == b'\n').count();
    if separators >= MAX_LINE_SEPARATORS {
        return Err(resource(
            "decoder discovery exceeds the 65,536-line representation budget",
        ));
    }

    let raw_lines = stdout.split('\n').collect::<Vec<_>>();
    let last_index = raw_lines.len().saturating_sub(1);
    let mut lines = raw_lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            // JavaScript's /\r?\n/ consumes CR only when it belongs to a
            // line separator. A terminal lone CR remains producer text.
            if index < last_index {
                line.strip_suffix('\r').unwrap_or(line).to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    Ok(lines)
}

fn parse_catalog(lines: &[String]) -> Result<Vec<Decoder>, Failure> {
    let heading = lines
        .iter()
        .position(|line| line == "Supported protocol decoders:")
        .ok_or_else(|| invalid("sigrok decoder catalog heading is missing"))?;
    let mut seen = BTreeMap::new();
    let mut decoders = Vec::new();
    for line in lines.iter().skip(heading + 1) {
        if line.is_empty() {
            continue;
        }
        let trimmed = line
            .strip_prefix("  ")
            .ok_or_else(|| invalid("malformed sigrok decoder catalog record"))?;
        let (id, name) = trimmed
            .split_once(' ')
            .filter(|(id, name)| !id.is_empty() && !name.trim_start().is_empty())
            .ok_or_else(|| invalid("malformed sigrok decoder catalog record"))?;
        let valid_id = id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-'));
        if !valid_id || seen.insert(id, ()).is_some() {
            return Err(invalid(
                "malformed or duplicate sigrok decoder catalog record",
            ));
        }
        decoders.push(Decoder {
            id: id.to_owned(),
            name: name.trim_start().to_owned(),
        });
    }
    Ok(decoders)
}

fn default_limit() -> Option<u64> {
    Some(DEFAULT_LIMIT)
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.to_owned(),
        true,
        "Correct the request and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(message: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        message.to_owned(),
        false,
        "Reduce the producer output or selected scope and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            (
                "maximum_output_bytes",
                Detail::Count(MAX_OUTPUT_BYTES as u64),
            ),
        ]),
    )
}
