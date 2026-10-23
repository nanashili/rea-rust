//! Read-only projection of caller-captured Apktool launcher evidence.
//!
//! Process creation and command ownership belong to the caller. This module
//! parses a captured `--version` response and preserves launcher identity.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_apktool_client";
pub const COMMAND_ENV: &str = "REA_APKTOOL_COMMAND";
const VERSION_OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ClientInspection {
    pub client: ClientIdentity,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ClientIdentity {
    pub command: String,
    pub command_source: CommandSource,
    pub apktool_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSelection {
    pub command: String,
    pub command_source: CommandSource,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedVersionOutput {
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CommandSource {
    Environment,
    Path,
}

/// Project a caller-selected launcher and its already-captured version output.
pub fn inspect(
    selection: CommandSelection,
    output: CapturedVersionOutput,
) -> Result<ClientInspection, Failure> {
    ensure_captured_output_is_bounded(&selection, &output)?;

    let version = parse_version(&output.stdout)
        .ok_or_else(|| version_unresolved_failure(&selection, &output))?;
    ensure_supported_version(&selection, &version)?;

    Ok(ClientInspection {
        client: ClientIdentity {
            command: selection.command,
            command_source: selection.command_source,
            apktool_version: Some(version),
        },
    })
}

fn ensure_captured_output_is_bounded(
    selection: &CommandSelection,
    output: &CapturedVersionOutput,
) -> Result<(), Failure> {
    let stdout_bytes = output.stdout.len();
    let stderr_bytes = output.stderr.len();
    let captured_bytes = stdout_bytes.saturating_add(stderr_bytes);
    if captured_bytes <= VERSION_OUTPUT_LIMIT {
        return Ok(());
    }

    let mut details = selection_details(selection);
    details.insert("limit_bytes", Detail::Count(VERSION_OUTPUT_LIMIT as u64));
    details.insert("captured_bytes", Detail::Count(captured_bytes as u64));
    details.insert("stdout_bytes", Detail::Count(stdout_bytes as u64));
    details.insert("stderr_bytes", Detail::Count(stderr_bytes as u64));
    Err(Failure::new(
        "resource_limit",
        "resource",
        "The captured Apktool version output exceeds the 64 KiB limit".into(),
        false,
        "Provide bounded Apktool --version output and retry.".into(),
        details,
    ))
}

/// Parse the first non-empty line from a captured version response.
pub fn parse_version(output: &str) -> Option<String> {
    if output.len() > VERSION_OUTPUT_LIMIT {
        return None;
    }

    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .filter(|line| looks_like_version(line))
        .map(ToOwned::to_owned)
}

fn looks_like_version(value: &str) -> bool {
    let candidate = value.strip_prefix('v').unwrap_or(value);
    let numeric = candidate.split(['-', '+']).next().unwrap_or_default();
    let parts = numeric.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
        })
}

fn ensure_supported_version(selection: &CommandSelection, version: &str) -> Result<(), Failure> {
    let candidate = version.strip_prefix('v').unwrap_or(version);
    let numeric = candidate.split(['-', '+']).next().unwrap_or_default();
    let mut parts = numeric
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    if (major, minor, patch) >= (2, 7, 0) {
        return Ok(());
    }

    let mut details = selection_details(selection);
    details.insert("reported_version", Detail::Text(version.into()));
    details.insert("minimum_version", Detail::Text("2.7.0".into()));
    Err(Failure::new(
        "unsupported_version",
        "unsupported_version",
        format!("The selected Apktool version {version} is older than the supported minimum 2.7.0"),
        false,
        "Use Apktool 2.7.0 or newer; see docs/apktool-resource-analysis.md.".into(),
        details,
    ))
}

fn version_unresolved_failure(
    selection: &CommandSelection,
    output: &CapturedVersionOutput,
) -> Failure {
    let reported_version = output
        .stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty());
    let mut details = selection_details(selection);
    details.insert("version_probe", Detail::Text("unrecognized_output".into()));
    details.insert(
        "reported_version",
        reported_version.map_or_else(
            || Detail::Text("".into()),
            |version| Detail::Text(version.into()),
        ),
    );
    Failure::new(
        "version_unresolved",
        "version_unresolved",
        "The selected Apktool launcher exited successfully but did not report a recognizable version".into(),
        false,
        "Use an Apktool launcher that reports a semantic version from --version.".into(),
        details,
    )
}

fn selection_details(selection: &CommandSelection) -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([
        ("operation", Detail::Text(OPERATION.into())),
        ("command", Detail::Text(selection.command.clone())),
        (
            "command_source",
            Detail::Text(command_source_name(&selection.command_source).into()),
        ),
    ])
}

fn command_source_name(source: &CommandSource) -> &'static str {
    match source {
        CommandSource::Environment => "environment",
        CommandSource::Path => "path",
    }
}
