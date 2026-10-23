//! Offline projection of a captured `adb shell ps -A` response.
//!
//! The host adapter owns ADB execution and device selection.  This module only
//! parses the bounded output supplied by that adapter, retaining row order and
//! making incomplete coverage explicit.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_adb_processes";
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_UNPARSED_LINES: usize = 10;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub serial: String,
}

/// Captured command output supplied by the host adapter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeOutput {
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessEntry {
    pub user: String,
    pub pid: u64,
    pub ppid: Option<u64>,
    pub rss: Option<u64>,
    pub state: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessList {
    pub client: Value,
    pub serial: String,
    pub columns: Option<String>,
    pub processes: Vec<ProcessEntry>,
    pub unparsed_lines: Vec<String>,
    pub coverage: &'static str,
}

/// Parse a captured process listing while preserving its source order.
pub fn list(
    client: Value,
    selection: Selection,
    output: ProbeOutput,
) -> Result<ProcessList, Failure> {
    validate_selection(&selection)?;
    validate_output_size(&output)?;

    let parsed = parse_process_list(&output.stdout);
    let coverage = if output.truncated || parsed.unparsed_count > 0 {
        "partial"
    } else {
        "complete"
    };

    Ok(ProcessList {
        client,
        serial: selection.serial,
        columns: parsed.columns,
        processes: parsed.processes,
        unparsed_lines: parsed
            .unparsed_lines
            .into_iter()
            .take(MAX_UNPARSED_LINES)
            .collect(),
        coverage,
    })
}

/// Parse adapter-shaped JSON containing client identity, device selection, and
/// already-captured output.  No ADB process is spawned by this function.
pub fn list_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("ADB process input must be an object"))?;
    let client = object
        .get("client")
        .cloned()
        .ok_or_else(|| invalid("ADB client identity is required"))?;
    let selection: Selection = serde_json::from_value(
        object
            .get("selection")
            .cloned()
            .ok_or_else(|| invalid("ADB device selection is required"))?,
    )
    .map_err(|_| invalid("invalid ADB device selection"))?;
    let output: ProbeOutput = serde_json::from_value(
        object
            .get("probe")
            .cloned()
            .ok_or_else(|| invalid("captured ps output is required"))?,
    )
    .map_err(|_| invalid("invalid captured ps output"))?;

    serde_json::to_value(list(client, selection, output)?)
        .map_err(|_| invalid("process result is not serializable"))
}

struct ParsedProcessList {
    columns: Option<String>,
    processes: Vec<ProcessEntry>,
    unparsed_lines: Vec<String>,
    unparsed_count: usize,
}

fn parse_process_list(stdout: &str) -> ParsedProcessList {
    let mut columns = None;
    let mut processes = Vec::new();
    let mut unparsed_lines = Vec::new();
    let mut unparsed_count = 0;

    for raw_line in stdout.split('\n') {
        let line = raw_line.trim_end();
        if line.is_empty() {
            continue;
        }
        if is_process_header(line) {
            columns = Some(line.trim().to_owned());
            continue;
        }
        match parse_process_line(line) {
            Some(process) => processes.push(process),
            None => {
                unparsed_count += 1;
                unparsed_lines.push(line.to_owned());
            }
        }
    }

    ParsedProcessList {
        columns,
        processes,
        unparsed_lines,
        unparsed_count,
    }
}

fn is_process_header(line: &str) -> bool {
    let mut columns = line.split_whitespace();
    columns.next() == Some("USER")
        && columns.next() == Some("PID")
        && columns.next() == Some("PPID")
}

/// Parse the fixed toybox `ps -A` projection used by the TypeScript provider:
/// USER PID PPID VSZ RSS WCHAN ADDR S NAME.  The final name field may contain
/// spaces and is trimmed exactly as the source parser trims it.
fn parse_process_line(line: &str) -> Option<ProcessEntry> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 9 {
        return None;
    }
    let name = process_name_field(line)?;
    fields[3].parse::<u64>().ok()?;
    fields[5].parse::<u64>().ok()?;
    fields[6].parse::<u64>().ok()?;
    Some(ProcessEntry {
        user: fields[0].to_owned(),
        pid: fields[1].parse().ok()?,
        ppid: safe_integer(fields[2]),
        rss: safe_integer(fields[4]),
        state: Some(fields[7].to_owned()),
        name: name.to_owned(),
    })
}

/// Return the ninth field without collapsing whitespace inside the process name.
///
/// `splitn` is unsuitable here because repeated separators would become empty
/// fields.  The TypeScript parser skips separator runs for the first eight
/// columns and captures the remaining text verbatim before trimming it.
fn process_name_field(line: &str) -> Option<&str> {
    let mut offset = 0;

    for _ in 0..8 {
        while let Some(character) = line[offset..].chars().next() {
            if !character.is_whitespace() {
                break;
            }
            offset += character.len_utf8();
        }

        while let Some(character) = line[offset..].chars().next() {
            if character.is_whitespace() {
                break;
            }
            offset += character.len_utf8();
        }
    }

    let name = line[offset..].trim();
    (!name.is_empty()).then_some(name)
}

fn safe_integer(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed <= 9_007_199_254_740_991).then_some(parsed)
}

fn validate_selection(selection: &Selection) -> Result<(), Failure> {
    if selection.serial.trim().is_empty()
        || selection.serial.len() > 256
        || selection
            .serial
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '\0' | '"' | '\''))
    {
        return Err(invalid("ADB device serial is invalid"));
    }
    Ok(())
}

fn validate_output_size(output: &ProbeOutput) -> Result<(), Failure> {
    if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
        return Err(Failure::new(
            "analysis_input",
            "resource_constraint",
            "Captured ps output exceeds the maximum admitted size.".into(),
            false,
            "Provide bounded ps output and retry.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("max_output_bytes", Detail::Count(MAX_OUTPUT_BYTES as u64)),
            ]),
        ));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "analysis_input",
        "invalid_input",
        reason.into(),
        false,
        "Provide the caller-selected serial, client identity, and bounded captured ps output."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
