//! Port of `src/native/parsers/machoUuid.ts`.
//!
//! Reconciles the selected slice's UUID observations from otool and dwarfdump.

use crate::native_macos::macho::otool::LoadCommand;
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::OnceLock;

fn macho_uuid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$").expect("valid"))
}

fn is_macho_uuid(value: &str) -> bool {
    macho_uuid_re().is_match(value)
}

/// One UUID observation (`UuidObservation`).
enum UuidObservation {
    Absent,
    Valid(String),
    Invalid(String),
    Conflict(String),
}

/// The selected slice identity used to filter dwarfdump rows.
pub(crate) struct UuidArchitectureSelection {
    pub name: String,
    pub dwarfdump_name: String,
}

/// Result of `reconcileMachoUuid`.
pub(crate) struct ReconciledUuid {
    pub value: Option<String>,
    pub limitations: Vec<String>,
}

/// `reconcileMachoUuid(commands, dwarfdumpOutput, artifactPath, selected)`.
pub(crate) fn reconcile_macho_uuid(
    commands: &[LoadCommand],
    dwarfdump_output: &str,
    artifact_path: &str,
    selected_architecture: Option<&UuidArchitectureSelection>,
) -> ReconciledUuid {
    reconcile_observations(
        load_command_uuid(commands),
        parse_dwarfdump_uuid(dwarfdump_output, artifact_path, selected_architecture),
    )
}

fn parse_dwarfdump_uuid(
    output: &str,
    artifact_path: &str,
    selected_architecture: Option<&UuidArchitectureSelection>,
) -> UuidObservation {
    match parse_dwarfdump_rows(output, artifact_path) {
        DwarfdumpRows::Invalid(reason) => UuidObservation::Invalid(reason),
        DwarfdumpRows::Rows(rows) => select_dwarfdump_row(&rows, selected_architecture),
    }
}

struct DwarfdumpUuidRow {
    value: String,
    architecture: String,
}

enum DwarfdumpRows {
    Rows(Vec<DwarfdumpUuidRow>),
    Invalid(String),
}

fn dwarfdump_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Anchored, sticky in TS (`y`). We emulate stickiness by matching at a
    // specific offset and requiring `start == 0` of the remaining slice.
    RE.get_or_init(|| Regex::new(r"^UUID:[ \t]*([^\s]+)[ \t]+\(([^)\r\n]+)\) ").expect("valid"))
}

/// `parseDwarfdumpRows(output, artifactPath)`.
fn parse_dwarfdump_rows(output: &str, artifact_path: &str) -> DwarfdumpRows {
    if output.trim().is_empty() {
        return DwarfdumpRows::Rows(Vec::new());
    }
    let bytes = output.as_bytes();
    let mut rows = Vec::new();
    let mut offset = 0usize;
    while offset < output.len() {
        if output[offset..].starts_with("\r\n") {
            offset += 2;
            continue;
        }
        if bytes[offset] == b'\n' {
            offset += 1;
            continue;
        }
        let remainder = &output[offset..];
        let Some(captures) = dwarfdump_header_re().captures(remainder) else {
            return DwarfdumpRows::Invalid(
                "dwarfdump --uuid output contains an unrecognized row".to_owned(),
            );
        };
        let value = captures
            .get(1)
            .map_or("", |matched| matched.as_str())
            .to_owned();
        let architecture = captures
            .get(2)
            .map_or("", |matched| matched.as_str())
            .to_owned();
        let whole = captures.get(0).expect("match 0");
        offset += whole.end();
        if !output[offset..].starts_with(artifact_path) {
            return DwarfdumpRows::Invalid(format!(
                "dwarfdump --uuid row does not match the selected artifact path (UUID {})",
                json_string(&value)
            ));
        }
        offset += artifact_path.len();
        if offset < output.len() && output[offset..].starts_with("\r\n") {
            offset += 2;
        } else if offset < output.len() && bytes[offset] == b'\n' {
            offset += 1;
        } else if offset != output.len() {
            return DwarfdumpRows::Invalid(format!(
                "dwarfdump --uuid returned malformed UUID row {}",
                json_string(&value)
            ));
        }
        rows.push(DwarfdumpUuidRow {
            value,
            architecture,
        });
    }
    DwarfdumpRows::Rows(rows)
}

fn select_dwarfdump_row(
    rows: &[DwarfdumpUuidRow],
    selected_architecture: Option<&UuidArchitectureSelection>,
) -> UuidObservation {
    if rows.is_empty() {
        return UuidObservation::Absent;
    }
    let selected_rows: Vec<&DwarfdumpUuidRow> = match selected_architecture {
        None => rows.iter().collect(),
        Some(selection) => rows
            .iter()
            .filter(|row| row.architecture == selection.dwarfdump_name)
            .collect(),
    };
    let name = selected_architecture
        .map(|selection| selection.name.as_str())
        .unwrap_or("unknown");
    let distinct_valid: BTreeSet<String> = selected_rows
        .iter()
        .filter(|row| is_macho_uuid(&row.value))
        .map(|row| row.value.to_lowercase())
        .collect();
    if distinct_valid.len() > 1 {
        return UuidObservation::Conflict(format!(
            "dwarfdump --uuid returned conflicting UUIDs for selected architecture {name}"
        ));
    }
    if selected_rows.len() != 1 {
        return UuidObservation::Invalid(if selected_rows.len() > 1 {
            format!("dwarfdump --uuid returned multiple rows for selected architecture {name}")
        } else {
            format!("dwarfdump --uuid returned no row for selected architecture {name}")
        });
    }
    let row = selected_rows[0];
    if !is_macho_uuid(&row.value) {
        return UuidObservation::Invalid(format!(
            "dwarfdump --uuid returned malformed UUID {}",
            json_string(&row.value)
        ));
    }
    UuidObservation::Valid(row.value.clone())
}

fn load_command_uuid(commands: &[LoadCommand]) -> UuidObservation {
    let load_commands: Vec<&LoadCommand> = commands
        .iter()
        .filter(|command| command.kind == "LC_UUID")
        .collect();
    if load_commands.is_empty() {
        return UuidObservation::Absent;
    }
    if load_commands.len() > 1 {
        let observed: Vec<String> = load_commands
            .iter()
            .filter_map(|command| match command.fields.get("uuid") {
                Some(Value::String(value)) if is_macho_uuid(value) => Some(value.clone()),
                _ => None,
            })
            .collect();
        let distinct: BTreeSet<String> =
            observed.iter().map(|value| value.to_lowercase()).collect();
        return if distinct.len() > 1 {
            UuidObservation::Conflict(format!(
                "otool returned conflicting LC_UUID values {}",
                observed
                    .iter()
                    .map(|value| json_string(value))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ))
        } else {
            UuidObservation::Invalid(format!(
                "otool returned {} LC_UUID commands",
                load_commands.len()
            ))
        };
    }
    match load_commands[0].fields.get("uuid") {
        Some(Value::String(value)) if is_macho_uuid(value) => UuidObservation::Valid(value.clone()),
        other => UuidObservation::Invalid(format!(
            "otool LC_UUID contains malformed UUID {}",
            match other {
                Some(Value::String(value)) => json_string(value),
                _ => "null".to_owned(),
            }
        )),
    }
}

fn reconcile_observations(
    load_uuid: UuidObservation,
    dwarfdump: UuidObservation,
) -> ReconciledUuid {
    use UuidObservation::{Conflict, Invalid, Valid};
    if let (Valid(dwarf_value), Valid(load_value)) = (&dwarfdump, &load_uuid) {
        if dwarf_value.to_lowercase() == load_value.to_lowercase() {
            return ReconciledUuid {
                value: Some(dwarf_value.clone()),
                limitations: Vec::new(),
            };
        }
        return ReconciledUuid {
            value: None,
            limitations: vec![format!(
                "dwarfdump --uuid ({dwarf_value}) conflicts with otool LC_UUID ({load_value}); the image UUID is unknown."
            )],
        };
    }
    if let (Valid(_), Conflict(reason)) = (&dwarfdump, &load_uuid) {
        return ReconciledUuid {
            value: None,
            limitations: vec![reason.clone()],
        };
    }
    if let (Valid(_), Conflict(reason)) = (&load_uuid, &dwarfdump) {
        return ReconciledUuid {
            value: None,
            limitations: vec![reason.clone()],
        };
    }
    if let Valid(dwarf_value) = &dwarfdump {
        return ReconciledUuid {
            value: Some(dwarf_value.clone()),
            limitations: match &load_uuid {
                Invalid(reason) => {
                    vec![format!("{reason}; using the unambiguous dwarfdump UUID.")]
                }
                _ => Vec::new(),
            },
        };
    }
    if let Valid(load_value) = &load_uuid {
        return ReconciledUuid {
            value: Some(load_value.clone()),
            limitations: match &dwarfdump {
                Invalid(reason) => {
                    vec![format!("{reason}; using the unambiguous otool LC_UUID.")]
                }
                _ => Vec::new(),
            },
        };
    }
    let mut limitations = Vec::new();
    if let Invalid(reason) | Conflict(reason) = &dwarfdump {
        limitations.push(reason.clone());
    }
    if let Invalid(reason) | Conflict(reason) = &load_uuid {
        limitations.push(reason.clone());
    }
    ReconciledUuid {
        value: None,
        limitations,
    }
}

/// `JSON.stringify(value)` for a string: quoted with JSON escaping.
fn json_string(value: &str) -> String {
    Value::String(value.to_owned()).to_string()
}
