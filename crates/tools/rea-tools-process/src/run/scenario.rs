//! Parsed process scenario, its refinements and committed projections.
//!
//! Compatibility owner: `processScenarioSchema` (`processScenario.ts`). The
//! catalog JSON Schema (validated by `rea_mcp`, which also applies declared
//! defaults) covers the shape; this module adds the `superRefine` rules the
//! advertised schema cannot express and the scenario commitments.

use crate::json::commitment;
use serde_json::{Map, Value, json};

/// `PROCESS_TERMINAL_CELL_BUDGET`.
pub const TERMINAL_CELL_BUDGET: u64 = 1_000_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq)]
pub enum EventKind {
    Input { data: String, sensitive: bool },
    Resize { columns: u16, rows: u16 },
    Signal(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub at_ms: u64,
    pub kind: EventKind,
}

impl Event {
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            EventKind::Input { .. } => "input",
            EventKind::Resize { .. } => "resize",
            EventKind::Signal(_) => "signal",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pattern {
    pub pattern: String,
    pub replacement: String,
}

/// One parsed scenario; `value` is the defaulted, Zod-ordered projection.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub value: Value,
    pub executable: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub environment: Vec<(String, String)>,
    pub filesystem_observation_paths: Vec<String>,
    pub columns: u16,
    pub rows: u16,
    pub scrollback: usize,
    pub events: Vec<Event>,
    pub timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub settle_ms: u64,
    pub finalization_ms: u64,
    pub output_bytes: u64,
    pub files: u64,
    pub file_bytes: u64,
    pub processes: u64,
    pub filesystem_depth: u64,
    pub normalize_paths: bool,
    pub normalize_pids: bool,
    pub normalize_ports: bool,
    pub time_bucket_ms: u64,
    pub patterns: Vec<Pattern>,
}

fn u(value: &Value, key: &str) -> u64 {
    value[key].as_u64().unwrap_or_default()
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_owned()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Zod output order for one event (`timedEventBase` first).
fn event_value(event: &Value) -> Value {
    let mut object = Map::new();
    object.insert("at_ms".into(), event["at_ms"].clone());
    object.insert("type".into(), event["type"].clone());
    for key in ["data", "sensitive", "columns", "rows", "signal"] {
        if let Some(value) = event.get(key) {
            object.insert(key.into(), value.clone());
        }
    }
    if event["type"] == "input" && !object.contains_key("sensitive") {
        object.insert("sensitive".into(), json!(false));
    }
    Value::Object(object)
}

/// Reorder the validated input into the original parser's output order.
fn ordered(input: &Value) -> Value {
    let mut object = Map::new();
    for key in [
        "executable",
        "arguments",
        "working_directory",
        "environment",
        "filesystem_observation_paths",
        "terminal",
        "events",
        "timeout_ms",
        "idle_timeout_ms",
        "settle_ms",
        "finalization_ms",
        "limits",
        "normalization",
    ] {
        let value = &input[key];
        let value = match key {
            "terminal" => {
                json!({"columns": value["columns"], "rows": value["rows"], "scrollback": value["scrollback"]})
            }
            "events" => Value::Array(
                value
                    .as_array()
                    .map(|events| events.iter().map(event_value).collect())
                    .unwrap_or_default(),
            ),
            "limits" => json!({
                "output_bytes": value["output_bytes"], "files": value["files"], "file_bytes": value["file_bytes"],
                "processes": value["processes"], "filesystem_depth": value["filesystem_depth"],
            }),
            "normalization" => json!({
                "paths": value["paths"], "pids": value["pids"], "ports": value["ports"],
                "time_bucket_ms": value["time_bucket_ms"],
                "patterns": value["patterns"].as_array().map(|patterns| patterns.iter().map(|pattern| json!({
                    "pattern": pattern["pattern"], "replacement": pattern["replacement"],
                })).collect::<Vec<_>>()).unwrap_or_default(),
            }),
            _ => value.clone(),
        };
        object.insert(key.into(), value);
    }
    Value::Object(object)
}

impl Scenario {
    /// Build from catalog-validated input with defaults applied.
    pub fn from_input(input: &Value) -> Self {
        Self::from_value(ordered(input))
    }

    fn from_value(value: Value) -> Self {
        let terminal = &value["terminal"];
        let limits = &value["limits"];
        let normalization = &value["normalization"];
        let events = value["events"]
            .as_array()
            .map(|events| {
                events
                    .iter()
                    .map(|event| Event {
                        at_ms: u(event, "at_ms"),
                        kind: match event["type"].as_str() {
                            Some("input") => EventKind::Input {
                                data: text(event, "data"),
                                sensitive: event["sensitive"].as_bool().unwrap_or(false),
                            },
                            Some("resize") => EventKind::Resize {
                                columns: u(event, "columns") as u16,
                                rows: u(event, "rows") as u16,
                            },
                            _ => EventKind::Signal(text(event, "signal")),
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            executable: text(&value, "executable"),
            arguments: strings(&value["arguments"]),
            working_directory: text(&value, "working_directory"),
            environment: value["environment"]
                .as_object()
                .map(|map| {
                    map.iter()
                        .map(|(key, value)| {
                            (key.clone(), value.as_str().unwrap_or_default().to_owned())
                        })
                        .collect()
                })
                .unwrap_or_default(),
            filesystem_observation_paths: strings(&value["filesystem_observation_paths"]),
            columns: u(terminal, "columns") as u16,
            rows: u(terminal, "rows") as u16,
            scrollback: u(terminal, "scrollback") as usize,
            events,
            timeout_ms: u(&value, "timeout_ms"),
            idle_timeout_ms: u(&value, "idle_timeout_ms"),
            settle_ms: u(&value, "settle_ms"),
            finalization_ms: u(&value, "finalization_ms"),
            output_bytes: u(limits, "output_bytes"),
            files: u(limits, "files"),
            file_bytes: u(limits, "file_bytes"),
            processes: u(limits, "processes"),
            filesystem_depth: u(limits, "filesystem_depth"),
            normalize_paths: normalization["paths"].as_bool().unwrap_or(false),
            normalize_pids: normalization["pids"].as_bool().unwrap_or(true),
            normalize_ports: normalization["ports"].as_bool().unwrap_or(true),
            time_bucket_ms: u(normalization, "time_bucket_ms").max(1),
            patterns: normalization["patterns"]
                .as_array()
                .map(|patterns| {
                    patterns
                        .iter()
                        .map(|pattern| Pattern {
                            pattern: text(pattern, "pattern"),
                            replacement: text(pattern, "replacement"),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            value,
        }
    }

    /// The scenario with runtime-resolved paths (`resolveProcessScenarioRuntimePaths`).
    pub fn with_resolved_paths(
        &self,
        executable: String,
        working_directory: String,
        observation_paths: Vec<String>,
    ) -> Self {
        let mut value = self.value.clone();
        value["executable"] = json!(executable);
        value["working_directory"] = json!(working_directory);
        value["filesystem_observation_paths"] = json!(observation_paths);
        Self::from_value(value)
    }

    pub fn normalization(&self) -> Value {
        self.value["normalization"].clone()
    }

    pub fn has_sensitive_input(&self) -> bool {
        self.events.iter().any(|event| {
            matches!(
                event.kind,
                EventKind::Input {
                    sensitive: true,
                    ..
                }
            )
        })
    }

    fn committed_events(&self, include_length: bool) -> Value {
        Value::Array(
            self.value["events"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|event| {
                    let mut event = event.clone();
                    if event["type"] == "input" && event["sensitive"] == true {
                        let length = event["data"].as_str().map_or(0, str::len);
                        event["data"] = json!(if include_length {
                            format!("<redacted-input:{length}-bytes>")
                        } else {
                            "<redacted-input>".to_owned()
                        });
                    }
                    event
                })
                .collect(),
        )
    }

    /// `processScenarioCommitment`.
    pub fn commitment(&self, executable_sha256: Option<&str>) -> Value {
        let mut object = self.value.as_object().cloned().unwrap_or_default();
        object.shift_remove("finalization_ms");
        if self.finalization_ms > 0 {
            object.insert("finalization_ms".into(), json!(self.finalization_ms));
        }
        object.insert("events".into(), self.committed_events(true));
        object.insert("executable_sha256".into(), json!(executable_sha256));
        Value::Object(object)
    }

    /// `processComparisonContract`.
    pub fn comparison_contract(&self) -> Value {
        let mut object = Map::new();
        object.insert(
            "working_directory".into(),
            self.value["working_directory"].clone(),
        );
        object.insert("environment".into(), self.value["environment"].clone());
        object.insert("ambient_environment".into(), json!("unknown"));
        object.insert(
            "filesystem_observation_paths".into(),
            self.value["filesystem_observation_paths"].clone(),
        );
        object.insert("terminal".into(), self.value["terminal"].clone());
        object.insert("events".into(), self.committed_events(false));
        object.insert("timeout_ms".into(), json!(self.timeout_ms));
        object.insert("idle_timeout_ms".into(), json!(self.idle_timeout_ms));
        object.insert("settle_ms".into(), json!(self.settle_ms));
        if self.finalization_ms > 0 {
            object.insert("finalization_ms".into(), json!(self.finalization_ms));
        }
        object.insert("limits".into(), self.value["limits"].clone());
        object.insert("normalization".into(), self.normalization());
        if self.normalize_paths {
            object.insert(
                "path_normalization_version".into(),
                json!("longest-original-paths-v1"),
            );
        }
        if self.normalize_ports {
            object.insert(
                "port_normalization_version".into(),
                json!("contextual-endpoints-v2"),
            );
        }
        if !self.patterns.is_empty() {
            object.insert(
                "pattern_normalization_version".into(),
                json!("literal-replacements-v1"),
            );
        }
        object.insert(
            "rendered_line_format".into(),
            json!("trailing-spaces-trimmed-v1"),
        );
        Value::Object(object)
    }
}

/// `digestProcessCommitment`.
pub fn digest(value: &Value) -> String {
    commitment(value).unwrap_or_default()
}

/// `fitsProcessTerminalCellBudget`.
pub fn fits_cell_budget(columns: u64, rows: u64, scrollback: u64) -> bool {
    columns > 0 && rows + scrollback <= TERMINAL_CELL_BUDGET / columns
}

/// The `superRefine` issues, in the original order: (path, message).
pub fn refinements(scenario: &Scenario) -> Vec<(Vec<String>, String)> {
    let mut issues = Vec::new();
    let lifecycle = u128::from(scenario.timeout_ms)
        + u128::from(scenario.finalization_ms)
        + u128::from(scenario.settle_ms);
    if lifecycle > u128::from(MAX_SAFE_INTEGER) {
        issues.push((
            vec!["timeout_ms".to_owned()],
            format!(
                "timeout_ms + finalization_ms + settle_ms must stay at or below {MAX_SAFE_INTEGER} ms, the largest total exactly representable as a JavaScript number"
            ),
        ));
    }
    let scrollback = scenario.scrollback as u64;
    if !fits_cell_budget(
        u64::from(scenario.columns),
        u64::from(scenario.rows),
        scrollback,
    ) {
        issues.push((
            vec!["terminal".to_owned()],
            format!("terminal columns × (rows + scrollback) must not exceed {TERMINAL_CELL_BUDGET} renderer cells"),
        ));
    }
    for index in 1..scenario.events.len() {
        if scenario.events[index].at_ms < scenario.events[index - 1].at_ms {
            issues.push((
                vec!["events".to_owned(), index.to_string()],
                "events must be ordered by at_ms".to_owned(),
            ));
        }
    }
    for (index, event) in scenario.events.iter().enumerate() {
        if let EventKind::Resize { columns, rows } = event.kind
            && !fits_cell_budget(u64::from(columns), u64::from(rows), scrollback)
        {
            issues.push((
                vec!["events".to_owned(), index.to_string()],
                format!(
                    "resize event at {} ms exceeds the {TERMINAL_CELL_BUDGET}-cell renderer budget with the selected scrollback",
                    event.at_ms
                ),
            ));
        }
        if event.at_ms > scenario.timeout_ms {
            issues.push((
                vec!["events".to_owned()],
                "event occurs after the scenario timeout".to_owned(),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(extra: Value) -> Scenario {
        let mut input = json!({
            "executable": "/bin/echo", "arguments": [], "working_directory": ".", "environment": {},
            "filesystem_observation_paths": [], "terminal": {"columns": 80, "rows": 24, "scrollback": 1000},
            "events": [], "timeout_ms": 30000, "idle_timeout_ms": 30000, "settle_ms": 100, "finalization_ms": 0,
            "limits": {"output_bytes": 1000000, "files": 10000, "file_bytes": 10000000, "processes": 1000, "filesystem_depth": 16},
            "normalization": {"paths": false, "pids": true, "ports": true, "time_bucket_ms": 10, "patterns": []},
        });
        for (key, value) in extra.as_object().unwrap() {
            input[key] = value.clone();
        }
        Scenario::from_input(&input)
    }

    #[test]
    fn refinements_follow_the_original_order_and_messages() {
        let issues = refinements(&scenario(json!({
            "timeout_ms": 100,
            "terminal": {"columns": 1000, "rows": 1000, "scrollback": 1000},
            "events": [{"at_ms": 50, "type": "input", "data": "a"}, {"at_ms": 10, "type": "resize", "columns": 2000, "rows": 600}, {"at_ms": 500, "type": "signal", "signal": "SIGINT"}],
        })));
        let paths: Vec<_> = issues.iter().map(|(path, _)| path.join(".")).collect();
        assert_eq!(paths, ["terminal", "events.1", "events.1", "events"]);
        assert_eq!(issues[3].1, "event occurs after the scenario timeout");
    }

    #[test]
    fn commitments_redact_sensitive_input_and_keep_zero_finalization_out() {
        let scenario = scenario(
            json!({"events": [{"at_ms": 0, "type": "input", "data": "secret", "sensitive": true}]}),
        );
        let committed = scenario.commitment(Some("abc"));
        assert_eq!(committed["events"][0]["data"], "<redacted-input:6-bytes>");
        assert!(committed.get("finalization_ms").is_none());
        assert_eq!(
            scenario.comparison_contract()["events"][0]["data"],
            "<redacted-input>"
        );
        assert_eq!(
            scenario.comparison_contract()["port_normalization_version"],
            "contextual-endpoints-v2"
        );
    }
}
