//! Offline projections for captured ADB display and window-manager output.
//!
//! The runtime owns command execution and fallback policy.  These functions
//! parse only supplied captures, retain the selected serial, and keep missing
//! or conflicting declarations explicit.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const DISPLAY_OPERATION: &str = "inspect_adb_display";
pub const WINDOW_OPERATION: &str = "inspect_adb_window";
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub serial: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct DisplayInspection {
    pub serial: String,
    pub physical_size: Size,
    pub override_size: Option<Size>,
    pub physical_density: Option<u32>,
    pub override_density: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FocusDeclaration {
    pub field: String,
    pub value: Option<String>,
    pub raw_line: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FocusContext {
    pub scope: String,
    pub display_id: Option<String>,
    pub header_line: Option<String>,
    pub declarations: Vec<FocusDeclaration>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowInspection {
    pub serial: String,
    pub source_section: String,
    pub focus_contexts: Vec<FocusContext>,
    pub focus_summary: String,
    pub focused_window: Option<String>,
    pub focused_app: Option<String>,
    pub observed_lines: Vec<String>,
}

pub fn inspect_display(
    selection: Selection,
    size_capture: Capture,
    density_capture: Capture,
) -> Result<DisplayInspection, Failure> {
    validate_selection(&selection)?;
    validate_capture(DISPLAY_OPERATION, &size_capture)?;
    validate_capture(DISPLAY_OPERATION, &density_capture)?;
    let (physical_size, override_size) = parse_size(&size_capture.stdout)
        .ok_or_else(|| invalid(DISPLAY_OPERATION, "wm size did not report a physical size"))?;
    let (physical_density, override_density) = parse_density(&density_capture.stdout);
    Ok(DisplayInspection {
        serial: selection.serial,
        physical_size,
        override_size,
        physical_density,
        override_density,
    })
}

pub fn inspect_window(
    selection: Selection,
    source_section: String,
    capture: Capture,
) -> Result<WindowInspection, Failure> {
    validate_selection(&selection)?;
    validate_capture(WINDOW_OPERATION, &capture)?;
    if !matches!(source_section.as_str(), "windows" | "displays") {
        return Err(invalid(
            WINDOW_OPERATION,
            "window source section is invalid",
        ));
    }
    let (focus_contexts, observed_lines) = parse_focus(&capture.stdout);
    let (focus_summary, focused_window, focused_app) = summarize_focus(&focus_contexts);
    Ok(WindowInspection {
        serial: selection.serial,
        source_section,
        focus_contexts,
        focus_summary,
        focused_window,
        focused_app,
        observed_lines,
    })
}

/// Parse adapter-shaped display input without contacting ADB.
pub fn inspect_display_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid(DISPLAY_OPERATION, "input must be an object"))?;
    let selection = decode_selection(object)?;
    let size: Capture = decode_capture(object.get("size"), DISPLAY_OPERATION, "size")?;
    let density: Capture = decode_capture(object.get("density"), DISPLAY_OPERATION, "density")?;
    serde_json::to_value(inspect_display(selection, size, density)?)
        .map_err(|_| invalid(DISPLAY_OPERATION, "result is not serializable"))
}

/// Parse adapter-shaped window input without contacting ADB.
pub fn inspect_window_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid(WINDOW_OPERATION, "input must be an object"))?;
    let selection = decode_selection(object)?;
    let section = object
        .get("source_section")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(WINDOW_OPERATION, "source_section is required"))?
        .to_owned();
    let capture: Capture = decode_capture(object.get("capture"), WINDOW_OPERATION, "capture")?;
    serde_json::to_value(inspect_window(selection, section, capture)?)
        .map_err(|_| invalid(WINDOW_OPERATION, "result is not serializable"))
}

fn parse_size(stdout: &str) -> Option<(Size, Option<Size>)> {
    let mut physical = None;
    let mut override_size = None;
    for line in stdout.lines().map(str::trim) {
        if let Some(value) = declaration_value(line, "Physical size:") {
            physical = parse_pair(value);
        }
        if let Some(value) = declaration_value(line, "Override size:") {
            override_size = parse_pair(value);
        }
    }
    physical.map(|value| (value, override_size))
}

fn parse_pair(value: &str) -> Option<Size> {
    let (width, height) = value.split_once('x')?;
    let width = width.parse().ok()?;
    let height = height.parse().ok()?;
    Some(Size { width, height })
}

fn parse_density(stdout: &str) -> (Option<u32>, Option<u32>) {
    let mut physical = None;
    let mut override_density = None;
    let mut bare = None;
    for line in stdout.lines().map(str::trim) {
        if let Some(value) = declaration_value(line, "Physical density:") {
            physical = value.parse().ok();
        }
        if let Some(value) = declaration_value(line, "Override density:") {
            override_density = value.parse().ok();
        }
        if !line.is_empty()
            && line.chars().all(|character| character.is_ascii_digit())
            && bare.is_none()
        {
            bare = line.parse().ok();
        }
    }
    (physical.or(bare), override_density)
}

fn declaration_value<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let remainder = line.strip_prefix(label)?;
    remainder
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
        .then(|| remainder.trim())
        .filter(|value| !value.is_empty())
}

fn parse_focus(stdout: &str) -> (Vec<FocusContext>, Vec<String>) {
    let mut contexts = Vec::new();
    let mut observed = Vec::new();
    let mut current: Option<usize> = None;
    for raw_line in stdout.lines() {
        let trimmed = raw_line.trim();
        if let Some(value) = trimmed.strip_prefix("Display:") {
            let display_id = value
                .split_whitespace()
                .next()
                .and_then(|part| part.strip_prefix("mDisplayId="))
                .and_then(parse_display_id);
            contexts.push(FocusContext {
                scope: "display".into(),
                display_id,
                header_line: Some(raw_line.into()),
                declarations: Vec::new(),
            });
            current = Some(contexts.len() - 1);
            observed.push(raw_line.into());
            continue;
        }
        let field = if trimmed.starts_with("mCurrentFocus=") {
            Some("mCurrentFocus")
        } else if trimmed.starts_with("mFocusedApp=") {
            Some("mFocusedApp")
        } else {
            None
        };
        let Some(field) = field else { continue };
        let index = current.unwrap_or_else(|| {
            contexts.push(FocusContext {
                scope: "unscoped".into(),
                display_id: None,
                header_line: None,
                declarations: Vec::new(),
            });
            contexts.len() - 1
        });
        let value = trimmed[field.len() + 1..].trim();
        contexts[index].declarations.push(FocusDeclaration {
            field: field.into(),
            value: (value != "null").then(|| value.into()),
            raw_line: raw_line.into(),
        });
        observed.push(raw_line.into());
    }
    (contexts, observed)
}

fn parse_display_id(value: &str) -> Option<String> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    (!digits.is_empty() && digits.chars().all(|character| character.is_ascii_digit()))
        .then(|| value.to_owned())
}

fn summarize_focus(contexts: &[FocusContext]) -> (String, Option<String>, Option<String>) {
    let declared = contexts
        .iter()
        .any(|context| !context.declarations.is_empty());
    if !declared {
        return ("unavailable".into(), None, None);
    }
    if contexts.len() != 1 {
        return ("ambiguous".into(), None, None);
    }
    let windows = contexts[0]
        .declarations
        .iter()
        .filter(|item| item.field == "mCurrentFocus")
        .collect::<Vec<_>>();
    let apps = contexts[0]
        .declarations
        .iter()
        .filter(|item| item.field == "mFocusedApp")
        .collect::<Vec<_>>();
    if windows.len() > 1 || apps.len() > 1 {
        return ("ambiguous".into(), None, None);
    }
    (
        "single_context".into(),
        windows.first().and_then(|item| item.value.clone()),
        apps.first().and_then(|item| item.value.clone()),
    )
}

fn decode_selection(object: &serde_json::Map<String, Value>) -> Result<Selection, Failure> {
    serde_json::from_value(
        object
            .get("selection")
            .cloned()
            .ok_or_else(|| invalid(DISPLAY_OPERATION, "selection is required"))?,
    )
    .map_err(|_| invalid(DISPLAY_OPERATION, "invalid selection"))
}

fn decode_capture(value: Option<&Value>, operation: &str, name: &str) -> Result<Capture, Failure> {
    serde_json::from_value(
        value
            .cloned()
            .ok_or_else(|| invalid(operation, &format!("{name} capture is required")))?,
    )
    .map_err(|_| invalid(operation, &format!("invalid {name} capture")))
}

fn validate_selection(selection: &Selection) -> Result<(), Failure> {
    if selection.serial.trim().is_empty()
        || selection.serial.len() > 256
        || selection.serial.chars().any(|character| {
            character.is_whitespace() || character == '\0' || character == '"' || character == '\''
        })
    {
        return Err(invalid(DISPLAY_OPERATION, "ADB device serial is invalid"));
    }
    Ok(())
}

fn validate_capture(operation: &str, capture: &Capture) -> Result<(), Failure> {
    if capture.stdout.len() > MAX_CAPTURE_BYTES || capture.stderr.len() > MAX_CAPTURE_BYTES {
        return Err(Failure::new(
            "resource_constraint",
            "resource_constraint",
            "Captured ADB output exceeds the retained output bound.".into(),
            false,
            "Provide bounded ADB command output and retry.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(operation.into())),
                ("max_output_bytes", Detail::Count(MAX_CAPTURE_BYTES as u64)),
            ]),
        ));
    }
    Ok(())
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide the selected serial and bounded captured ADB output.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}
