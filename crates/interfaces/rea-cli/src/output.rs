//! CLI result delivery: failure detection, output envelope and exit status.
//!
//! Combines the observable behavior of `scripts/rea.mjs`, incur's `serve`
//! `write()` and REA's `cliResultOutput`/`cliLogging`. REA command handlers
//! return plain values (never incur error sentinels), so a returned value is
//! formatted as data while a detected failure still forces exit code 1.
use crate::commands::CommandOutput;
use crate::format::{self, Format};
use rea_application::javascript::graph::json::{self, Json, Obj};
use rea_application::javascript::semantic::value_types::JsString;
use serde_json::{Map, Value};

/// Output controls resolved from global flags.
pub struct OutputCtx {
    pub format: Format,
    pub human: bool,
    pub full_output: bool,
    pub filter: Option<Vec<format::filter::FilterPath>>,
    pub token_count: bool,
    pub token_limit: Option<usize>,
    pub token_offset: Option<usize>,
    pub agent_only: bool,
}

/// How a command classifies its own returned value as a failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Default inference (projection / error envelope / `healthy:false`).
    Inferred,
    /// `{ error: "Process command failed", category, message }`.
    ProcessCli,
    /// `{ status: "failed" | "needs_human" | ... }` style maintenance results.
    StatusField,
    /// Reference-source import failure (`{ error: "Import failed", ... }`).
    ImportFailed,
}

fn looks_like_projection(object: &Map<String, Value>) -> bool {
    object.get("code").and_then(Value::as_str).is_some()
        && object.get("message").and_then(Value::as_str).is_some()
        && object.get("category").and_then(Value::as_str).is_some()
}

/// Return the failure payload if `value` means the operation failed.
pub fn failure_payload(value: &Value, kind: FailureKind) -> Option<Value> {
    let object = value.as_object()?;
    match kind {
        FailureKind::ProcessCli => {
            if object.get("error").and_then(Value::as_str) == Some("Process command failed") {
                return Some(value.clone());
            }
        }
        FailureKind::StatusField => {
            if let Some(status) = object.get("status").and_then(Value::as_str)
                && matches!(
                    status,
                    "failed"
                        | "needs_human"
                        | "needs_confirmation"
                        | "blocked"
                        | "partial"
                        | "deferred"
                )
            {
                return Some(value.clone());
            }
            if object.get("cleanupFailure").is_some() {
                return Some(value.clone());
            }
        }
        FailureKind::ImportFailed => {
            if object.get("error").and_then(Value::as_str) == Some("Import failed") {
                return Some(value.clone());
            }
        }
        FailureKind::Inferred => {}
    }
    // Inferred classification (applies to every command as a fallback).
    if looks_like_projection(object) {
        return Some(value.clone());
    }
    if let Some(label) = object.get("error") {
        if label.is_string() {
            // CLI failure envelope: strip the label, keep the projection body.
            let mut projection = object.clone();
            projection.remove("error");
            projection.remove("input_path");
            projection.remove("input_reason");
            return Some(Value::Object(projection));
        }
        if let Some(nested) = label.as_object()
            && looks_like_projection(nested)
        {
            return Some(label.clone());
        }
    }
    if object.get("healthy") == Some(&Value::Bool(false)) {
        return Some(value.clone());
    }
    None
}

fn apply_filter(value: &Value, ctx: &OutputCtx) -> Value {
    match &ctx.filter {
        Some(paths) => format::filter::apply(value, paths),
        None => value.clone(),
    }
}

fn apply_exact_filter(value: &Json, paths: &[format::filter::FilterPath]) -> Json {
    use format::filter::Segment;

    if paths.is_empty() {
        return value.clone();
    }

    if paths.len() == 1
        && paths[0].len() == 1
        && let Segment::Key(key) = &paths[0][0]
    {
        let key = JsString::from(key.as_str());
        return match value {
            Json::Array(items) => Json::Array(
                items
                    .iter()
                    .map(|item| apply_exact_filter(item, paths))
                    .collect(),
            ),
            Json::Object(object) => match object.get::<JsString>(&key) {
                Some(selected) if matches!(selected, Json::Object(_) | Json::Array(_)) => {
                    Json::Object(Obj::new().with(key, selected.clone()))
                }
                Some(selected) => selected.clone(),
                None => Json::Null,
            },
            _ => Json::Null,
        };
    }

    if let Json::Array(items) = value {
        return Json::Array(
            items
                .iter()
                .map(|item| apply_exact_filter(item, paths))
                .collect(),
        );
    }

    let mut result = Obj::new();
    for path in paths {
        merge_exact_filter(&mut result, value, path, 0);
    }
    Json::Object(result)
}

fn merge_exact_filter(
    target: &mut Obj,
    value: &Json,
    path: &format::filter::FilterPath,
    index: usize,
) {
    use format::filter::Segment;

    let Json::Object(object) = value else {
        return;
    };
    let Some(Segment::Key(key)) = path.get(index) else {
        return;
    };
    let key = JsString::from(key.as_str());
    let Some(selected) = object.get::<JsString>(&key) else {
        return;
    };

    if index + 1 >= path.len() {
        target.set(key, selected.clone());
        return;
    }

    if let format::filter::Segment::Slice { start, end } = &path[index + 1] {
        let Json::Array(items) = selected else {
            return;
        };
        let selected = exact_slice(items.as_slice(), *start, *end);
        target.set(key, Json::Array(selected));
        return;
    }

    let nested = apply_exact_filter(selected, &[path[index + 1..].to_vec()]);
    target.set(key, nested);
}

fn exact_slice(items: &[Json], start: i64, end: i64) -> Vec<Json> {
    let len = items.len() as i64;
    let normalize = |index: i64| {
        if index < 0 {
            (len + index).max(0)
        } else {
            index.min(len)
        }
    };
    let start = normalize(start);
    let end = normalize(end);
    if start >= end {
        return Vec::new();
    }
    items[start as usize..end as usize].to_vec()
}

#[derive(Clone, Copy)]
enum ExactDisplayMode {
    Yaml,
    Replacement,
}

fn exact_display_value(
    value: &Json,
    mode: ExactDisplayMode,
    source: &str,
) -> (Value, Vec<(String, String)>) {
    let mut replacements = Vec::new();
    let converted = exact_display_value_inner(value, mode, source, &mut replacements);
    (converted, replacements)
}

fn exact_display_value_inner(
    value: &Json,
    mode: ExactDisplayMode,
    source: &str,
    replacements: &mut Vec<(String, String)>,
) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Number(number) => serde_json::Number::from_f64(*number)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Json::String(text) => Value::String(exact_display_string(text, mode, source, replacements)),
        Json::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| exact_display_value_inner(item, mode, source, replacements))
                .collect(),
        ),
        Json::Object(object) => {
            let mut result = Map::new();
            for (key, item) in object.iter() {
                let display_key = exact_display_string(key, mode, source, replacements);
                result.insert(
                    display_key,
                    exact_display_value_inner(item, mode, source, replacements),
                );
            }
            Value::Object(result)
        }
    }
}

fn exact_display_string(
    text: &JsString,
    mode: ExactDisplayMode,
    source: &str,
    replacements: &mut Vec<(String, String)>,
) -> String {
    if let Some(valid) = text.as_str() {
        return valid.to_owned();
    }
    if matches!(mode, ExactDisplayMode::Replacement) {
        return String::from_utf16_lossy(text.units());
    }

    let mut index = replacements.len();
    let sentinel = loop {
        let candidate = format!("__REA_EXACT_UTF16_{index}__");
        if !source.contains(&candidate) {
            break candidate;
        }
        index += 1;
    };
    let escaped = text
        .units()
        .iter()
        .map(|unit| format!("\\u{unit:04x}"))
        .collect::<String>();
    replacements.push((sentinel.clone(), escaped));
    sentinel
}

fn replace_yaml_sentinels(mut text: String, replacements: &[(String, String)]) -> String {
    for (sentinel, escaped) in replacements {
        let quoted_sentinel = format!("\"{sentinel}\"");
        let quoted_value = format!("\"{escaped}\"");
        text = text.replace(&quoted_sentinel, &quoted_value);
        text = text.replace(sentinel, &quoted_value);
    }
    text
}

fn deliver_exact_display(
    value: &Json,
    command: &str,
    duration_ms: u128,
    ctx: &OutputCtx,
) -> (String, i32) {
    let mode = if matches!(ctx.format, Format::Yaml) {
        ExactDisplayMode::Yaml
    } else {
        ExactDisplayMode::Replacement
    };
    let (display_value, replacements) = exact_display_value(value, mode, &value.stringify());
    if ctx.token_count {
        let formatted = format::format(&display_value, ctx.format);
        return (format!("{}\n", format::tokens::estimate(&formatted)), 0);
    }

    let document = if ctx.full_output {
        let mut envelope = Map::new();
        envelope.insert("ok".to_owned(), Value::Bool(true));
        envelope.insert("data".to_owned(), display_value);
        envelope.insert(
            "meta".to_owned(),
            envelope_meta(command, &format!("{duration_ms}ms"), None),
        );
        Value::Object(envelope)
    } else {
        display_value
    };
    let formatted = format::format(&document, ctx.format);
    let formatted = if matches!(mode, ExactDisplayMode::Yaml) {
        replace_yaml_sentinels(formatted, &replacements)
    } else {
        formatted
    };
    let (text, _next) = truncate(&formatted, ctx);
    (with_final_newline(text), 0)
}

fn with_final_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

fn truncate(text: &str, ctx: &OutputCtx) -> (String, Option<usize>) {
    if ctx.token_limit.is_none() && ctx.token_offset.is_none() {
        return (text.to_owned(), None);
    }
    let total = format::tokens::estimate(text);
    let offset = ctx.token_offset.unwrap_or(0);
    let end = ctx.token_limit.map(|limit| offset + limit);
    if offset == 0 && end.map_or(true, |end| end >= total) {
        return (text.to_owned(), None);
    }
    let sliced = format::tokens::slice(text, offset, end);
    let actual_end = end.map_or(total, |end| end.min(total));
    let next = if actual_end < total {
        Some(actual_end)
    } else {
        None
    };
    (
        format!("{sliced}\n[truncated: showing tokens {offset}\u{2013}{actual_end} of {total}]"),
        next,
    )
}

fn envelope_meta(command: &str, duration: &str, next_offset: Option<usize>) -> Value {
    let mut meta = Map::new();
    meta.insert("command".to_owned(), Value::String(command.to_owned()));
    meta.insert("duration".to_owned(), Value::String(duration.to_owned()));
    if let Some(next) = next_offset {
        meta.insert("nextOffset".to_owned(), Value::Number(next.into()));
    }
    Value::Object(meta)
}

/// Format a normally-returned command value into stdout text and exit code.
pub fn deliver(
    output: &CommandOutput,
    command: &str,
    duration_ms: u128,
    kind: FailureKind,
    ctx: &OutputCtx,
) -> (String, i32) {
    if let CommandOutput::Raw(raw) = output {
        let raw = raw.get();
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            return deliver(
                &CommandOutput::Value(value),
                command,
                duration_ms,
                kind,
                ctx,
            );
        }

        if let Some(paths) = &ctx.filter
            && let Ok(exact) = json::parse(raw)
        {
            let selected = apply_exact_filter(&exact, paths);
            let selected_raw = selected.stringify();
            if let Ok(value) = serde_json::from_str::<Value>(&selected_raw) {
                return deliver(
                    &CommandOutput::Value(value),
                    command,
                    duration_ms,
                    kind,
                    ctx,
                );
            }
            if matches!(ctx.format, Format::Json | Format::Jsonl) {
                return deliver_exact_json(&selected_raw, command, duration_ms, ctx);
            }
            return deliver_exact_display(&selected, command, duration_ms, ctx);
        }

        if ctx.human && ctx.agent_only {
            return (String::new(), 0);
        }

        if ctx.filter.is_some() {
            return raw_output_error(
                "Filtering this exact JavaScript result requires a JSON-capable client because its source contains an unpaired UTF-16 code unit.",
                ctx,
            );
        }

        if !matches!(ctx.format, Format::Json | Format::Jsonl) {
            if let Ok(exact) = json::parse(raw) {
                return deliver_exact_display(&exact, command, duration_ms, ctx);
            }
            return raw_output_error("The exact JavaScript result is not valid JSON.", ctx);
        }

        return deliver_exact_json(raw, command, duration_ms, ctx);
    }
    let CommandOutput::Value(value) = output else {
        unreachable!("raw command output handled above")
    };

    let failure = failure_payload(value, kind);
    let exit = if failure.is_some() { 1 } else { 0 };
    let duration = format!("{duration_ms}ms");
    let filtered = apply_filter(value, ctx);

    if ctx.token_count {
        let base = failure.clone().unwrap_or_else(|| filtered.clone());
        let count = format::tokens::estimate(&format::format(&base, ctx.format));
        return (format!("{count}\n"), exit);
    }

    if ctx.full_output {
        let document = if let Some(payload) = &failure {
            let mut object = Map::new();
            object.insert("ok".to_owned(), Value::Bool(false));
            object.insert("error".to_owned(), payload.clone());
            object.insert("meta".to_owned(), envelope_meta(command, &duration, None));
            Value::Object(object)
        } else {
            let mut object = Map::new();
            object.insert("ok".to_owned(), Value::Bool(true));
            if !filtered.is_null() {
                object.insert("data".to_owned(), filtered.clone());
            }
            object.insert("meta".to_owned(), envelope_meta(command, &duration, None));
            Value::Object(object)
        };
        let formatted = format::format(&document, ctx.format);
        let (text, _next) = truncate(&formatted, ctx);
        return (with_final_newline(text), exit);
    }

    // Human TTY without an explicit format still prints the formatted value;
    // a detected failure only changes the exit code.
    let base = failure.clone().unwrap_or(filtered);
    if ctx.human && failure.is_none() && ctx.agent_only {
        // agent-only policy suppresses data for humans.
        return (String::new(), exit);
    }
    if base.is_null() {
        if ctx.filter.is_some() && matches!(ctx.format, Format::Json | Format::Jsonl | Format::Yaml)
        {
            return ("{}\n".to_owned(), exit);
        }
        return (String::new(), exit);
    }
    let formatted = format::format(&base, ctx.format);
    let (text, _next) = truncate(&formatted, ctx);
    (with_final_newline(text), exit)
}

fn raw_output_error(message: &str, ctx: &OutputCtx) -> (String, i32) {
    (
        deliver_error("RAW_OUTPUT_UNSUPPORTED", message, None, ctx),
        1,
    )
}

fn deliver_exact_json(
    raw: &str,
    command: &str,
    duration_ms: u128,
    ctx: &OutputCtx,
) -> (String, i32) {
    if ctx.token_count {
        return (format!("{}\n", format::tokens::estimate(raw)), 0);
    }
    if ctx.full_output {
        let document = format!(
            "{{\"ok\":true,\"data\":{raw},\"meta\":{{\"command\":{command:?},\"duration\":\"{duration_ms}ms\"}}}}"
        );
        let (text, _next) = truncate(&document, ctx);
        return (with_final_newline(text), 0);
    }
    let (text, _next) = truncate(raw, ctx);
    (with_final_newline(text), 0)
}

/// Format a framework-generated error (command-not-found, parse/validation,
/// output-argument). Always exit code 1.
pub fn deliver_error(
    code: &str,
    message: &str,
    field_errors: Option<Value>,
    ctx: &OutputCtx,
) -> String {
    if ctx.human && !ctx.full_output {
        let prefix = if code == "UNKNOWN" || code == "COMMAND_NOT_FOUND" {
            "Error".to_owned()
        } else {
            format!("Error ({code})")
        };
        return format!("{prefix}: {message}\n");
    }
    let mut error = Map::new();
    error.insert("code".to_owned(), Value::String(code.to_owned()));
    error.insert("message".to_owned(), Value::String(message.to_owned()));
    if let Some(fields) = field_errors {
        error.insert("fieldErrors".to_owned(), fields);
    }
    let document = if ctx.full_output {
        let mut object = Map::new();
        object.insert("ok".to_owned(), Value::Bool(false));
        object.insert("error".to_owned(), Value::Object(error));
        object
    } else {
        error
    };
    with_final_newline(format::format(&Value::Object(document), ctx.format))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;

    fn context(format: Format) -> OutputCtx {
        OutputCtx {
            format,
            human: false,
            full_output: false,
            filter: None,
            token_count: false,
            token_limit: None,
            token_offset: None,
            agent_only: false,
        }
    }

    #[test]
    fn raw_cli_carrier_writes_unpaired_surrogate_without_value_decode() {
        let raw = RawValue::from_string(r#"{"path":"\ud800"}"#.to_owned()).expect("raw JSON");
        let value = CommandOutput::Raw(raw);
        let context = context(Format::Json);

        let (text, exit) = deliver(
            &value,
            "analyze_javascript_application",
            0,
            FailureKind::Inferred,
            &context,
        );

        assert_eq!(text, concat!(r#"{"path":"\ud800"}"#, "\n"));
        assert_eq!(exit, 0);
    }

    #[test]
    fn raw_cli_carrier_applies_filter_without_losing_unpaired_surrogate() {
        let raw = RawValue::from_string(r#"{"path":"\ud800"}"#.to_owned()).expect("raw JSON");
        let value = CommandOutput::Raw(raw);
        let mut context = context(Format::Json);
        context.filter = Some(format::filter::parse("path"));

        let (text, exit) = deliver(
            &value,
            "analyze_javascript_application",
            0,
            FailureKind::Inferred,
            &context,
        );

        assert_eq!(exit, 0);
        assert_eq!(text, concat!(r#""\ud800""#, "\n"));
    }

    #[test]
    fn valid_raw_json_reuses_requested_formatter() {
        let raw = RawValue::from_string(r#"{"path":"/tmp/app"}"#.to_owned()).expect("raw JSON");
        let value = CommandOutput::Raw(raw);
        let context = context(Format::Yaml);

        let (text, exit) = deliver(
            &value,
            "analyze_javascript_application",
            0,
            FailureKind::Inferred,
            &context,
        );

        assert_eq!(exit, 0);
        assert!(text.contains("path: /tmp/app"));
    }

    #[test]
    fn exact_surrogate_yaml_uses_javascript_escape() {
        let raw = RawValue::from_string(r#"{"path":"\ud800"}"#.to_owned()).expect("raw JSON");
        let value = CommandOutput::Raw(raw);
        let context = context(Format::Yaml);

        let (text, exit) = deliver(
            &value,
            "analyze_javascript_application",
            0,
            FailureKind::Inferred,
            &context,
        );

        assert_eq!(exit, 0);
        assert_eq!(text, "path: \"\\ud800\"\n");
    }

    #[test]
    fn exact_surrogate_toon_uses_display_replacement() {
        let raw = RawValue::from_string(r#"{"path":"\ud800"}"#.to_owned()).expect("raw JSON");
        let value = CommandOutput::Raw(raw);
        let context = context(Format::Toon);

        let (text, exit) = deliver(
            &value,
            "analyze_javascript_application",
            0,
            FailureKind::Inferred,
            &context,
        );

        assert_eq!(exit, 0);
        assert!(text.contains('\u{fffd}'));
    }
}
