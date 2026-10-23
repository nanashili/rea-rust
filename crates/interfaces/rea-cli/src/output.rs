//! CLI result delivery: failure detection, output envelope and exit status.
//!
//! Combines the observable behavior of `scripts/rea.mjs`, incur's `serve`
//! `write()` and REA's `cliResultOutput`/`cliLogging`. REA command handlers
//! return plain values (never incur error sentinels), so a returned value is
//! formatted as data while a detected failure still forces exit code 1.
use crate::format::{self, Format};
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
                && (status == "failed" || status == "needs_human" || status == "needs_confirmation")
            {
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
    value: &Value,
    command: &str,
    duration_ms: u128,
    kind: FailureKind,
    ctx: &OutputCtx,
) -> (String, i32) {
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
        return (format!("{text}\n"), exit);
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
    (format!("{text}\n"), exit)
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
    format!("{}\n", format::format(&Value::Object(document), ctx.format))
}
