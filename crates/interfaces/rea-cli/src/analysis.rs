//! One-shot analysis lifecycle: open a target, run one or more tools, always
//! close. Mirrors `src/application/DirectAnalysis.ts`. MCP mode keeps a target
//! open across calls; the CLI intentionally isolates every invocation by
//! opening and closing its own target, never retaining a provider client.
use crate::invoke::{Invocation, Runner};
use crate::util::{absolute_caller_path, labelled};
use serde_json::{Map, Value};
use std::path::Path;

/// Target-open options derived from shared native CLI flags.
#[derive(Default)]
pub struct OpenOptions {
    pub snapshot: Option<String>,
    pub provider: Option<String>,
}

fn looks_like_projection(object: &Map<String, Value>) -> bool {
    object.get("code").and_then(Value::as_str).is_some()
        && object.get("message").and_then(Value::as_str).is_some()
        && object.get("category").and_then(Value::as_str).is_some()
}

/// `{ error: "Analysis failed", ...projection }`.
pub fn cli_error(projection: Value) -> Value {
    labelled("Analysis failed", projection)
}

/// Fold a provider cleanup failure into the primary CLI output, mirroring
/// `directAnalysisCleanupFailure`.
fn cleanup_failure(output: Value, cleanup: Value) -> Value {
    let cleanup_remediation = cleanup.get("remediation").cloned();
    let cleanup_details = cleanup.get("details").and_then(Value::as_object).cloned();
    if let Some(object) = output.as_object() {
        let label = object
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut projection = object.clone();
        projection.remove("error");
        if let (Some(label), true) = (label, looks_like_projection(&projection)) {
            let mut out = Map::new();
            out.insert("error".to_owned(), Value::String(label));
            for (key, value) in &projection {
                out.insert(key.clone(), value.clone());
            }
            out.insert(
                "code".to_owned(),
                Value::String("cleanup_incomplete".to_owned()),
            );
            out.insert("retryable".to_owned(), Value::Bool(false));
            if let Some(remediation) = cleanup_remediation.clone() {
                out.insert("remediation".to_owned(), remediation);
            }
            let mut details = Map::new();
            details.insert("resources".to_owned(), Value::Array(Vec::new()));
            if let Some(existing) = projection.get("details").and_then(Value::as_object) {
                for (key, value) in existing {
                    details.insert(key.clone(), value.clone());
                }
            }
            details.insert("cleanup".to_owned(), Value::String("incomplete".to_owned()));
            let execution = projection
                .get("code")
                .cloned()
                .unwrap_or_else(|| Value::String("execution_failure".to_owned()));
            details.insert("execution_failure".to_owned(), execution);
            details.insert("cleanup_error".to_owned(), cleanup.clone());
            out.insert("details".to_owned(), Value::Object(details));
            return Value::Object(out);
        }
    }
    let mut out = Map::new();
    out.insert(
        "error".to_owned(),
        Value::String("Analysis failed".to_owned()),
    );
    if let Some(fields) = cleanup.as_object() {
        for (key, value) in fields {
            out.insert(key.clone(), value.clone());
        }
    }
    out.insert(
        "code".to_owned(),
        Value::String("cleanup_incomplete".to_owned()),
    );
    out.insert("retryable".to_owned(), Value::Bool(false));
    let mut details = Map::new();
    if let Some(existing) = cleanup_details {
        for (key, value) in existing {
            details.insert(key, value);
        }
    }
    details.insert("cleanup".to_owned(), Value::String("incomplete".to_owned()));
    details.insert("partial_observation".to_owned(), output);
    out.insert("details".to_owned(), Value::Object(details));
    Value::Object(out)
}

/// Normalize an invocation into success value or failure projection.
pub fn outcome(invocation: Invocation) -> Result<Value, Value> {
    match invocation {
        Invocation::Success(value) => Ok(value),
        Invocation::Failure(projection) => Err(projection),
        Invocation::UnknownTool => Err(crate::util::object([
            ("code", Value::String("execution_failure".to_owned())),
            ("category", Value::String("execution".to_owned())),
            (
                "message",
                Value::String(
                    "This operation is not available in the native runtime build.".to_owned(),
                ),
            ),
            ("retryable", Value::Bool(false)),
        ])),
    }
}

/// Open one target, run `body` against the open session, then always close.
/// `body` returns the primary success value or a failure projection.
pub fn run_custom<F>(runner: &Runner<'_>, path: &str, options: &OpenOptions, body: F) -> Value
where
    F: FnOnce(&Runner<'_>) -> Result<Value, Value>,
{
    let snapshot = options.snapshot.as_deref().map(absolute_caller_path);
    let snapshot_exists = snapshot
        .as_deref()
        .map(|path| Path::new(path).exists())
        .unwrap_or(false);

    let mut open = Map::new();
    open.insert("path".to_owned(), Value::String(absolute_caller_path(path)));
    if let (true, Some(snapshot)) = (snapshot_exists, snapshot.as_ref()) {
        open.insert("snapshot_path".to_owned(), Value::String(snapshot.clone()));
    }
    if let Some(provider) = &options.provider {
        open.insert("provider_id".to_owned(), Value::String(provider.clone()));
    }

    // An open failure leaves nothing to close; return it directly.
    if let Err(projection) = outcome(runner.invoke("open_binary", Value::Object(open))) {
        return cli_error(projection);
    }

    let result = body(runner);

    let mut close = Map::new();
    if let Some(snapshot) = &snapshot {
        close.insert("snapshot_path".to_owned(), Value::String(snapshot.clone()));
        close.insert("overwrite".to_owned(), Value::Bool(true));
    }
    let close_result = outcome(runner.invoke("close_binary", Value::Object(close)));

    match (result, close_result) {
        (Ok(value), Ok(_)) => value,
        (Ok(value), Err(cleanup)) => cleanup_failure(value, cleanup),
        (Err(error), Ok(_)) => cli_error(error),
        (Err(error), Err(cleanup)) => cleanup_failure(cli_error(error), cleanup),
    }
}

/// Open one binary, execute one tool, then always close it.
pub fn run_direct_analysis(
    runner: &Runner<'_>,
    path: &str,
    tool: &str,
    arguments: Value,
    options: &OpenOptions,
) -> Value {
    run_custom(runner, path, options, |runner| {
        outcome(runner.invoke(tool, arguments))
    })
}

/// Execute one provider-native operation with the open/close lifecycle and no
/// snapshot, mirroring `runProviderAnalysis`.
pub fn run_provider_analysis(
    runner: &Runner<'_>,
    path: &str,
    tool: &str,
    arguments: Value,
) -> Value {
    run_direct_analysis(runner, path, tool, arguments, &OpenOptions::default())
}
