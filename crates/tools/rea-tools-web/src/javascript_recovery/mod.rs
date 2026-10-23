//! Derived JavaScript source recovery over an externally configured Wakaru.
//!
//! Compatibility owners: `src/server/registerJavaScriptRecoveryTool.ts`,
//! `src/application/javascript/JavaScriptRecoveryService.ts`,
//! `src/application/javascript/JavaScriptRecoveryPort.ts`,
//! `src/domain/javascript/javascriptRecovery.ts` and
//! `src/javascript/recovery/*`.
//!
//! The advertised schema (frozen catalog) is validated and defaulted by the
//! registry before a handler runs, exactly like the original Zod parse. This
//! module ports the *service-level* refinements the TS service applies after
//! that parse (absolute-path and duplicate-selection checks) and the Wakaru
//! provider, which launches the externally configured command only through
//! `rea_host::process::launcher`. On any non-Linux/x64 host, or without an
//! absolute `REA_WAKARU_COMMAND`, the provider returns the exact typed
//! capability-unavailable error without launching anything.

mod command;
mod execution;
mod provider;
mod publication;
mod recovery_files;
mod release;
mod report;
mod snapshots;
mod version;

use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::Evidence;
use rea_mcp::{Registry, ToolContext};
use serde_json::Value;

pub(crate) const OPERATION: &str = "recover_javascript_sources";

/// Bind optional recovery to its exact named contract without acquiring an engine.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context, input| recover(context, input).into());
}

/// Shared CLI/MCP parsing and Evidence for derived JavaScript artifacts.
fn recover(context: &ToolContext<'_>, input: Value) -> Result<Evidence, AnalysisError> {
    // `AnalysisCancelledError(OPERATION)` when the caller already cancelled.
    context.check_cancelled()?;

    let parsed = ParsedInput::from_validated(&input);
    validate_selection(&parsed)?;

    let provider = provider::provider(context);
    let execution = provider.recover(context, &parsed)?;

    // The service rebinds the provider execution to its immutable input. On
    // this host the provider never returns a success execution (Wakaru is a
    // Linux-only external tool), so this projection is the Linux success path.
    execution.into_evidence(&parsed)
}

/// The advertised input after registry validation and default application.
pub(crate) struct ParsedInput {
    pub path: String,
    pub additional_paths: Vec<String>,
    pub output_directory: String,
    pub extraction_mode: String,
    pub rewrite_level: String,
    pub raw: Value,
}

impl ParsedInput {
    fn from_validated(input: &Value) -> Self {
        let object = input.as_object().cloned().unwrap_or_default();
        let string = |key: &str| {
            object
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let additional_paths = object
            .get("additional_paths")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| item.as_str().unwrap_or_default().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            path: string("path"),
            additional_paths,
            output_directory: string("output_directory"),
            // Defaults mirror the frozen schema's declared defaults.
            extraction_mode: object
                .get("extraction_mode")
                .and_then(Value::as_str)
                .unwrap_or("structural")
                .to_owned(),
            rewrite_level: object
                .get("rewrite_level")
                .and_then(Value::as_str)
                .unwrap_or("standard")
                .to_owned(),
            raw: Value::Object(object),
        }
    }

    /// `[path, ...additional_paths]` exactly as the TS service orders them.
    pub fn all_paths(&self) -> Vec<String> {
        let mut paths = Vec::with_capacity(1 + self.additional_paths.len());
        paths.push(self.path.clone());
        paths.extend(self.additional_paths.iter().cloned());
        paths
    }
}

/// Port of the TS service refinements that run after the schema parse.
fn validate_selection(parsed: &ParsedInput) -> Result<(), AnalysisError> {
    let mut issues: Vec<InputIssue> = Vec::new();

    // `["path", "output_directory"].filter((field) => !isAbsolute(...))`
    for (field, value) in [
        ("path", &parsed.path),
        ("output_directory", &parsed.output_directory),
    ] {
        if !is_absolute(value) {
            issues.push(InputIssue::new(
                &[field],
                "invalid_format",
                format!("{field} must be an absolute filesystem path on this host."),
            ));
        }
    }

    // `additional_paths.filter((additional) => !isAbsolute(additional))`
    for additional in &parsed.additional_paths {
        if !is_absolute(additional) {
            issues.push(InputIssue::new(
                &["additional_paths"],
                "invalid_format",
                format!(
                    "additional_paths entries must be absolute filesystem paths on this host: {additional}"
                ),
            ));
        }
    }

    if !issues.is_empty() {
        return Err(AnalysisError::input(OPERATION, issues));
    }

    // `new Set([path, ...additional].map(resolve)).size !== 1 + additional.length`
    let all = parsed.all_paths();
    let mut seen = std::collections::BTreeSet::new();
    let unique = all.iter().filter(|path| seen.insert(resolve(path))).count();
    if unique != all.len() {
        return Err(AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["additional_paths"],
                "invalid_format",
                "additional_paths must not repeat path or each other.",
            )],
        ));
    }

    Ok(())
}

/// Node `path.isAbsolute` for POSIX: a leading `/`.
pub(crate) fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// Node `path.resolve` for an already-absolute POSIX path: normalize `.`/`..`
/// and collapse separators without touching the (unused) process cwd.
pub(crate) fn resolve(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    if segments.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", segments.join("/"))
    }
}
