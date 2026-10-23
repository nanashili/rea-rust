//! REA's native MCP server core.
//!
//! The frozen public contracts in `contracts/catalog/` are the single source
//! of truth for advertised tools, prompts and server identity. Tool families
//! register exact-name handlers; this crate owns validation, delivery, the
//! session Evidence ledger and the stdio transport.
pub mod catalog;
pub mod delivery;
pub mod prompts;
pub mod protocol;
pub mod registry;
pub mod schema;
pub mod session;
pub mod support;

use rea_core::analysis_error::{AnalysisError, SettingIssue};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

pub use catalog::{ToolContract, catalog};
pub use prompts::{CompletionProvider, NoCompletion};
pub use registry::{Progress, Registry, ToolContext, ToolHandler, ToolOutput};
pub use session::{Session, SessionResource};

const MINIMUM_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn configuration(setting: &str, constraint: &str) -> AnalysisError {
    AnalysisError::configuration(
        constraint,
        vec![SettingIssue {
            setting: setting.into(),
            constraint: constraint.into(),
        }],
    )
}

/// Parse REA_MCP_MAX_RESPONSE_BYTES exactly as the original configuration owner.
pub fn response_budget(
    environment: &HashMap<String, String>,
) -> Result<Option<usize>, AnalysisError> {
    let Some(value) = environment.get("REA_MCP_MAX_RESPONSE_BYTES") else {
        return Ok(None);
    };
    let constraint = format!(
        "REA_MCP_MAX_RESPONSE_BYTES must be a decimal safe integer at least {MINIMUM_RESPONSE_BYTES} bytes, the default stdio receive-buffer size."
    );
    let decimal = !value.is_empty()
        && !value.starts_with('0')
        && value.chars().all(|character| character.is_ascii_digit());
    match value.parse::<u64>() {
        Ok(bytes)
            if decimal && bytes <= MAX_SAFE_INTEGER && bytes >= MINIMUM_RESPONSE_BYTES as u64 =>
        {
            Ok(Some(bytes as usize))
        }
        _ => Err(configuration("REA_MCP_MAX_RESPONSE_BYTES", &constraint)),
    }
}

/// Parse REA_MCP_OUTPUT_SCHEMA_PROFILE (`full` default, or `off`).
pub fn include_output_schemas(
    environment: &HashMap<String, String>,
) -> Result<bool, AnalysisError> {
    match environment
        .get("REA_MCP_OUTPUT_SCHEMA_PROFILE")
        .map(String::as_str)
    {
        None | Some("full") => Ok(true),
        Some("off") => Ok(false),
        Some(_) => Err(configuration(
            "REA_MCP_OUTPUT_SCHEMA_PROFILE",
            "REA_MCP_OUTPUT_SCHEMA_PROFILE must be \"full\" (default) or \"off\". The off profile omits output schemas from tools/list while REA validates every successful result against its canonical tool contract and returns complete structured content.",
        )),
    }
}

/// Parse REA_MCP_INPUT_SCHEMA_PROFILE (`full` default, or `compact`).
pub fn compact_input_schemas(environment: &HashMap<String, String>) -> Result<bool, AnalysisError> {
    match environment
        .get("REA_MCP_INPUT_SCHEMA_PROFILE")
        .map(String::as_str)
    {
        None | Some("full") => Ok(false),
        Some("compact") => Ok(true),
        Some(_) => Err(configuration(
            "REA_MCP_INPUT_SCHEMA_PROFILE",
            "REA_MCP_INPUT_SCHEMA_PROFILE must be \"full\" (default) or \"compact\". The compact profile advertises bounded input schemas with fewer nested annotations for providers with schema compatibility constraints.",
        )),
    }
}

/// Every server-composition configuration check, in the original order.
pub fn validate_configuration(environment: &HashMap<String, String>) -> Result<(), AnalysisError> {
    response_budget(environment)?;
    include_output_schemas(environment)?;
    compact_input_schemas(environment)?;
    Ok(())
}

/// Composition supplied by the executable: every family's handlers and the
/// live completion source for prompt arguments.
pub trait Composition: Send + Sync {
    fn register(&self, registry: &mut Registry, session: &Arc<Session>);
    fn completion(&self, session: &Arc<Session>) -> Arc<dyn CompletionProvider>;
}

/// Build a server bound to a fresh session and the supplied composition.
pub fn build(
    sink: protocol::Sink,
    environment: HashMap<String, String>,
    composition: &dyn Composition,
) -> Result<Arc<protocol::Server>, AnalysisError> {
    let budget = response_budget(&environment)?;
    let include_output_schemas = include_output_schemas(&environment)?;
    let compact = compact_input_schemas(&environment)?;
    let session = Arc::new(Session::new(environment));
    let mut registry = Registry::default();
    composition.register(&mut registry, &session);
    let completion = composition.completion(&session);
    Ok(protocol::Server::new(
        Arc::new(registry),
        session,
        delivery::Delivery::new(budget),
        protocol::Profile {
            include_output_schemas,
            compact_input_schemas: compact,
        },
        completion,
        sink,
    ))
}

/// Outcome of one in-process tool invocation (used by the CLI).
#[derive(Debug)]
pub enum Invocation {
    /// The tool's success value: Evidence, or the plain (unwrapped) result.
    Success(Value),
    /// The caller-facing failure projection.
    Failure(Value),
    /// The tool is not in the catalog.
    UnknownTool,
}

/// Run one catalog tool in-process with the shared validation, handler and
/// Evidence retention, without MCP result framing.
pub fn invoke(
    registry: &Registry,
    session: &Arc<Session>,
    name: &str,
    arguments: Value,
    cancellation: rea_core::cancellation::Cancellation,
    progress: Progress,
) -> Invocation {
    let Some(contract) = catalog().tool(name) else {
        return Invocation::UnknownTool;
    };
    let input = match schema::validate(contract.input_schema(), &arguments) {
        Ok(input) => input,
        Err(issues) => {
            let issues = issues
                .into_iter()
                .map(|issue| rea_core::analysis_error::InputIssue {
                    path: issue.path.into_iter().map(Value::String).collect(),
                    reason: "invalid_value",
                    message: Some(issue.message),
                    expected: None,
                    minimum: None,
                    maximum: None,
                })
                .collect();
            return Invocation::Failure(AnalysisError::input(name, issues).project());
        }
    };
    let Some(handler) = registry.get(name) else {
        return Invocation::Failure(
            AnalysisError::capability_unavailable(
                "rea",
                name,
                "This operation is not available in the native runtime build.",
            )
            .project(),
        );
    };
    let context = ToolContext {
        contract,
        session,
        cancellation,
        progress,
    };
    match handler.call(&context, input) {
        ToolOutput::Evidence(evidence) => match session.record(&evidence) {
            Ok(()) => Invocation::Success(evidence.into_value()),
            Err(error) => Invocation::Failure(error.project()),
        },
        ToolOutput::Value(value) => Invocation::Success(value),
        ToolOutput::Raw(value) => {
            if value.get("isError") == Some(&Value::Bool(true)) {
                Invocation::Failure(
                    value
                        .get("structuredContent")
                        .and_then(|content| content.get("error"))
                        .cloned()
                        .unwrap_or(value),
                )
            } else {
                Invocation::Success(value.get("structuredContent").cloned().unwrap_or(value))
            }
        }
        ToolOutput::Failure(error) => {
            if let Some(partial) = &error.partial_observation
                && partial.get("evidence_id").is_some()
                && let Ok(raw) = serde_json::value::to_raw_value(partial)
            {
                let _ = session.record_raw(&raw);
            }
            Invocation::Failure(error.project())
        }
    }
}

/// Run the stdio MCP server until the client disconnects.
pub fn run_stdio(composition: &dyn Composition) -> i32 {
    let environment = std::env::vars().collect::<HashMap<_, _>>();
    if let Err(error) = validate_configuration(&environment) {
        eprintln!("{}", error.user_message());
        return 1;
    }
    protocol::serve_stdio(move |sink| {
        build(sink, environment, composition).expect("configuration validated before serving")
    })
}
