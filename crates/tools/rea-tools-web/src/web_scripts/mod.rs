//! Offline JavaScript source export from retained browser captures.
mod capture;
mod errors;
mod export;
mod node;
mod plan;
mod publish;

use rea_mcp::{Registry, ToolOutput};
use serde_json::Value;

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(
        "export_web_scripts",
        |context, input: Value| match export::export(context, &input) {
            Ok(evidence) => ToolOutput::Evidence(evidence),
            Err(error) => ToolOutput::Failure(error),
        },
    );
}
