//! The SDK's text-only input validation failure for refinements the
//! advertised JSON Schema cannot express (Zod `superRefine` issues).

use rea_mcp::delivery::target_content_meta;
use rea_mcp::schema::{Issue, validation_error_text};
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, json};

/// Project refinement issues exactly like a schema validation failure.
pub fn refinement_failure(
    context: &ToolContext<'_>,
    issues: Vec<(Vec<String>, String)>,
) -> ToolOutput {
    let rendered = issues
        .into_iter()
        .map(|(path, message)| Issue { path, message })
        .collect::<Vec<_>>();
    let mut result = Map::new();
    result.insert(
        "content".into(),
        json!([{ "type": "text", "text": validation_error_text(context.name(), &rendered) }]),
    );
    result.insert("isError".into(), json!(true));
    if context.contract.returns_target_content {
        result.insert("_meta".into(), target_content_meta());
    }
    ToolOutput::Raw(serde_json::Value::Object(result))
}
