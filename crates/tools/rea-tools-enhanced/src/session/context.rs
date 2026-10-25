//! Navigation and address context composed from provider queries.
//!
//! Compatibility owner: `getNavigationContext` / `inspectAddressContext`
//! (`application/AnalysisContextQueries.ts`) and their registration in
//! `server/registerSessionTools.ts`.
use crate::analysis::Analysis;
use crate::analysis::is_capability_unavailable;
use crate::enhanced::overview::resolve_analysis_document;
use rea_analysis::AnalysisExecution;
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{ToolContext, ToolOutput};
use rea_tools_binary::port::with_admitted_analysis;
use serde_json::{Map, Value, json};

fn parameters(document: Option<&str>, address: Option<&str>) -> Map<String, Value> {
    let mut parameters = Map::new();
    if let Some(document) = document {
        parameters.insert("document".into(), json!(document));
    }
    if let Some(address) = address {
        parameters.insert("address".into(), json!(address));
    }
    parameters
}

fn text<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str)
}

/// Run `body` against the admitted provider port as a session tool.
fn admitted(
    context: &ToolContext<'_>,
    input: &Value,
    body: fn(&Analysis<'_>, &Value) -> Result<Value, AnalysisError>,
) -> ToolOutput {
    let result = with_admitted_analysis(
        context.session,
        context.name(),
        &context.cancellation,
        |port| {
            let analysis = Analysis::new(port, context.cancellation.clone(), None);
            body(&analysis, input)
        },
    );
    match result.and_then(|inner| inner) {
        Ok(value) => ToolOutput::Value(value),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// `isMissingCurrentProcedure`.
fn missing_current_procedure(error: &AnalysisError) -> bool {
    let message = error.message().to_lowercase();
    message.contains("no procedure exists") || message.contains("not in a procedure")
}

/// `containingProcedureName`.
fn containing_procedure_name(value: &Value) -> Value {
    if value.get("found") != Some(&Value::Bool(true)) {
        return Value::Null;
    }
    value
        .get("procedure")
        .and_then(|procedure| procedure.get("name"))
        .and_then(Value::as_str)
        .map_or(Value::Null, |name| json!(name))
}

fn unavailable_navigation_facet(
    operation: &str,
    error: &AnalysisError,
    remediation: &str,
) -> Value {
    json!({
        "state": "unavailable",
        "reason": error.message(),
        "operation": operation,
        "remediation": remediation,
    })
}

fn unavailable_procedure_facet(reason: &str) -> Value {
    json!({
        "state": "unavailable",
        "reason": reason,
        "operation": "resolve_containing_procedure",
        "remediation": "Provide an address explicitly or use a provider with cursor support.",
    })
}

fn navigation(analysis: &Analysis<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let document = match text(input, "document") {
        Some(document) => document.to_owned(),
        None => {
            let current = analysis.execute("current_document", &Map::new(), false)?;
            current.result.as_str().map(str::to_owned).ok_or_else(|| {
                AnalysisError::output("current_document", "expected a document identity string")
            })?
        }
    };
    let address = match analysis.execute("current_address", &Map::new(), false) {
        Ok(address) => {
            let Some(address) = address.result.as_str().map(str::to_owned) else {
                return Err(AnalysisError::output(
                    "current_address",
                    "expected an address string",
                ));
            };
            address
        }
        Err(error) if is_capability_unavailable(&error) => {
            return Ok(json!({
                "document": document,
                "address": unavailable_navigation_facet(
                    "current_address",
                    &error,
                    "Use get_navigation_context with an interactive provider, or provide an address to inspect_address_context.",
                ),
                "procedure": unavailable_procedure_facet(
                    "Containing procedure is unavailable because the provider did not expose a current address.",
                ),
            }));
        }
        Err(error) => return Err(error),
    };
    let procedure = match analysis.execute(
        "resolve_containing_procedure",
        &parameters(None, Some(&address)),
        false,
    ) {
        Ok(procedure) => containing_procedure_name(&procedure.result),
        Err(error) if missing_current_procedure(&error) => Value::Null,
        Err(error) => return Err(error),
    };
    Ok(json!({ "document": document, "address": address, "procedure": procedure }))
}

/// `get_navigation_context`.
pub fn get_navigation_context(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    admitted(context, &input, navigation)
}

/// `isRequestLevelFailure`.
fn request_level_failure(error: &AnalysisError) -> bool {
    matches!(
        error.tag(),
        "AnalysisCancelledError" | "AnalysisTimeoutError" | "NoBinaryOpenError"
    )
}

/// `facet`.
fn facet(result: &Result<AnalysisExecution, AnalysisError>, operation: &str) -> Value {
    match result {
        Ok(execution) => json!({ "state": "available", "value": execution.result }),
        Err(error) => json!({
            "state": "unavailable",
            "reason": error.message(),
            "remediation": format!("Call {operation} directly to inspect provider availability and diagnostics."),
        }),
    }
}

/// `resolvedAddress`.
fn resolved_address(result: &Result<AnalysisExecution, AnalysisError>, fallback: &str) -> String {
    result
        .as_ref()
        .ok()
        .and_then(|execution| execution.result.get("query_address"))
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

fn malformed_bookmarks(reason: &str) -> Value {
    json!({
        "state": "unavailable",
        "reason": reason,
        "remediation": "Retry list_bookmarks directly and report the provider output shape if it remains malformed.",
    })
}

/// `matchingBookmarks`: `analysisBookmarkSchema` is `{ address: string, name: string | null }`.
fn matching_bookmarks(value: &Value, address: &str) -> Value {
    let Some(bookmarks) = value.as_array() else {
        return malformed_bookmarks("list_bookmarks returned malformed output; expected an array.");
    };
    let valid = bookmarks.iter().all(|bookmark| {
        bookmark.get("address").is_some_and(Value::is_string)
            && bookmark
                .get("name")
                .is_some_and(|name| name.is_string() || name.is_null())
    });
    if !valid {
        return malformed_bookmarks(
            "list_bookmarks returned malformed entries; expected an address string and a string or null name.",
        );
    }
    let matching = bookmarks
        .iter()
        .filter(|bookmark| bookmark.get("address").and_then(Value::as_str) == Some(address))
        .map(|bookmark| json!({ "address": bookmark["address"], "name": bookmark["name"] }))
        .collect::<Vec<_>>();
    json!({ "state": "available", "value": matching })
}

fn address_context(analysis: &Analysis<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let address = text(input, "address").unwrap_or_default().to_owned();
    let document = match text(input, "document") {
        Some(document) => document.to_owned(),
        None => resolve_analysis_document(analysis)?,
    };
    let at_address = parameters(Some(&document), Some(&address));
    let operations = [
        "address_name",
        "resolve_containing_procedure",
        "comment",
        "inline_comment",
        "list_bookmarks",
    ];
    let results = operations
        .iter()
        .map(|operation| {
            let selected = if *operation == "list_bookmarks" {
                parameters(Some(&document), None)
            } else {
                at_address.clone()
            };
            analysis.execute(operation, &selected, false)
        })
        .collect::<Vec<_>>();
    if let Some(Err(error)) = results
        .iter()
        .find(|result| matches!(result, Err(error) if request_level_failure(error)))
    {
        return Err(error.clone());
    }
    let bookmarks = match &results[4] {
        Ok(execution) => {
            matching_bookmarks(&execution.result, &resolved_address(&results[1], &address))
        }
        failed => facet(failed, operations[4]),
    };
    Ok(json!({
        "address": address,
        "document": document,
        "name": facet(&results[0], operations[0]),
        "procedure": facet(&results[1], operations[1]),
        "comment": facet(&results[2], operations[2]),
        "inline_comment": facet(&results[3], operations[3]),
        "bookmarks": bookmarks,
    }))
}

/// `inspect_address_context`.
pub fn inspect_address_context(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    admitted(context, &input, address_context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_analysis::{AnalysisExecution, ExecutionOptions, ProviderIdentity};
    use rea_core::cancellation::Cancellation;
    use rea_tools_binary::port::AnalysisPort;

    struct StubPort {
        address: Result<Value, AnalysisError>,
    }

    impl AnalysisPort for StubPort {
        fn supports_operation(&self, _operation: &str) -> bool {
            true
        }

        fn execute(
            &self,
            operation: &str,
            parameters: &Map<String, Value>,
            _options: &ExecutionOptions,
        ) -> Result<AnalysisExecution, AnalysisError> {
            match operation {
                "current_document" => Ok(AnalysisExecution::new(
                    json!("/tmp/example.bin"),
                    ProviderIdentity::new("stub", "stub provider", None),
                )),
                "current_address" => {
                    if parameters.contains_key("document") {
                        return Err(AnalysisError::output(
                            operation,
                            "unknown_argument document",
                        ));
                    }
                    self.address
                        .as_ref()
                        .map(|value| {
                            AnalysisExecution::new(
                                value.clone(),
                                ProviderIdentity::new("stub", "stub provider", None),
                            )
                        })
                        .map_err(Clone::clone)
                }
                "resolve_containing_procedure" => {
                    if parameters.contains_key("document") {
                        return Err(AnalysisError::output(
                            operation,
                            "unknown_argument document",
                        ));
                    }
                    Ok(AnalysisExecution::new(
                        json!({
                            "found": true,
                            "procedure": {"name": "main"}
                        }),
                        ProviderIdentity::new("stub", "stub provider", None),
                    ))
                }
                _ => Err(AnalysisError::output(
                    operation,
                    "unexpected stub operation",
                )),
            }
        }
    }

    #[test]
    fn navigation_keeps_document_when_provider_has_no_cursor() {
        let error = AnalysisError::capability_unavailable(
            "ghidra-rust",
            "current_address",
            "The Rust provider has no UI cursor or current address.",
        );

        let port = StubPort {
            address: Err(error),
        };
        let analysis = Analysis::new(&port, Cancellation::default(), None);
        let result = navigation(&analysis, &json!({})).expect("capability gaps are partial");

        assert_eq!(result["document"], "/tmp/example.bin");
        assert_eq!(result["address"]["state"], "unavailable");
        assert_eq!(result["address"]["operation"], "current_address");
        assert_eq!(result["procedure"]["state"], "unavailable");
        assert_eq!(
            result["procedure"]["operation"],
            "resolve_containing_procedure"
        );
    }

    #[test]
    fn navigation_preserves_unexpected_cursor_failures() {
        let port = StubPort {
            address: Err(AnalysisError::output(
                "current_address",
                "cursor transport failed",
            )),
        };
        let analysis = Analysis::new(&port, Cancellation::default(), None);

        let error = navigation(&analysis, &json!({})).expect_err("unexpected failures propagate");
        assert_eq!(error.tag(), "AnalysisOutputError");
        assert!(error.message().contains("cursor transport failed"));
    }

    #[test]
    fn navigation_uses_each_provider_operation_parameter_contract() {
        let port = StubPort {
            address: Ok(json!("0x1000")),
        };
        let analysis = Analysis::new(&port, Cancellation::default(), None);

        let result = navigation(&analysis, &json!({})).expect("navigation succeeds");

        assert_eq!(result["document"], "/tmp/example.bin");
        assert_eq!(result["address"], "0x1000");
        assert_eq!(result["procedure"], "main");
    }
}
