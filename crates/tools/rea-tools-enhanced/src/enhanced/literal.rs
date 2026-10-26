//! Literal feature tracing through provider string/procedure searches and xrefs.
//!
//! Compatibility owner: `traceLiteralFeature` (`EnhancedLiteralTracing.ts`).
use crate::analysis::{Analysis, is_capability_unavailable, params};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

const LITERAL_SEARCH_SOURCES: [(&str, &str); 2] = [
    ("search_strings", "string"),
    ("search_procedures", "procedure"),
];

struct TraceMatch {
    kind: &'static str,
    address: String,
    value: String,
}

fn literal_matches(
    analysis: &Analysis<'_>,
    query: &str,
    case_sensitive: bool,
) -> Result<Vec<TraceMatch>, AnalysisError> {
    let mut matches = Vec::new();
    let mut matched = HashSet::new();
    for (tool, kind) in LITERAL_SEARCH_SOURCES {
        let result = analysis.call(
            tool,
            &params([
                ("pattern", json!(query)),
                ("mode", json!("literal")),
                ("case_sensitive", json!(case_sensitive)),
            ]),
            false,
        )?;
        let invalid = || AnalysisError::output(tool, "provider returned an invalid search result");
        let Value::Array(items) = result else {
            return Err(invalid());
        };
        let mut page = Vec::with_capacity(items.len());
        for item in &items {
            match (item.get("address"), item.get("value")) {
                (Some(Value::String(address)), Some(Value::String(value))) if item.is_object() => {
                    page.push((address.clone(), value.clone()));
                }
                _ => return Err(invalid()),
            }
        }
        for (address, value) in page {
            if matched.insert((kind, address.clone())) {
                matches.push(TraceMatch {
                    kind,
                    address,
                    value,
                });
            }
        }
    }
    Ok(matches)
}

/// `traceLiteralFeature`.
pub fn trace_literal_feature(
    analysis: &Analysis<'_>,
    query: &str,
    case_sensitive: bool,
) -> Result<Value, AnalysisError> {
    let matches = literal_matches(analysis, query, case_sensitive)?;
    let mut references = Vec::new();
    let mut residual: Vec<String> = Vec::new();
    // A source address is resolved once however many matches reference it.
    let mut containing: HashMap<String, Value> = HashMap::new();
    for found in &matches {
        let observed =
            analysis.observe("xrefs", &params([("address", json!(found.address))]), false)?;
        // Only an explicit producer report of truncation is a coverage gap.
        let unknown = format!(
            "References to {} were truncated by the provider; additional references may exist.",
            found.address
        );
        if observed.references_truncated == Some(true) && !residual.contains(&unknown) {
            residual.push(unknown);
        }
        let Value::Array(sources) = &observed.result else {
            return Err(AnalysisError::output(
                "xrefs",
                "provider returned a non-array result",
            ));
        };
        for source in sources {
            let Value::String(source) = source else {
                return Err(AnalysisError::output(
                    "xrefs",
                    "provider returned a non-address value",
                ));
            };
            let procedure = match containing.get(source) {
                Some(procedure) => procedure.clone(),
                None => {
                    let resolved = analysis.call(
                        "resolve_containing_procedure",
                        &params([("address", json!(source))]),
                        false,
                    );
                    match resolved {
                        Ok(resolved) => {
                            containing.insert(source.clone(), resolved.clone());
                            resolved
                        }
                        Err(error) if is_capability_unavailable(&error) => {
                            let unknown = format!(
                                "Containing procedure for {source} is unavailable: {}",
                                error.user_message()
                            );
                            if !residual.contains(&unknown) {
                                residual.push(unknown);
                            }
                            containing.insert(source.clone(), Value::Null);
                            Value::Null
                        }
                        Err(error) => return Err(error),
                    }
                }
            };
            references.push(json!({
                "target_address": found.address,
                "source_address": source,
                "containing_procedure": procedure,
            }));
        }
    }
    let matches = matches
        .into_iter()
        .map(|found| json!({ "type": found.kind, "address": found.address, "value": found.value }))
        .collect::<Vec<_>>();
    Ok(json!({
        "query": query,
        "search_mode": "literal",
        "matches": matches,
        "references": references,
        "truncated": !residual.is_empty(),
        "residual_unknowns": residual,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_analysis::{AnalysisExecution, ExecutionOptions, ProviderIdentity};
    use rea_core::cancellation::Cancellation;
    use rea_tools_binary::port::AnalysisPort;
    use serde_json::Map;

    struct TracePort;

    impl AnalysisPort for TracePort {
        fn supports_operation(&self, _operation: &str) -> bool {
            true
        }

        fn execute(
            &self,
            operation: &str,
            parameters: &Map<String, Value>,
            _options: &ExecutionOptions,
        ) -> Result<AnalysisExecution, AnalysisError> {
            let result = match operation {
                "search_strings" => json!([{
                    "address": "0x2000",
                    "value": "needle"
                }]),
                "search_procedures" => json!([]),
                "xrefs" => {
                    assert_eq!(parameters["address"], "0x2000");
                    json!(["0x3000"])
                }
                "resolve_containing_procedure" => {
                    return Err(AnalysisError::capability_unavailable(
                        "stub",
                        operation,
                        "the mapped address is outside recovered procedure coverage",
                    ));
                }
                _ => return Err(AnalysisError::output(operation, "unexpected operation")),
            };

            Ok(AnalysisExecution::new(
                result,
                ProviderIdentity::new("stub", "stub provider", None),
            ))
        }
    }

    #[test]
    fn trace_preserves_reference_when_containing_procedure_is_unknown() {
        let analysis = Analysis::new(&TracePort, Cancellation::default(), None);

        let result = trace_literal_feature(&analysis, "needle", false).expect("trace succeeds");

        assert_eq!(result["references"][0]["source_address"], "0x3000");
        assert_eq!(result["references"][0]["containing_procedure"], Value::Null);
        assert_eq!(result["truncated"], true);
        assert_eq!(result["residual_unknowns"].as_array().unwrap().len(), 1);
        assert!(
            result["residual_unknowns"][0]
                .as_str()
                .unwrap()
                .contains("0x3000")
        );
    }

    #[test]
    fn trace_propagates_unexpected_containment_failures() {
        struct FailingPort;

        impl AnalysisPort for FailingPort {
            fn supports_operation(&self, _operation: &str) -> bool {
                true
            }

            fn execute(
                &self,
                operation: &str,
                _parameters: &Map<String, Value>,
                _options: &ExecutionOptions,
            ) -> Result<AnalysisExecution, AnalysisError> {
                if operation == "resolve_containing_procedure" {
                    return Err(AnalysisError::output(operation, "transport failed"));
                }
                let result = match operation {
                    "search_strings" => json!([{
                        "address": "0x2000",
                        "value": "needle"
                    }]),
                    "search_procedures" => json!([]),
                    "xrefs" => json!(["0x3000"]),
                    _ => return Err(AnalysisError::output(operation, "unexpected operation")),
                };
                Ok(AnalysisExecution::new(
                    result,
                    ProviderIdentity::new("stub", "stub provider", None),
                ))
            }
        }

        let analysis = Analysis::new(&FailingPort, Cancellation::default(), None);
        let error = trace_literal_feature(&analysis, "needle", false)
            .expect_err("unexpected containment failures propagate");

        assert!(matches!(
            error.kind,
            rea_core::analysis_error::ErrorKind::Output { .. }
        ));
        assert!(error.message().contains("transport failed"));
    }
}
