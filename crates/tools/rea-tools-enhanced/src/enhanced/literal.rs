//! Literal feature tracing through provider string/procedure searches and xrefs.
//!
//! Compatibility owner: `traceLiteralFeature` (`EnhancedLiteralTracing.ts`).
use crate::analysis::{Analysis, params};
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
                    )?;
                    containing.insert(source.clone(), resolved.clone());
                    resolved
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
