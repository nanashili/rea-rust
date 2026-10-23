//! `#US` literals loaded by `ldstr` in the inspected method bodies.
//!
//! Port of `src/dotnet/ManagedUserStrings.ts`. The literals carry their own
//! coverage, which never enters member coverage. Issues are unique by
//! construction, so they are not deduplicated: each distinct token yields one
//! failure or per-offset conformance issues, and a missing stream is one issue.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::budget::admit_managed_projection;
use super::failure::{ManagedParseIssue, ReadError, ReadResult, read_managed_value};
use super::heaps::read_metadata_user_string;
use super::layout::ManagedMetadataLayout;
use super::method_body::Anchor;

/// Bookkeeping per distinct ldstr token.
const USER_STRING_TOKEN_BYTES: i64 = 128;

/// Build the `user_strings` inventory object in schema key order
/// (`state`, `literals`, `issues`).
fn inventory(literals: &[Value], issues: &[ManagedParseIssue], scanned: bool) -> Value {
    let state = if issues.is_empty() && scanned {
        "complete"
    } else {
        "partial"
    };
    let mut map = Map::new();
    map.insert("state".into(), Value::from(state));
    map.insert("literals".into(), Value::Array(literals.to_vec()));
    map.insert(
        "issues".into(),
        Value::Array(issues.iter().map(ManagedParseIssue::to_value).collect()),
    );
    Value::Object(map)
}

/// `parseUserStrings(bytes, layout, parsed)`.
///
/// `method_anchors` is one anchor list per inspected method, in method order.
pub fn parse_user_strings(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    method_anchors: &[Vec<Anchor>],
    unscanned_methods: i64,
    unreadable_selected_types: i64,
) -> ReadResult<Value> {
    let scanned = unscanned_methods == 0 && unreadable_selected_types == 0;
    let mut user_strings: Vec<Value> = Vec::new();
    let mut issues: Vec<ManagedParseIssue> = Vec::new();
    let mut tokens: BTreeSet<String> = BTreeSet::new();
    let outcome = (|| -> ReadResult<Value> {
        // Only ldstr loads a literal; a malformed ldtoken can carry a 0x70 token.
        for anchors in method_anchors {
            for anchor in anchors {
                if anchor.opcode == "ldstr" {
                    if let Some(operand) = &anchor.operand {
                        if !tokens.contains(operand) {
                            layout
                                .budget()
                                .admit_transient(USER_STRING_TOKEN_BYTES, None)?;
                            tokens.insert(operand.clone());
                        }
                    }
                }
            }
        }
        // Tokens are fixed-width lowercase hex, so string order is token order.
        // `BTreeSet` already yields ascending order equal to JS `sort()`.
        let mut references: Vec<String> = Vec::new();
        for token in tokens.iter() {
            if token.starts_with("0x70") {
                references.push(token.clone());
            } else {
                // An operand from another table names no #US item.
                let issue = ManagedParseIssue {
                    code: "invalid-heap-index",
                    scope: format!("metadata.#US:{token}"),
                    offset: None,
                    detail: "ldstr operand does not name an item inside #US".to_string(),
                };
                admit_managed_projection(&issue.to_value(), Some(&mut layout.budget()))?;
                issues.push(issue);
            }
        }
        if !references.is_empty() && layout.user_strings.is_none() {
            // A missing stream is one fact about the metadata, not one per token.
            let issue = ManagedParseIssue {
                code: "missing-stream",
                scope: "metadata.#US".to_string(),
                offset: None,
                detail: format!(
                    "{} distinct ldstr operand(s) reference #US, but the metadata has no #US stream",
                    references.len()
                ),
            };
            admit_managed_projection(&issue.to_value(), Some(&mut layout.budget()))?;
            issues.push(issue);
            return Ok(inventory(&user_strings, &issues, scanned));
        }
        for token in references.iter() {
            let mut failures: Vec<ManagedParseIssue> = Vec::new();
            // The read, its conformance issues, and the admitted literal all sit
            // inside `readManagedValue`; a non-resource reader failure is sunk
            // into `failures`, exactly as the TS passes `failures` to it.
            let produced = read_managed_value(
                || -> ReadResult<(Value, Vec<ManagedParseIssue>)> {
                    let read =
                        read_metadata_user_string(bytes, layout, token).map_err(ReadError::from)?;
                    let observed = read.issues.clone();
                    let mut map = Map::new();
                    map.insert("token".into(), Value::from(token.clone()));
                    map.insert("offset".into(), Value::from(read.offset));
                    map.insert("value".into(), Value::from(read.value));
                    let literal = Value::Object(map);
                    admit_managed_projection(&literal, Some(&mut layout.budget()))?;
                    Ok((literal, observed))
                },
                &mut failures,
            )?;
            if let Some((literal, observed)) = produced {
                for issue in observed {
                    failures.push(issue);
                }
                user_strings.push(literal);
            }
            for failure in &failures {
                admit_managed_projection(&failure.to_value(), Some(&mut layout.budget()))?;
                issues.push(failure.clone());
            }
        }
        Ok(inventory(&user_strings, &issues, scanned))
    })();
    layout.budget().release_transient();
    outcome
}
