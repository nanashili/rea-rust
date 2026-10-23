//! Summary, matching tallies, coverage, side manifests, and the comparison's
//! own limitations.
//!
//! Compatibility owner: `src/domain/managed/managedMemberComparisonCoverage.ts`.
use super::signature::has_signature_resolution;
use serde_json::{Value, json};
use std::collections::HashSet;

/// Declaring-type selection of one side, or `None` when every type was read.
fn selection_names(result: &Value) -> Option<Vec<String>> {
    let selection = result.get("selection")?;
    if selection.is_null() {
        return None;
    }
    Some(
        selection
            .get("type_names")
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// `sameSelection(left, right)`: whether both observations inspected the same
/// declaring types.
fn same_selection(left: &Value, right: &Value) -> bool {
    match (selection_names(left), selection_names(right)) {
        (None, None) => true,
        (None, Some(_)) | (Some(_), None) => false,
        (Some(left_names), Some(right_names)) => {
            let right_set: HashSet<&str> = right_names.iter().map(String::as_str).collect();
            let left_set: HashSet<&str> = left_names.iter().map(String::as_str).collect();
            right_set.len() == left_set.len()
                && left_names
                    .iter()
                    .all(|name| right_set.contains(name.as_str()))
        }
    }
}

/// `sideCoverageStatus(result)`.
fn side_coverage_status(result: &Value) -> &'static str {
    match result
        .get("coverage")
        .and_then(|coverage| coverage.get("state"))
        .and_then(Value::as_str)
    {
        Some("unavailable") => "unavailable",
        Some("complete") => "complete",
        _ => "partial",
    }
}

fn coverage_state_complete(result: &Value) -> bool {
    result
        .get("coverage")
        .and_then(|coverage| coverage.get("state"))
        .and_then(Value::as_str)
        == Some("complete")
}

/// `buildComparisonCoverage({ left, right })`.
pub fn build_coverage(left: &Value, right: &Value) -> Value {
    let left_status = side_coverage_status(left);
    let right_status = side_coverage_status(right);
    let unknown_input = !coverage_state_complete(left)
        || !coverage_state_complete(right)
        || !same_selection(left, right);
    let status = if !unknown_input && left_status == "complete" && right_status == "complete" {
        "complete-within-inputs"
    } else {
        "partial"
    };
    json!({
        "status": status,
        "left_status": left_status,
        "right_status": right_status,
    })
}

/// `sideManifest(side)`.
pub fn side_manifest(evidence_id: &str, result: &Value) -> Value {
    let module = result.get("module");
    let mvid = module
        .and_then(|module| module.get("mvid"))
        .cloned()
        .unwrap_or(Value::Null);
    let module_name = module
        .and_then(|module| module.get("name"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "evidence_id": evidence_id,
        "artifact_sha256": result
            .get("artifact")
            .and_then(|artifact| artifact.get("sha256"))
            .cloned()
            .unwrap_or(Value::Null),
        "mvid": mvid,
        "module_name": module_name,
        "metadata_status": result
            .get("metadata")
            .and_then(|metadata| metadata.get("status"))
            .cloned()
            .unwrap_or(Value::Null),
        "methods_total": result.get("methods").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
        "fields_total": result.get("fields").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
    })
}

fn status_of(item: &Value) -> Option<&str> {
    item.get("status").and_then(Value::as_str)
}

fn match_basis(item: &Value) -> Option<&str> {
    item.get("match")
        .and_then(|m| m.get("basis"))
        .and_then(Value::as_str)
}

fn match_status(item: &Value) -> Option<&str> {
    item.get("match")
        .and_then(|m| m.get("status"))
        .and_then(Value::as_str)
}

/// `buildComparisonSummary(items)`.
pub fn build_summary(items: &[Value]) -> Value {
    let count = |want: &str| {
        items
            .iter()
            .filter(|item| status_of(item) == Some(want))
            .count()
    };
    json!({
        "unchanged": count("unchanged"),
        "changed": count("changed"),
        "added": count("added"),
        "removed": count("removed"),
        "unknown": count("unknown"),
    })
}

/// `buildComparisonMatching(methodItems, fieldItems)`.
pub fn build_matching(method_items: &[Value], field_items: &[Value]) -> Value {
    let exact_il_signature = method_items
        .iter()
        .filter(|item| match_basis(item) == Some("exact-il-signature"))
        .count();
    let exact_signature = method_items
        .iter()
        .chain(field_items.iter())
        .filter(|item| match_basis(item) == Some("exact-signature"))
        .count();
    let structural_method_shape = method_items
        .iter()
        .filter(|item| match_basis(item) == Some("structural-method-shape"))
        .count();
    let field_signature = field_items
        .iter()
        .filter(|item| match_basis(item) == Some("field-signature"))
        .count();
    let ambiguous = method_items
        .iter()
        .filter(|item| match_status(item) == Some("ambiguous"))
        .count()
        + field_items
            .iter()
            .filter(|item| match_status(item) == Some("ambiguous"))
            .count();
    let unmatched = method_items
        .iter()
        .chain(field_items.iter())
        .filter(|item| match_status(item) == Some("unmatched"))
        .count();
    json!({
        "exact_il_signature": exact_il_signature,
        "exact_signature": exact_signature,
        "structural_method_shape": structural_method_shape,
        "field_signature": field_signature,
        "ambiguous": ambiguous,
        "unmatched": unmatched,
    })
}

/// Whether a side's signatures name any type (resolved digest differs from raw).
fn names_types(result: &Value) -> bool {
    let any = |key: &str| {
        result
            .get(key)
            .and_then(Value::as_array)
            .map(|members| {
                members.iter().any(|member| {
                    let signature = member.get("signature");
                    let resolved = signature
                        .and_then(|signature| signature.get("resolved_sha256"))
                        .and_then(Value::as_str);
                    let raw = signature
                        .and_then(|signature| signature.get("raw_sha256"))
                        .and_then(Value::as_str);
                    matches!(resolved, Some(resolved) if Some(resolved) != raw)
                })
            })
            .unwrap_or(false)
    };
    any("methods") || any("fields")
}

/// `comparisonLimitations(left, right)`.
pub fn comparison_limitations(left: &Value, right: &Value) -> Vec<String> {
    let mut limitations: Vec<String> = vec![
        "Metadata tokens are build-local coordinates; matched pairs are remaps, not persistent identities.".to_owned(),
        "Methods pair within one declared type and name by exact CIL/signature, then signature, then structural shape; only then may exact CIL/signature or structural shape alone remap across declared types or names, never taking a member whose own declared type and name remain unpaired on the other side or whose declaring type is unresolved. Names alone are never a matching basis.".to_owned(),
        "Fields pair by declared type, name, and signature, then remap by exact decoded signature alone under the same rule; an undecoded signature is compared only for an exact signature match, and an unmatched member with one stays unknown.".to_owned(),
    ];

    if has_signature_resolution(left)
        && has_signature_resolution(right)
        && (names_types(left) || names_types(right))
    {
        limitations.push(
            "Signature type operands compare by namespace, name, and enclosing names only; defining assemblies and CLR type identity are not established by this comparison."
                .to_owned(),
        );
    }
    if !coverage_state_complete(left) || !coverage_state_complete(right) {
        limitations.push("At least one managed member observation is partial.".to_owned());
    }
    if !same_selection(left, right) {
        limitations.push(
            "The observations select different declaring types; a member outside the other side's selection is unknown, not added or removed."
                .to_owned(),
        );
    } else if let Some(names) = selection_names(left) {
        limitations.push(format!(
            "Both observations cover only the selected declaring types ({}); member totals and statuses describe those types, not the whole assembly.",
            names.join(", ")
        ));
    }
    if !has_signature_resolution(left) || !has_signature_resolution(right) {
        limitations.push(
            "At least one managed member observation does not attest signature type-name resolution, so signatures compare by raw bytes, which name types by build-local metadata row."
                .to_owned(),
        );
    }
    if left.get("nesting_read").map(Value::is_null).unwrap_or(true)
        || right
            .get("nesting_read")
            .map(Value::is_null)
            .unwrap_or(true)
    {
        limitations.push(
            "At least one managed member observation predates enclosing-name identity. The legacy bare-name comparison does not establish the enclosing owner of a nested type."
                .to_owned(),
        );
    }
    let exported_null = |result: &Value| {
        result
            .get("exported_types")
            .map(Value::is_null)
            .unwrap_or(true)
    };
    if exported_null(left) || exported_null(right) {
        limitations.push(
            "At least one managed member observation predates ExportedType inspection; its exported and forwarded types are unknown."
                .to_owned(),
        );
    }
    let exported_len = |result: &Value| {
        result
            .get("exported_types")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    };
    if exported_len(left) > 0 || exported_len(right) > 0 {
        limitations.push(
            "ExportedType rows, including type forwarders, are observed but not compared; an unchanged comparison does not establish an unchanged exported or forwarded type set."
                .to_owned(),
        );
    }
    limitations.push(
        "ldstr literals are not compared; normalized CIL keeps #US tokens rather than decoded text, so an unchanged method does not establish unchanged string literals."
            .to_owned(),
    );
    limitations
}
