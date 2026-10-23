//! The eight function comparison dimensions.
//!
//! Compatibility owner: `functionComparisonDimensions.ts`.

use super::canonical::canonical_json;
use super::line_diff::diff_lines_delta;
use super::normalization::{
    comment_projection, identity_projection, is_auto_name, normalize_cfg, sorted,
    string_and_name_projection, swift_literal_sites_conflict,
};
use super::reference_comparison::compare_function_references;
use super::results::{
    DimensionResultInput, dimension_result, dimension_status, unresolved_dimension,
};
use super::snapshot::FunctionSnapshot;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

const OPERATION: &str = "Function comparison";
const MAX_EDIT_LENGTH: usize = 10_000;

/// Shared comparison context.
pub struct ComparisonContext<'a> {
    pub links: &'a [String],
    pub providers_differ: bool,
}

/// `compareDimensions`.
pub fn compare_dimensions(
    left: &FunctionSnapshot,
    right: &FunctionSnapshot,
    context: &ComparisonContext<'_>,
) -> Result<Vec<Value>, AnalysisError> {
    let results = vec![
        compare_identity(left, right, context)?,
        compare_text("pseudocode", pseudocode(left), pseudocode(right), context)?,
        compare_text("assembly", assembly(left), assembly(right), context)?,
        compare_comments(left, right, context)?,
        compare_calls(left, right, context)?,
        compare_references(left, right, context)?,
        compare_strings_and_names(left, right, context)?,
        compare_cfg(left, right, context)?,
    ];

    let mut out = Vec::with_capacity(results.len());
    for result in results {
        let dimension = result["dimension"].as_str().unwrap_or_default().to_owned();
        let static_dimension = dimension_name(&dimension);
        let mut facet: Vec<String> = Vec::new();
        for reason in facet_limitations(left, static_dimension) {
            facet.push(format!("Left: {reason}"));
        }
        for reason in facet_limitations(right, static_dimension) {
            facet.push(format!("Right: {reason}"));
        }
        if facet.is_empty() {
            out.push(result);
        } else {
            let mut limitations: Vec<String> = result["limitations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            limitations.extend(facet);
            out.push(unresolved_dimension(
                static_dimension,
                context.links,
                None,
                None,
                limitations,
            ));
        }
    }
    Ok(out)
}

fn dimension_name(name: &str) -> &'static str {
    match name {
        "identity" => "identity",
        "pseudocode" => "pseudocode",
        "assembly" => "assembly",
        "comments" => "comments",
        "calls" => "calls",
        "references" => "references",
        "strings_names" => "strings_names",
        "cfg" => "cfg",
        _ => "identity",
    }
}

fn pseudocode(snapshot: &FunctionSnapshot) -> String {
    snapshot.dossier["pseudocode"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn assembly(snapshot: &FunctionSnapshot) -> String {
    snapshot.dossier["assembly"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Number of Unicode code points (`[...text].length`).
fn code_point_len(text: &str) -> i64 {
    text.chars().count() as i64
}

/// `facetLimitations`.
fn facet_limitations(snapshot: &FunctionSnapshot, dimension: &str) -> Vec<String> {
    let dossier = &snapshot.dossier;
    let array_len = |key: &str| {
        dossier[key]
            .as_array()
            .map(|array| array.len())
            .unwrap_or(0)
    };
    let fields: Vec<(&str, usize)> = match dimension {
        "identity" => Vec::new(),
        "pseudocode" => vec![("pseudocode", pseudocode(snapshot).len())],
        "assembly" => vec![("assembly", array_len("assembly"))],
        "comments" => vec![("comments", array_len("comments"))],
        "calls" => vec![
            ("callers", array_len("callers")),
            ("callees", array_len("callees")),
        ],
        "references" => vec![(
            "references",
            array_len("incoming_references") + array_len("outgoing_references"),
        )],
        "strings_names" => {
            vec![(
                "strings_names",
                array_len("referenced_strings") + array_len("referenced_names"),
            )]
        }
        "cfg" => vec![("cfg", array_len("basic_blocks"))],
        _ => Vec::new(),
    };
    let availability = dossier.get("facet_availability");
    let mut out = Vec::new();
    for (field, count) in fields {
        let entry = availability.and_then(|value| value.get(field));
        if let Some(entry) = entry {
            if entry["available"] == Value::Bool(false) {
                out.push(format!(
                    "{field}: {}",
                    entry["reason"].as_str().unwrap_or_default()
                ));
            }
        } else if count == 0 {
            out.push(format!(
                "{field}: Provider did not declare coverage for this empty facet."
            ));
        }
    }
    out
}

const TEXT_LIMITATION: &str = "Exact provider text is compared without address or generated-name normalization; layout-only differences do not establish a behavior change.";
const ASSEMBLY_LIMITATION: &str =
    "Assembly is opaque provider text; relocation normalization is unavailable.";

fn compare_text(
    dimension: &'static str,
    left: String,
    right: String,
    context: &ComparisonContext<'_>,
) -> Result<Value, AnalysisError> {
    let mut limitations = vec![TEXT_LIMITATION.to_owned()];
    if dimension == "assembly" {
        limitations.push(ASSEMBLY_LIMITATION.to_owned());
    }
    if context.providers_differ {
        let mut lim = limitations.clone();
        lim.push("Exact text comparison requires one provider identity.".to_owned());
        return Ok(unresolved_dimension(
            dimension,
            context.links,
            Some(code_point_len(&left)),
            Some(code_point_len(&right)),
            lim,
        ));
    }
    match diff_lines_delta(&left, &right, MAX_EDIT_LENGTH) {
        None => {
            let mut lim = limitations.clone();
            lim.push("Bounded line diff exceeded its time or edit-distance limit.".to_owned());
            Ok(unresolved_dimension(
                dimension,
                context.links,
                Some(code_point_len(&left)),
                Some(code_point_len(&right)),
                lim,
            ))
        }
        Some(delta) => {
            let text_delta = json!({
                "added_lines": delta.added_lines,
                "removed_lines": delta.removed_lines,
                "hunks": delta.hunks,
            });
            let left_value = Value::String(left.clone());
            let right_value = Value::String(right.clone());
            dimension_result(DimensionResultInput {
                dimension,
                changed: delta.hunks != 0,
                left: &left_value,
                right: &right_value,
                links: context.links,
                providers_differ: context.providers_differ,
                left_count: Some(code_point_len(&left)),
                right_count: Some(code_point_len(&right)),
                text_delta,
                limitations,
            })
        }
    }
}

fn compare_comments(
    left: &FunctionSnapshot,
    right: &FunctionSnapshot,
    context: &ComparisonContext<'_>,
) -> Result<Value, AnalysisError> {
    let left_values = comment_projection(&left.dossier)?;
    let right_values = comment_projection(&right.dossier)?;
    match (left_values, right_values) {
        (Some(left_values), Some(right_values)) => compare_values(
            "comments",
            &json!(left_values),
            &json!(right_values),
            context,
            &[],
        ),
        _ => Ok(unresolved_dimension(
            "comments",
            context.links,
            Some(
                left.dossier["comments"]
                    .as_array()
                    .map(|a| a.len() as i64)
                    .unwrap_or(0),
            ),
            Some(
                right.dossier["comments"]
                    .as_array()
                    .map(|a| a.len() as i64)
                    .unwrap_or(0),
            ),
            vec!["Comment locations could not be normalized relative to the function.".to_owned()],
        )),
    }
}

fn swift_literal_coverage(snapshot: &FunctionSnapshot) -> &'static str {
    let omissions = snapshot.dossier["swift_string_literal_omissions"]
        .as_array()
        .map(|array| array.len())
        .unwrap_or(0);
    if omissions > 0 {
        "partial"
    } else if snapshot
        .dossier
        .get("swift_string_literals")
        .is_none_or(Value::is_null)
    {
        "absent"
    } else {
        "complete"
    }
}

fn compare_strings_and_names(
    left: &FunctionSnapshot,
    right: &FunctionSnapshot,
    context: &ComparisonContext<'_>,
) -> Result<Value, AnalysisError> {
    let left_coverage = swift_literal_coverage(left);
    let right_coverage = swift_literal_coverage(right);
    let complete = left_coverage == right_coverage && left_coverage != "partial";

    let left_values = string_and_name_projection(&left.dossier, complete)?;
    let right_values = string_and_name_projection(&right.dossier, complete)?;
    let (Some(left_values), Some(right_values)) = (left_values, right_values) else {
        return Ok(unresolved_dimension(
            "strings_names",
            context.links,
            None,
            None,
            vec![
                "Reference source locations could not be normalized to function offsets."
                    .to_owned(),
            ],
        ));
    };
    let compared = compare_values(
        "strings_names",
        &json!(left_values),
        &json!(right_values),
        context,
        &[],
    )?;
    if complete || dimension_status(&compared) == "changed" {
        return Ok(compared);
    }
    if swift_literal_sites_conflict(&left.dossier, &right.dossier)? {
        let left_all = string_and_name_projection(&left.dossier, true)?;
        let right_all = string_and_name_projection(&right.dossier, true)?;
        if let (Some(left_all), Some(right_all)) = (left_all, right_all) {
            return compare_values(
                "strings_names",
                &json!(left_all),
                &json!(right_all),
                context,
                &[],
            );
        }
    }
    Ok(unresolved_dimension(
        "strings_names",
        context.links,
        None,
        None,
        vec![
            "Swift String literal coverage differs or is partial; referenced strings and names match, and complete coverage does not establish a differing literal."
                .to_owned(),
        ],
    ))
}

fn compare_references(
    left: &FunctionSnapshot,
    right: &FunctionSnapshot,
    context: &ComparisonContext<'_>,
) -> Result<Value, AnalysisError> {
    let compared = compare_function_references(left, right)?;
    if compared.status == "unknown" {
        return Ok(unresolved_dimension(
            "references",
            context.links,
            Some(compared.left_count as i64),
            Some(compared.right_count as i64),
            compared.limitations,
        ));
    }
    // dimensionResult with { ...compared, ...context, textDelta: null }.
    let left_value = Value::Array(compared.left.clone().unwrap_or_default());
    let right_value = Value::Array(compared.right.clone().unwrap_or_default());
    dimension_result(DimensionResultInput {
        dimension: "references",
        changed: compared.status == "changed",
        left: &left_value,
        right: &right_value,
        links: context.links,
        providers_differ: context.providers_differ,
        left_count: Some(compared.left_count as i64),
        right_count: Some(compared.right_count as i64),
        text_delta: Value::Null,
        limitations: compared.limitations,
    })
}

fn compare_identity(
    left: &FunctionSnapshot,
    right: &FunctionSnapshot,
    context: &ComparisonContext<'_>,
) -> Result<Value, AnalysisError> {
    let left_name = left.dossier["procedure"]["name"]
        .as_str()
        .unwrap_or_default();
    let right_name = right.dossier["procedure"]["name"]
        .as_str()
        .unwrap_or_default();
    if is_auto_name(left_name) || is_auto_name(right_name) {
        return Ok(unresolved_dimension(
            "identity",
            context.links,
            None,
            None,
            vec![
                "Address-derived function names are not stable cross-version identity.".to_owned(),
            ],
        ));
    }
    compare_values(
        "identity",
        &identity_projection(&left.dossier),
        &identity_projection(&right.dossier),
        context,
        &[],
    )
}

fn compare_calls(
    left: &FunctionSnapshot,
    right: &FunctionSnapshot,
    context: &ComparisonContext<'_>,
) -> Result<Value, AnalysisError> {
    let left_values = call_projection(left);
    let right_values = call_projection(right);
    let mut coverage_limitations: Vec<String> = Vec::new();
    for reason in &left.call_coverage_blockers {
        coverage_limitations.push(format!("Left: {reason}"));
    }
    for reason in &right.call_coverage_blockers {
        coverage_limitations.push(format!("Right: {reason}"));
    }
    let mut coverage_diagnostics: Vec<String> = Vec::new();
    for reason in &left.call_coverage_diagnostics {
        coverage_diagnostics.push(format!("Left: {reason}"));
    }
    for reason in &right.call_coverage_diagnostics {
        coverage_diagnostics.push(format!("Right: {reason}"));
    }
    if !coverage_limitations.is_empty() {
        let mut lim = coverage_limitations;
        lim.extend(coverage_diagnostics);
        return Ok(unresolved_dimension(
            "calls",
            context.links,
            Some(left_values.len() as i64),
            Some(right_values.len() as i64),
            lim,
        ));
    }
    let any_auto = left_values
        .iter()
        .chain(right_values.iter())
        .any(|value| value["name"].as_str().is_some_and(is_auto_name));
    if any_auto {
        let mut lim =
            vec!["Address-derived callee or caller names cannot be matched safely.".to_owned()];
        lim.extend(coverage_diagnostics);
        return Ok(unresolved_dimension(
            "calls",
            context.links,
            Some(left_values.len() as i64),
            Some(right_values.len() as i64),
            lim,
        ));
    }
    compare_values(
        "calls",
        &Value::Array(sorted(left_values)?),
        &Value::Array(sorted(right_values)?),
        context,
        &coverage_diagnostics,
    )
}

fn call_projection(snapshot: &FunctionSnapshot) -> Vec<Value> {
    let mut values = Vec::new();
    for caller in snapshot.dossier["callers"].as_array().into_iter().flatten() {
        values.push(json!({ "direction": "in", "name": caller["name"] }));
    }
    for callee in snapshot.dossier["callees"].as_array().into_iter().flatten() {
        values.push(json!({ "direction": "out", "name": callee["name"] }));
    }
    values
}

fn compare_cfg(
    left: &FunctionSnapshot,
    right: &FunctionSnapshot,
    context: &ComparisonContext<'_>,
) -> Result<Value, AnalysisError> {
    let empty: Vec<Value> = Vec::new();
    let left_blocks = left.dossier["basic_blocks"].as_array().unwrap_or(&empty);
    let right_blocks = right.dossier["basic_blocks"].as_array().unwrap_or(&empty);
    let left_graph = normalize_cfg(left_blocks);
    let right_graph = normalize_cfg(right_blocks);
    match (left_graph, right_graph) {
        (Some(left_graph), Some(right_graph)) => {
            compare_values("cfg", &json!(left_graph), &json!(right_graph), context, &[])
        }
        _ => Ok(unresolved_dimension(
            "cfg",
            context.links,
            Some(left_blocks.len() as i64),
            Some(right_blocks.len() as i64),
            vec!["CFG addresses could not be normalized to local block indices.".to_owned()],
        )),
    }
}

fn compare_values(
    dimension: &'static str,
    left: &Value,
    right: &Value,
    context: &ComparisonContext<'_>,
    limitations: &[String],
) -> Result<Value, AnalysisError> {
    let left_json = canonical_json(left, OPERATION)?;
    let right_json = canonical_json(right, OPERATION)?;
    let left_count = left.as_array().map(|array| array.len() as i64);
    let right_count = right.as_array().map(|array| array.len() as i64);
    dimension_result(DimensionResultInput {
        dimension,
        changed: left_json != right_json,
        left,
        right,
        links: context.links,
        providers_differ: context.providers_differ,
        left_count,
        right_count,
        text_delta: Value::Null,
        limitations: limitations.to_vec(),
    })
}
