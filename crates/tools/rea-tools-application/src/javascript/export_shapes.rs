//! `compare_javascript_export_shapes`.
//!
//! Compatibility owners:
//! `src/server/registerApplicationTools/compareExportShapes.ts`,
//! `compareJavaScriptExportShapesEvidenceValidated` and
//! `src/domain/javascript/javascriptExportShape*.ts`.
use super::js::{array, canonical, digest, text, unique_sorted};
use super::{graph_evidence, workflow_evidence};
use crate::support;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::Evidence;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const OPERATION: &str = "compare_javascript_export_shapes";

pub fn register(registry: &mut Registry) {
    registry.handle(OPERATION, handle);
}

fn handle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let resolved =
        graph_evidence::resolve_evidence_input(context, &input["left"]).and_then(|left| {
            graph_evidence::resolve_evidence_input(context, &input["right"])
                .map(|right| (left, right))
        });
    let (left, right) = match resolved {
        Ok(pair) => pair,
        Err(error) => return ToolOutput::Failure(error),
    };
    let evidence = compare(&left, &right, &input);
    support::deliver_with_unknown(context.session, &[left, right], evidence, |evidence| {
        let result = &evidence.value()["normalized_result"];
        let unknown = result["summary"]["unknown"].as_u64().unwrap_or(0) > 0
            || result["coverage"]["status"] != "complete-within-inputs";
        unknown.then(|| support::comparison_unknown(evidence, "javascript-export-shape"))
    })
}

fn compare(left: &Value, right: &Value, input: &Value) -> Result<Evidence, AnalysisError> {
    if left["evidence_id"] == right["evidence_id"] {
        return Err(AnalysisError::input(
            OPERATION,
            vec![InputIssue {
                path: vec![json!("right")],
                reason: "invalid_value",
                message: Some("JavaScript export shape Evidence must be distinct".into()),
                expected: None,
                minimum: None,
                maximum: None,
            }],
        ));
    }
    let left_source = graph_evidence::parse_application_graph_evidence(left, &[json!("left")])
        .map_err(|issues| graph_evidence::input_error(OPERATION, issues))?;
    let right_source = graph_evidence::parse_application_graph_evidence(right, &[json!("right")])
        .map_err(|issues| graph_evidence::input_error(OPERATION, issues))?;
    let side = |source: &graph_evidence::GraphSource, prefix: &str| Side {
        evidence_id: source.evidence_id().to_owned(),
        graph: source.graph.clone(),
        module_path: text(input, &format!("{prefix}_module_path")).to_owned(),
        export_name: text(input, &format!("{prefix}_export_name")).to_owned(),
    };
    let left_side = side(&left_source, "left");
    let right_side = side(&right_source, "right");
    let result = compare_sides(&left_side, &right_side).map_err(|message| {
        AnalysisError::protocol(format!(
            "JavaScript application workflow failed while producing {OPERATION}: {message}"
        ))
    })?;
    workflow_evidence::create(
        "rea.javascript-export-shape-comparison",
        OPERATION,
        json!({
            "left_evidence_id": left_side.evidence_id,
            "right_evidence_id": right_side.evidence_id,
            "left_module_path": left_side.module_path,
            "left_export_name": left_side.export_name,
            "right_module_path": right_side.module_path,
            "right_export_name": right_side.export_name,
        }),
        result,
    )
}

struct Side {
    evidence_id: String,
    graph: Value,
    module_path: String,
    export_name: String,
}

struct Selected {
    selection: Value,
    projection: Option<Value>,
    observation_complete: bool,
    limitations: Vec<String>,
}

impl Selected {
    fn status(&self) -> &str {
        text(&self.selection, "status")
    }
    fn coverage(&self) -> Option<&Value> {
        self.projection
            .as_ref()
            .map(|projection| &projection["return_shape_coverage"])
    }
    fn shapes(&self) -> &[Value] {
        self.projection.as_ref().map_or(&[][..], |projection| {
            array(&projection["static_return_shapes"])
        })
    }
}

fn compare_sides(left_side: &Side, right_side: &Side) -> Result<Value, String> {
    let left = select(left_side);
    let right = select(right_side);
    let pairing = pair_variants(left.shapes(), right.shapes())?;
    let links = [
        left_side.evidence_id.clone(),
        right_side.evidence_id.clone(),
    ];
    let mut changes = build_changes(&left, &right, &pairing, &links)?;
    // sortChanges
    let mut keyed = Vec::with_capacity(changes.len());
    for (index, change) in changes.drain(..).enumerate() {
        let key = canonical(&json!({
            "discriminant": change["discriminant"],
            "path": change["path"],
            "status": change["status"],
            "left_source_range": change["left_source_range"],
            "right_source_range": change["right_source_range"],
            "change_id": change["change_id"],
        }))?;
        keyed.push((key, index, change));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let changes: Vec<Value> = keyed.into_iter().map(|(_, _, change)| change).collect();
    let inventories = inventories(&pairing, left.shapes(), right.shapes());
    // comparisonCoverage
    let omitted_candidates = left.selection["omitted_candidates"].as_u64().unwrap_or(0)
        + right.selection["omitted_candidates"].as_u64().unwrap_or(0);
    let truncated =
        omitted_candidates > 0 || projection_truncated(&left) || projection_truncated(&right);
    let partial = selection_partial(&left)
        || selection_partial(&right)
        || left_side.graph["coverage"]["status"] != "complete"
        || right_side.graph["coverage"]["status"] != "complete"
        || partial_property_coverage(left.shapes())
        || partial_property_coverage(right.shapes())
        || !pairing.unpaired_left.is_empty()
        || !pairing.unpaired_right.is_empty()
        || changes.iter().any(|change| change["status"] == "unknown");
    let status = if truncated {
        "truncated"
    } else if partial {
        "partial"
    } else {
        "complete-within-inputs"
    };
    let source_field = |selected: &Selected, key: &str, fallback: Value| {
        selected
            .coverage()
            .map_or(fallback, |coverage| coverage[key].clone())
    };
    let coverage = json!({
        "status": status,
        "left_graph_status": left_side.graph["coverage"]["status"],
        "right_graph_status": right_side.graph["coverage"]["status"],
        "paired_variants": pairing.pairs.len(),
        "unpaired_left_variants": pairing.unpaired_left.len(),
        "unpaired_right_variants": pairing.unpaired_right.len(),
        "omitted_left_variants": 0,
        "omitted_right_variants": 0,
        "left_source_omitted_variants": source_field(&left, "omitted_return_sites", Value::Null),
        "right_source_omitted_variants": source_field(&right, "omitted_return_sites", Value::Null),
        "left_omitted_fields": source_field(&left, "omitted_fields", json!(0)),
        "right_omitted_fields": source_field(&right, "omitted_fields", json!(0)),
        "left_omitted_property_coverage": source_field(&left, "omitted_property_coverage", json!(0)),
        "right_omitted_property_coverage": source_field(&right, "omitted_property_coverage", json!(0)),
        "omitted_candidates": omitted_candidates,
        "omitted_changes": 0,
    });
    let mut limitations: Vec<String> = vec![
        "Return shapes are inferred from inert syntax and do not prove runtime behavior.".into(),
        "Return variants are paired only by unique exact literal discriminants, never by source order.".into(),
        "Dynamic values, incomplete object coverage, and ambiguous variants remain unknown.".into(),
        "This static comparison cannot establish runtime semantics; run behavioral probes directly against the relevant application versions when that evidence is required.".into(),
    ];
    limitations.extend(left.limitations.iter().cloned());
    limitations.extend(right.limitations.iter().cloned());
    if status == "truncated" {
        limitations.push(
            "Comparison output or source return-shape recovery reached an explicit limit.".into(),
        );
    }
    if status == "partial" {
        limitations.push(
            "At least one selector, graph, return shape, or property boundary is incomplete."
                .into(),
        );
    }
    let count = |status: &str| {
        changes
            .iter()
            .filter(|change| change["status"] == status)
            .count()
    };
    let mut semantic = Map::new();
    semantic.insert("left".into(), left.selection.clone());
    semantic.insert("right".into(), right.selection.clone());
    semantic.insert("property_inventories".into(), json!(inventories));
    semantic.insert(
        "summary".into(),
        json!({"added": count("added"), "removed": count("removed"), "changed": count("changed"), "unknown": count("unknown")}),
    );
    semantic.insert("changes".into(), json!(changes));
    semantic.insert("coverage".into(), coverage);
    semantic.insert("evidence_links".into(), json!(links));
    semantic.insert("limitations".into(), json!(unique_sorted(limitations)));
    let id = format!("jesc_{}", digest(&Value::Object(semantic.clone()))?);
    semantic.insert("comparison_id".into(), json!(id));
    Ok(Value::Object(semantic))
}

fn projection_truncated(selected: &Selected) -> bool {
    selected.coverage().is_some_and(|coverage| {
        coverage["status"] == "truncated"
            || coverage["omitted_fields"].as_u64().unwrap_or(0) > 0
            || coverage["omitted_property_coverage"].as_u64().unwrap_or(0) > 0
            || coverage["projection_complete"] == false
    })
}

fn selection_partial(selected: &Selected) -> bool {
    selected.status() != "selected"
        || !selected.observation_complete
        || selected.coverage().is_none_or(|coverage| {
            coverage["status"] != "complete" || coverage["projection_complete"] != true
        })
}

// ---------------------------------------------------------------------------
// Selection (`javascriptExportShapeSelection.ts`)
// ---------------------------------------------------------------------------

struct Candidate<'a> {
    node: &'a Value,
    module_path: &'a str,
    export_name: &'a str,
    trusted: bool,
}

fn select(side: &Side) -> Selected {
    let mut candidates: Vec<Candidate<'_>> = Vec::new();
    let mut index: HashMap<(&str, &str, &str), usize> = HashMap::new();
    for node in array(&side.graph["nodes"]) {
        for observation in array(&node["observations"]) {
            let properties = &observation["properties"];
            if properties["semantic_role"] != "export-binding" {
                continue;
            }
            let (Some(module_path), Some(export_name)) = (
                properties["module_path"].as_str(),
                properties["exported_name"].as_str(),
            ) else {
                continue;
            };
            let evidence = &observation["evidence"];
            let trusted = evidence["authority"] == "ast-static-analysis"
                && evidence["state"] == "observed"
                && evidence["extractor"]["operation"] == "recover-module-export";
            let key = (text(node, "node_id"), module_path, export_name);
            match index.get(&key) {
                Some(&position) => candidates[position].trusted |= trusted,
                None => {
                    index.insert(key, candidates.len());
                    candidates.push(Candidate {
                        node,
                        module_path,
                        export_name,
                        trusted,
                    });
                }
            }
        }
    }
    candidates.sort_by(|left, right| {
        (
            left.module_path,
            left.export_name,
            text(left.node, "node_id"),
        )
            .cmp(&(
                right.module_path,
                right.export_name,
                text(right.node, "node_id"),
            ))
    });
    let exact: Vec<&Candidate<'_>> = candidates
        .iter()
        .filter(|candidate| {
            candidate.module_path == side.module_path && candidate.export_name == side.export_name
        })
        .collect();
    let one: Vec<&Candidate<'_>> = candidates
        .iter()
        .filter(|candidate| {
            candidate.module_path == side.module_path || candidate.export_name == side.export_name
        })
        .collect();
    let pool: Vec<&Candidate<'_>> = if !exact.is_empty() {
        exact.clone()
    } else if !one.is_empty() {
        one
    } else {
        candidates.iter().collect()
    };
    let mut base = Map::new();
    base.insert("evidence_id".into(), json!(side.evidence_id));
    base.insert("graph_id".into(), side.graph["graph_id"].clone());
    base.insert("requested_module_path".into(), json!(side.module_path));
    base.insert("requested_export_name".into(), json!(side.export_name));
    base.insert(
        "candidates".into(),
        Value::Array(
            pool.iter()
                .map(|candidate| {
                    json!({
                        "node_id": candidate.node["node_id"],
                        "module_path": candidate.module_path,
                        "export_name": candidate.export_name,
                        "matches_requested_module": candidate.module_path == side.module_path,
                        "matches_requested_export": candidate.export_name == side.export_name,
                    })
                })
                .collect(),
        ),
    );
    base.insert("omitted_candidates".into(), json!(0));
    let unresolved = |status: &str, selected: Value, limitation: String| {
        let mut selection = base.clone();
        selection.insert("status".into(), json!(status));
        selection.insert("selected_node_id".into(), selected);
        Selected {
            selection: Value::Object(selection),
            projection: None,
            observation_complete: false,
            limitations: vec![limitation],
        }
    };
    let label = format!("{}:{}", side.module_path, side.export_name);
    if exact.is_empty() {
        return unresolved(
            "missing",
            Value::Null,
            format!("No exact export binding matched {label}."),
        );
    }
    if exact.len() > 1 {
        return unresolved(
            "ambiguous",
            Value::Null,
            format!("Multiple exact export bindings matched {label}; none was selected."),
        );
    }
    let selected = exact[0];
    if !selected.trusted {
        return unresolved(
            "unavailable",
            selected.node["node_id"].clone(),
            "The exact export binding lacks the expected static-analysis authority.".into(),
        );
    }
    match return_shape(selected.node, side) {
        Err(reason) => unresolved(
            "unavailable",
            selected.node["node_id"].clone(),
            reason.into(),
        ),
        Ok((projection, observation_complete)) => {
            let mut selection = base;
            selection.insert("status".into(), json!("selected"));
            selection.insert("selected_node_id".into(), selected.node["node_id"].clone());
            Selected {
                selection: Value::Object(selection),
                projection: Some(projection),
                observation_complete,
                limitations: Vec::new(),
            }
        }
    }
}

fn return_shape(node: &Value, side: &Side) -> Result<(Value, bool), &'static str> {
    let observations: Vec<&Value> = array(&node["observations"])
        .iter()
        .filter(|observation| observation["properties"]["semantic_role"] == "export-return-shapes")
        .collect();
    if observations
        .iter()
        .any(|observation| !valid_projection(&observation["properties"]))
    {
        return Err("The export return-shape observation is malformed.");
    }
    let matching: Vec<&&Value> = observations
        .iter()
        .filter(|observation| {
            observation["properties"]["module_path"] == side.module_path.as_str()
                && observation["properties"]["exported_name"] == side.export_name.as_str()
        })
        .collect();
    if matching.len() != 1 {
        return Err(if matching.is_empty() {
            "No exact static return-shape observation is available for the selected export."
        } else {
            "Multiple static return-shape observations matched the selected export."
        });
    }
    let observation = matching[0];
    let evidence = &observation["evidence"];
    if !(evidence["authority"] == "static-relationship-inference"
        && evidence["state"] == "inferred"
        && evidence["extractor"]["operation"] == "recover-export-return-shapes")
    {
        return Err("The return-shape observation lacks the expected static-inference authority.");
    }
    Ok((
        observation["properties"].clone(),
        evidence["coverage"]["status"] == "complete" && evidence["coverage"]["truncated"] != true,
    ))
}

// ---------------------------------------------------------------------------
// `projectedExportReturnShapesSchema.safeParse`
// ---------------------------------------------------------------------------

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn is_json_pointer(value: &Value) -> bool {
    let Some(value) = value.as_str() else {
        return false;
    };
    if value.is_empty() {
        return true;
    }
    if !value.starts_with('/') {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if !matches!(bytes.get(index + 1), Some(b'0' | b'1')) {
                return false;
            }
            index += 1;
        }
        index += 1;
    }
    true
}

fn is_count(value: &Value) -> bool {
    value
        .as_f64()
        .is_some_and(|number| number >= 0.0 && number.fract() == 0.0)
}

fn is_text(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.is_empty())
}

fn is_primitive(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::String(_) | Value::Number(_)
    )
}

fn valid_point(value: &Value, minimum_line: f64) -> bool {
    exact_keys(value, &["line", "column"])
        && value["line"]
            .as_f64()
            .is_some_and(|line| line >= minimum_line && line.fract() == 0.0)
        && is_count(&value["column"])
}

fn valid_range(value: &Value) -> bool {
    if !(exact_keys(value, &["start", "end"])
        && valid_point(&value["start"], 1.0)
        && valid_point(&value["end"], 1.0))
    {
        return false;
    }
    let (start, end) = (&value["start"], &value["end"]);
    let line = |point: &Value| point["line"].as_f64().unwrap_or(0.0);
    let column = |point: &Value| point["column"].as_f64().unwrap_or(0.0);
    !(line(end) < line(start) || (line(end) == line(start) && column(end) < column(start)))
}

fn valid_field(field: &Value) -> bool {
    if !exact_keys(field, &["path", "presence", "state", "value", "reason"])
        || !is_json_pointer(&field["path"])
        || !matches!(
            field["presence"].as_str(),
            Some("present" | "absent" | "unknown-coverage")
        )
    {
        return false;
    }
    match field["state"].as_str() {
        Some("literal") => is_primitive(&field["value"]) && field["reason"].is_null(),
        Some("union") => {
            field["value"]
                .as_array()
                .is_some_and(|values| !values.is_empty() && values.iter().all(is_primitive))
                && field["reason"].is_null()
        }
        Some("unknown") => field["value"].is_null() && is_text(&field["reason"]),
        _ => false,
    }
}

fn valid_property_coverage(coverage: &Value) -> bool {
    exact_keys(coverage, &["path", "status", "omitted"])
        && is_json_pointer(&coverage["path"])
        && match coverage["status"].as_str() {
            Some("complete") => coverage["omitted"].as_f64() == Some(0.0),
            Some("partial") => {
                coverage["omitted"].is_null()
                    || coverage["omitted"]
                        .as_f64()
                        .is_some_and(|n| n > 0.0 && n.fract() == 0.0)
            }
            _ => false,
        }
}

fn unique_paths(values: &[Value]) -> bool {
    let mut seen = HashSet::new();
    values.iter().all(|value| seen.insert(text(value, "path")))
}

fn valid_shape(shape: &Value) -> bool {
    exact_keys(
        shape,
        &[
            "source_range",
            "value_status",
            "fields",
            "property_coverage",
        ],
    ) && valid_range(&shape["source_range"])
        && matches!(
            shape["value_status"].as_str(),
            Some("literal" | "union" | "object" | "array" | "unknown" | "ambiguous" | "cycle")
        )
        && shape["fields"]
            .as_array()
            .is_some_and(|fields| fields.iter().all(valid_field) && unique_paths(fields))
        && shape["property_coverage"]
            .as_array()
            .is_some_and(|coverage| {
                coverage.iter().all(valid_property_coverage) && unique_paths(coverage)
            })
}

fn valid_projection(properties: &Value) -> bool {
    let coverage = &properties["return_shape_coverage"];
    exact_keys(
        properties,
        &[
            "semantic_role",
            "module_path",
            "exported_name",
            "callable_id",
            "callable_kind",
            "static_return_shapes",
            "return_shape_coverage",
        ],
    ) && properties["semantic_role"] == "export-return-shapes"
        && is_text(&properties["module_path"])
        && properties["exported_name"].is_string()
        && is_text(&properties["callable_id"])
        && matches!(
            properties["callable_kind"].as_str(),
            Some("function" | "class" | "method")
        )
        && properties["static_return_shapes"]
            .as_array()
            .is_some_and(|shapes| shapes.iter().all(valid_shape))
        && exact_keys(
            coverage,
            &[
                "status",
                "retained_return_sites",
                "omitted_return_sites",
                "omitted_fields",
                "omitted_property_coverage",
                "projection_complete",
            ],
        )
        && matches!(
            coverage["status"].as_str(),
            Some("complete" | "partial" | "truncated")
        )
        && is_count(&coverage["retained_return_sites"])
        && (coverage["omitted_return_sites"].is_null()
            || is_count(&coverage["omitted_return_sites"]))
        && is_count(&coverage["omitted_fields"])
        && is_count(&coverage["omitted_property_coverage"])
        && coverage["projection_complete"].is_boolean()
        && coverage["retained_return_sites"].as_f64()
            == Some(array(&properties["static_return_shapes"]).len() as f64)
}

// ---------------------------------------------------------------------------
// Variants (`javascriptExportShapeVariants.ts`)
// ---------------------------------------------------------------------------

struct Pair {
    left: usize,
    right: usize,
    discriminant: Value,
}

struct Pairing {
    pairs: Vec<Pair>,
    unpaired_left: Vec<usize>,
    unpaired_right: Vec<usize>,
}

fn field_presence(shape: &Value, field: Option<&Value>, path: &str) -> String {
    if let Some(field) = field {
        return text(field, "presence").to_owned();
    }
    let parent = if path.is_empty() {
        None
    } else {
        path.rfind('/').map(|separator| &path[..separator])
    };
    let complete = parent.is_some_and(|parent| {
        array(&shape["property_coverage"])
            .iter()
            .any(|coverage| coverage["path"] == parent && coverage["status"] == "complete")
    });
    if complete {
        "absent"
    } else {
        "unknown-coverage"
    }
    .to_owned()
}

fn literal_value(field: &Value) -> Option<&Value> {
    (field["state"] == "literal" && is_primitive(&field["value"])).then_some(&field["value"])
}

fn occurrences(shapes: &[Value]) -> Result<Vec<(String, Value, Vec<usize>)>, String> {
    // Map insertion order (first occurrence) is retained as the original Map.
    let mut output: Vec<(String, Value, Vec<usize>)> = Vec::new();
    let mut positions: HashMap<String, usize> = HashMap::new();
    for (index, shape) in shapes.iter().enumerate() {
        for field in array(&shape["fields"]) {
            if field_presence(shape, Some(field), text(field, "path")) != "present" {
                continue;
            }
            let Some(value) = literal_value(field) else {
                continue;
            };
            let discriminant = json!({"path": field["path"], "value": value});
            let key = canonical(&discriminant)?;
            match positions.get(&key) {
                Some(&position) => {
                    output[position].1 = discriminant;
                    output[position].2.push(index);
                }
                None => {
                    positions.insert(key.clone(), output.len());
                    output.push((key, discriminant, vec![index]));
                }
            }
        }
    }
    Ok(output)
}

fn pair_variants(left: &[Value], right: &[Value]) -> Result<Pairing, String> {
    let left_keys = occurrences(left)?;
    let right_keys: HashMap<String, Vec<usize>> = occurrences(right)?
        .into_iter()
        .map(|(key, _, indexes)| (key, indexes))
        .collect();
    let mut edges: HashMap<(usize, usize), Vec<Value>> = HashMap::new();
    // Map<number, Set<number>> in insertion order.
    let mut left_targets: Vec<(usize, BTreeSet<usize>)> = Vec::new();
    let mut right_targets: HashMap<usize, BTreeSet<usize>> = HashMap::new();
    for (key, discriminant, indexes) in &left_keys {
        let Some(right_indexes) = right_keys.get(key) else {
            continue;
        };
        if indexes.len() != 1 || right_indexes.len() != 1 {
            continue;
        }
        let (l, r) = (indexes[0], right_indexes[0]);
        edges.entry((l, r)).or_default().push(discriminant.clone());
        match left_targets.iter_mut().find(|(index, _)| *index == l) {
            Some((_, targets)) => {
                targets.insert(r);
            }
            None => left_targets.push((l, BTreeSet::from([r]))),
        }
        right_targets.entry(r).or_default().insert(l);
    }
    let mut pairs: Vec<(String, Pair)> = Vec::new();
    for (l, targets) in &left_targets {
        if targets.len() != 1 {
            continue;
        }
        let r = *targets.iter().next().unwrap_or(&0);
        if right_targets
            .get(&r)
            .is_none_or(|sources| sources.len() != 1 || !sources.contains(l))
        {
            continue;
        }
        let mut discriminants: Vec<(String, Value)> = Vec::new();
        for discriminant in edges.get(&(*l, r)).into_iter().flatten() {
            discriminants.push((canonical(discriminant)?, discriminant.clone()));
        }
        discriminants.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some((key, discriminant)) = discriminants.into_iter().next() {
            pairs.push((
                key,
                Pair {
                    left: *l,
                    right: r,
                    discriminant,
                },
            ));
        }
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let pairs: Vec<Pair> = pairs.into_iter().map(|(_, pair)| pair).collect();
    let paired_left: HashSet<usize> = pairs.iter().map(|pair| pair.left).collect();
    let paired_right: HashSet<usize> = pairs.iter().map(|pair| pair.right).collect();
    Ok(Pairing {
        unpaired_left: (0..left.len())
            .filter(|index| !paired_left.contains(index))
            .collect(),
        unpaired_right: (0..right.len())
            .filter(|index| !paired_right.contains(index))
            .collect(),
        pairs,
    })
}

const UNKNOWN_PRESENCE: (&str, &str) = ("unknown-coverage", "unknown-coverage");

fn change_with_id(mut semantic: Map<String, Value>) -> Result<Value, String> {
    let id = format!("jesc_change_{}", digest(&Value::Object(semantic.clone()))?);
    semantic.insert("change_id".into(), json!(id));
    Ok(Value::Object(semantic))
}

#[allow(clippy::too_many_arguments)]
fn change(
    status: &str,
    path: &str,
    discriminant: Value,
    presence: (&str, &str),
    left: Value,
    right: Value,
    left_range: Value,
    right_range: Value,
    links: &[String; 2],
    limitations: Vec<&str>,
) -> Result<Value, String> {
    let mut semantic = Map::new();
    semantic.insert("status".into(), json!(status));
    semantic.insert("path".into(), json!(path));
    semantic.insert("discriminant".into(), discriminant);
    semantic.insert(
        "presence".into(),
        json!({"left": presence.0, "right": presence.1}),
    );
    semantic.insert("left".into(), left);
    semantic.insert("right".into(), right);
    semantic.insert("left_source_range".into(), left_range);
    semantic.insert("right_source_range".into(), right_range);
    semantic.insert("evidence_links".into(), json!(links));
    semantic.insert("limitations".into(), json!(limitations));
    change_with_id(semantic)
}

fn unknown_reason(reason: String) -> Value {
    json!({"availability": "unknown", "reason": reason})
}

fn capitalize(side: &str) -> String {
    let mut chars = side.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn build_changes(
    left: &Selected,
    right: &Selected,
    pairing: &Pairing,
    links: &[String; 2],
) -> Result<Vec<Value>, String> {
    if left.status() != "selected" || right.status() != "selected" {
        return Ok(vec![change(
            "unknown",
            "",
            Value::Null,
            UNKNOWN_PRESENCE,
            unknown_reason(format!("Left export selection is {}.", left.status())),
            unknown_reason(format!("Right export selection is {}.", right.status())),
            Value::Null,
            Value::Null,
            links,
            vec![
                "Both selectors must resolve one exact export with trusted static return shapes before comparison.",
            ],
        )?]);
    }
    let (left_shapes, right_shapes) = (left.shapes(), right.shapes());
    if left_shapes.is_empty() && right_shapes.is_empty() {
        let availability = |shapes: &[Value], side: &str| {
            unknown_reason(if shapes.is_empty() {
                format!(
                    "{} export has no retained direct return shape.",
                    capitalize(side)
                )
            } else {
                format!(
                    "{} export return shape cannot be paired without an opposite variant.",
                    capitalize(side)
                )
            })
        };
        return Ok(vec![change(
            "unknown",
            "",
            Value::Null,
            UNKNOWN_PRESENCE,
            availability(left_shapes, "left"),
            availability(right_shapes, "right"),
            Value::Null,
            Value::Null,
            links,
            vec!["At least one selected export has no retained direct return shape."],
        )?]);
    }
    let mut changes = Vec::new();
    for pair in &pairing.pairs {
        changes.extend(diff_pair(
            &left_shapes[pair.left],
            &right_shapes[pair.right],
            &pair.discriminant,
            links,
        )?);
    }
    for (side, indexes, shapes) in [
        ("left", &pairing.unpaired_left, left_shapes),
        ("right", &pairing.unpaired_right, right_shapes),
    ] {
        for index in indexes {
            let shape = &shapes[*index];
            let is_left = side == "left";
            changes.push(change(
                "unknown",
                "",
                Value::Null,
                UNKNOWN_PRESENCE,
                unknown_reason(if is_left {
                    "Left return variant has no unique exact cross-version pairing.".into()
                } else {
                    "No left return variant was uniquely paired with this right variant.".into()
                }),
                unknown_reason(if is_left {
                    "No right return variant was uniquely paired with this left variant.".into()
                } else {
                    "Right return variant has no unique exact cross-version pairing.".into()
                }),
                if is_left { shape["source_range"].clone() } else { Value::Null },
                if is_left { Value::Null } else { shape["source_range"].clone() },
                links,
                vec!["The return variant was not paired because no reciprocal unique literal discriminant exists."],
            )?);
        }
    }
    Ok(changes)
}

fn field_at_path(shape: &Value, fields: &HashMap<&str, &Value>, path: &str) -> Option<Value> {
    if let Some(field) = fields.get(path) {
        return Some((*field).clone());
    }
    array(&shape["property_coverage"]).iter().any(|coverage| coverage["path"] == path).then(|| {
        json!({
            "path": path,
            "presence": "present",
            "state": "unknown",
            "value": null,
            "reason": "A static container is retained at this path, but no primitive field value is projected.",
        })
    })
}

fn availability(field: Option<&Value>) -> Value {
    let Some(field) = field.filter(|field| field["presence"] != "absent") else {
        return json!({"availability": "absent"});
    };
    match field["state"].as_str() {
        Some("unknown") => unknown_reason(
            field["reason"]
                .as_str()
                .unwrap_or("Static field value is unknown.")
                .to_owned(),
        ),
        Some("union") => json!({
            "availability": "union",
            "values": array(&field["value"]).iter().filter(|value| is_primitive(value)).collect::<Vec<_>>(),
        }),
        _ => match literal_value(field) {
            Some(value) => json!({"availability": "literal", "value": value}),
            None => unknown_reason("Static literal field failed its projection boundary.".into()),
        },
    }
}

fn diff_pair(
    left: &Value,
    right: &Value,
    discriminant: &Value,
    links: &[String; 2],
) -> Result<Vec<Value>, String> {
    let left_fields: HashMap<&str, &Value> = array(&left["fields"])
        .iter()
        .map(|f| (text(f, "path"), f))
        .collect();
    let right_fields: HashMap<&str, &Value> = array(&right["fields"])
        .iter()
        .map(|f| (text(f, "path"), f))
        .collect();
    let paths = unique_sorted(
        left_fields
            .keys()
            .chain(right_fields.keys())
            .map(|path| (*path).to_owned())
            .chain(
                array(&left["property_coverage"])
                    .iter()
                    .map(|c| text(c, "path").to_owned()),
            )
            .chain(
                array(&right["property_coverage"])
                    .iter()
                    .map(|c| text(c, "path").to_owned()),
            ),
    );
    let mut changes = Vec::new();
    for path in paths {
        let left_field = field_at_path(left, &left_fields, &path);
        let right_field = field_at_path(right, &right_fields, &path);
        let left_presence = field_presence(left, left_field.as_ref(), &path);
        let right_presence = field_presence(right, right_field.as_ref(), &path);
        let status = if let (Some(l), Some(r)) = (&left_field, &right_field)
            && canonical(l)? == canonical(r)?
        {
            None
        } else if left_presence == "absent" && right_presence == "absent" {
            None
        } else if left_presence == "unknown-coverage" || right_presence == "unknown-coverage" {
            Some("unknown")
        } else if left_presence == "absent" {
            Some("added")
        } else if right_presence == "absent" {
            Some("removed")
        } else if let (Some(l), Some(r)) = (&left_field, &right_field) {
            Some(if l["state"] == "unknown" || r["state"] == "unknown" {
                "unknown"
            } else {
                "changed"
            })
        } else {
            None
        };
        let Some(status) = status else { continue };
        changes.push(change(
            status,
            &path,
            discriminant.clone(),
            (&left_presence, &right_presence),
            availability(left_field.as_ref()),
            availability(right_field.as_ref()),
            left["source_range"].clone(),
            right["source_range"].clone(),
            links,
            if status == "unknown" {
                vec!["The static value or relevant parent-property coverage is incomplete."]
            } else {
                Vec::new()
            },
        )?);
    }
    Ok(changes)
}

fn inventories(pairing: &Pairing, left: &[Value], right: &[Value]) -> Vec<Value> {
    let left_pairs: BTreeMap<usize, &Pair> =
        pairing.pairs.iter().map(|pair| (pair.left, pair)).collect();
    let right_pairs: BTreeMap<usize, &Pair> = pairing
        .pairs
        .iter()
        .map(|pair| (pair.right, pair))
        .collect();
    let inventory = |side: &str, index: usize, shape: &Value, pair: Option<&&Pair>| {
        let properties: Vec<String> = unique_sorted(
            array(&shape["fields"])
                .iter()
                .filter(|field| {
                    field_presence(shape, Some(field), text(field, "path")) == "present"
                })
                .map(|field| text(field, "path").to_owned())
                .chain(
                    array(&shape["property_coverage"])
                        .iter()
                        .map(|c| text(c, "path").to_owned()),
                ),
        )
        .into_iter()
        .filter(|path| !path.is_empty())
        .collect();
        json!({
            "side": side,
            "variant_index": index,
            "discriminant": pair.map_or(Value::Null, |pair| pair.discriminant.clone()),
            "paired": pair.is_some(),
            "source_range": shape["source_range"],
            "properties": properties,
            "property_coverage": array(&shape["property_coverage"])
                .iter()
                .map(|c| json!({"path": c["path"], "status": c["status"]}))
                .collect::<Vec<_>>(),
        })
    };
    left.iter()
        .enumerate()
        .map(|(index, shape)| inventory("left", index, shape, left_pairs.get(&index)))
        .chain(
            right
                .iter()
                .enumerate()
                .map(|(index, shape)| inventory("right", index, shape, right_pairs.get(&index))),
        )
        .collect()
}

fn partial_property_coverage(shapes: &[Value]) -> bool {
    shapes.iter().any(|shape| {
        array(&shape["property_coverage"])
            .iter()
            .any(|coverage| coverage["status"] == "partial")
            || array(&shape["fields"]).iter().any(|field| {
                field_presence(shape, Some(field), text(field, "path")) == "unknown-coverage"
            })
    })
}
