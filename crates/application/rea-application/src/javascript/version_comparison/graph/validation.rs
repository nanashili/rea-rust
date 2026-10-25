//! Strict schema and semantic commitment checks for application graph values.

use super::{ApplicationEdge, ApplicationGraph, ApplicationNode, GraphCoverage, NodeObservation};
use rea_core::canonical_json;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

const NODE_KINDS: &[&str] = &[
    "package",
    "installer",
    "artifact",
    "asar-entry",
    "electron-main",
    "electron-preload",
    "electron-renderer",
    "electron-utility",
    "javascript-asset",
    "javascript-chunk",
    "javascript-module",
    "javascript-expression",
    "source-map",
    "source-module",
    "browser-window",
    "frame",
    "target",
    "context-bridge-api",
    "ipc-channel",
    "ipc-handler",
    "worker",
    "service-worker",
    "endpoint",
    "storage",
    "native-addon",
    "native-export",
    "managed-assembly",
    "managed-module",
    "managed-type",
    "managed-method",
    "managed-field",
    "managed-pinvoke-import",
    "managed-native-implementation",
    "runtime-script-instance",
    "unknown",
];

const RELATIONS: &[&str] = &[
    "contains",
    "loads",
    "imports",
    "maps_to",
    "exposes",
    "sends",
    "invokes",
    "handles",
    "calls",
    "persists_to",
    "observed_as",
    "changed_from",
];

const APPLICATION_EVIDENCE_AUTHORITIES: &[&str] = &[
    "artifact-bytes",
    "ast-static-analysis",
    "static-relationship-inference",
    "passive-cdp-runtime",
    "cross-layer-reconciliation",
    "cross-version-comparison",
    "controlled-replay",
    "native-analysis-provider",
    "managed-static-analysis",
    "historical-reference",
    "user-assertion",
    "unknown",
];

const UNAVAILABLE_REASONS: &[&str] = &[
    "not-applicable",
    "not-observed",
    "truncated",
    "provider-unavailable",
    "unresolved",
    "unknown",
];

pub(super) fn parse_graph(value: &Value, path: &str) -> Result<ApplicationGraph, super::Failure> {
    let graph = object(Some(value), path, "graph")?;
    exact_fields(
        graph,
        &[
            "schema",
            "root_node_ids",
            "nodes",
            "edges",
            "coverage",
            "limitations",
            "graph_id",
        ],
        path,
        "graph",
    )?;

    if string(graph.get("schema"), path, "graph.schema")? != "JavaScriptApplicationGraph" {
        return Err(invalid(
            path,
            "graph.schema must be JavaScriptApplicationGraph",
        ));
    }

    let graph_id = prefixed_digest(graph.get("graph_id"), "jag_", path, "graph.graph_id")?;
    let root_node_ids = string_array(
        graph.get("root_node_ids"),
        path,
        "graph.root_node_ids",
        true,
    )?;
    let graph_nodes = array(graph.get("nodes"), path, "graph.nodes")?;
    let graph_edges = array(graph.get("edges"), path, "graph.edges")?;
    let coverage = parse_coverage(graph.get("coverage"), path, "graph.coverage")?;
    let limitations = string_array(graph.get("limitations"), path, "graph.limitations", false)?;

    if graph_nodes.is_empty() {
        return Err(invalid(path, "graph.nodes must contain at least one node"));
    }
    if root_node_ids.is_empty() {
        return Err(invalid(
            path,
            "graph.root_node_ids must contain at least one node",
        ));
    }
    if coverage.status != "complete" && limitations.is_empty() {
        return Err(invalid(
            path,
            "Non-complete graph coverage requires an explicit limitation",
        ));
    }
    ensure_sorted_unique(&root_node_ids, path, "graph.root_node_ids")?;
    ensure_sorted_unique(&limitations, path, "graph.limitations")?;

    let nodes = graph_nodes
        .iter()
        .enumerate()
        .map(|(index, node)| parse_node(node, path, index))
        .collect::<Result<Vec<_>, _>>()?;
    ensure_sorted_unique(
        &nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>(),
        path,
        "graph.nodes",
    )?;

    let nodes_by_id = nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node.kind.as_str()))
        .collect::<BTreeMap<_, _>>();
    for root in &root_node_ids {
        if !nodes_by_id.contains_key(root.as_str()) {
            return Err(invalid(path, "Root identifier must name a graph node"));
        }
    }

    let edges = graph_edges
        .iter()
        .enumerate()
        .map(|(index, edge)| parse_edge(edge, path, index, &nodes_by_id))
        .collect::<Result<Vec<_>, _>>()?;
    ensure_sorted_unique(
        &edges
            .iter()
            .map(|edge| edge.edge_id.clone())
            .collect::<Vec<_>>(),
        path,
        "graph.edges",
    )?;

    let mut semantic = graph.clone();
    semantic.remove("graph_id");
    let expected_graph_id = committed_id("jag_", &Value::Object(semantic), path, "graph")?;
    if graph_id != expected_graph_id {
        return Err(invalid(
            path,
            "Graph identifier does not match its semantic content",
        ));
    }

    Ok(ApplicationGraph {
        graph_id,
        root_node_ids,
        nodes,
        edges,
        coverage,
        limitations,
    })
}

fn parse_node(value: &Value, path: &str, index: usize) -> Result<ApplicationNode, super::Failure> {
    let node_path = format!("graph.nodes[{index}]");
    let node = object(Some(value), path, &node_path)?;
    exact_fields(
        node,
        &["node_id", "kind", "identity", "observations"],
        path,
        &node_path,
    )?;

    let node_id = prefixed_digest(
        node.get("node_id"),
        "jag_node_",
        path,
        &format!("{node_path}.node_id"),
    )?;
    let kind = string(node.get("kind"), path, &format!("{node_path}.kind"))?;
    if !NODE_KINDS.contains(&kind) {
        return Err(invalid(path, &format!("{node_path}.kind is unsupported")));
    }
    let identity = node
        .get("identity")
        .ok_or_else(|| invalid(path, &format!("{node_path}.identity is required")))?;
    validate_identity(identity, path, &format!("{node_path}.identity"))?;
    let expected_node_id = committed_id(
        "jag_node_",
        &json!({"kind": kind, "identity": identity}),
        path,
        &node_path,
    )?;
    if node_id != expected_node_id {
        return Err(invalid(
            path,
            "Node identifier does not match its kind and identity",
        ));
    }

    let observations = array(
        node.get("observations"),
        path,
        &format!("{node_path}.observations"),
    )?;
    if observations.is_empty() {
        return Err(invalid(
            path,
            "Application nodes must have at least one observation",
        ));
    }
    let parsed_observations = observations
        .iter()
        .enumerate()
        .map(|(observation_index, observation)| {
            parse_observation(observation, path, &node_path, observation_index, &node_id)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ensure_sorted_unique(
        &parsed_observations
            .iter()
            .map(|observation| observation.observation_id.clone())
            .collect::<Vec<_>>(),
        path,
        &format!("{node_path}.observations"),
    )?;

    if !parsed_observations
        .iter()
        .any(|observation| observation_matches_identity(identity, observation))
    {
        return Err(invalid(
            path,
            "Node identity is not supported by a compatible observation",
        ));
    }

    Ok(ApplicationNode {
        node_id,
        kind: kind.to_owned(),
        identity: identity.clone(),
        observations: parsed_observations,
    })
}

fn parse_observation(
    value: &Value,
    path: &str,
    node_path: &str,
    index: usize,
    node_id: &str,
) -> Result<NodeObservation, super::Failure> {
    let observation_path = format!("{node_path}.observations[{index}]");
    let observation = object(Some(value), path, &observation_path)?;
    exact_fields(
        observation,
        &[
            "label",
            "source_map_reference",
            "properties",
            "evidence",
            "observation_id",
            "identifier_strategy",
        ],
        path,
        &observation_path,
    )?;

    match observation.get("label") {
        Some(Value::Null) => {}
        Some(Value::String(label)) if !label.is_empty() => {}
        _ => {
            return Err(invalid(
                path,
                "Observation label must be non-empty text or null",
            ));
        }
    }
    let source_map_reference = observation
        .get("source_map_reference")
        .ok_or_else(|| invalid(path, "Observation source_map_reference is required"))?;
    if !source_map_reference.is_null() {
        validate_source_map_reference(source_map_reference, path, &observation_path)?;
    }
    let properties = object(
        observation.get("properties"),
        path,
        &format!("{observation_path}.properties"),
    )?;
    if properties.keys().any(String::is_empty) {
        return Err(invalid(
            path,
            "Application property names must be non-empty",
        ));
    }
    validate_application_evidence(
        observation.get("evidence"),
        path,
        &format!("{observation_path}.evidence"),
    )?;
    validate_identifier_strategy(
        observation.get("identifier_strategy"),
        path,
        &format!("{observation_path}.identifier_strategy"),
        "observation-exact",
    )?;

    let observation_id = prefixed_digest(
        observation.get("observation_id"),
        "jag_observation_",
        path,
        &format!("{observation_path}.observation_id"),
    )?;
    let mut semantic = observation.clone();
    semantic.remove("observation_id");
    // The TypeScript graph owner hashes { node_id, ...observation }, not a nested observation object.
    semantic.insert("node_id".to_owned(), json!(node_id));
    let expected_id = committed_id(
        "jag_observation_",
        &Value::Object(semantic),
        path,
        &observation_path,
    )?;
    if observation_id != expected_id {
        return Err(invalid(
            path,
            "Observation identifier does not match its semantic content",
        ));
    }

    Ok(NodeObservation {
        raw: value.clone(),
        observation_id,
        label: observation
            .get("label")
            .and_then(Value::as_str)
            .map(str::to_owned),
        properties: properties.clone(),
        source_map_reference: source_map_reference.clone(),
        evidence: observation.get("evidence").cloned().unwrap_or(Value::Null),
    })
}

fn parse_edge(
    value: &Value,
    path: &str,
    index: usize,
    nodes_by_id: &BTreeMap<&str, &str>,
) -> Result<ApplicationEdge, super::Failure> {
    let edge_path = format!("graph.edges[{index}]");
    let edge = object(Some(value), path, &edge_path)?;
    exact_fields(
        edge,
        &[
            "source_node_id",
            "target_node_id",
            "relation",
            "properties",
            "evidence",
            "edge_id",
            "identifier_strategy",
        ],
        path,
        &edge_path,
    )?;

    let source_node_id = prefixed_digest(
        edge.get("source_node_id"),
        "jag_node_",
        path,
        &format!("{edge_path}.source_node_id"),
    )?;
    let target_node_id = prefixed_digest(
        edge.get("target_node_id"),
        "jag_node_",
        path,
        &format!("{edge_path}.target_node_id"),
    )?;
    if source_node_id == target_node_id {
        return Err(invalid(
            path,
            "Application graph edges cannot be self-referential",
        ));
    }
    let source_kind = nodes_by_id
        .get(source_node_id.as_str())
        .ok_or_else(|| invalid(path, "Edge endpoints must name graph nodes"))?;
    let target_kind = nodes_by_id
        .get(target_node_id.as_str())
        .ok_or_else(|| invalid(path, "Edge endpoints must name graph nodes"))?;
    let relation = string(edge.get("relation"), path, &format!("{edge_path}.relation"))?;
    if !RELATIONS.contains(&relation) {
        return Err(invalid(
            path,
            "Application graph edge relation is unsupported",
        ));
    }
    if relation == "changed_from" && source_kind != target_kind {
        return Err(invalid(
            path,
            "changed_from endpoints must have the same node kind",
        ));
    }
    let properties = object(
        edge.get("properties"),
        path,
        &format!("{edge_path}.properties"),
    )?;
    if properties.keys().any(String::is_empty) {
        return Err(invalid(
            path,
            "Application property names must be non-empty",
        ));
    }
    validate_application_evidence(edge.get("evidence"), path, &format!("{edge_path}.evidence"))?;
    validate_identifier_strategy(
        edge.get("identifier_strategy"),
        path,
        &format!("{edge_path}.identifier_strategy"),
        "relationship-exact",
    )?;

    let edge_id = prefixed_digest(
        edge.get("edge_id"),
        "jag_edge_",
        path,
        &format!("{edge_path}.edge_id"),
    )?;
    let mut semantic = edge.clone();
    semantic.remove("edge_id");
    let expected_id = committed_id("jag_edge_", &Value::Object(semantic), path, &edge_path)?;
    if edge_id != expected_id {
        return Err(invalid(
            path,
            "Edge identifier does not match its semantic content",
        ));
    }

    Ok(ApplicationEdge {
        raw: value.clone(),
        edge_id,
        source_node_id,
        target_node_id,
        relation: relation.to_owned(),
    })
}

fn validate_identity(value: &Value, path: &str, field: &str) -> Result<(), super::Failure> {
    let identity = object(Some(value), path, field)?;
    let strategy = string(identity.get("strategy"), path, &format!("{field}.strategy"))?;
    match strategy {
        "content-digest" => {
            exact_fields(identity, &["strategy", "stability", "sha256"], path, field)?;
            require_text_eq(identity, "stability", "global-exact", path, field)?;
            validate_sha256(identity.get("sha256"), path, field)?;
        }
        "source-map-original" => {
            exact_fields(
                identity,
                &[
                    "strategy",
                    "stability",
                    "source_map_sha256",
                    "original_source",
                    "source_root",
                    "source_sha256",
                ],
                path,
                field,
            )?;
            require_text_eq(identity, "stability", "source-map-exact", path, field)?;
            validate_sha256(identity.get("source_map_sha256"), path, field)?;
            // The TS contract preserves the exact declared source string, including "".
            nullable_text(identity.get("original_source"), path, field, false)?;
            nullable_text(identity.get("source_root"), path, field, false)?;
            validate_nullable_sha256(identity.get("source_sha256"), path, field)?;
        }
        "canonical-path" => {
            exact_fields(
                identity,
                &["strategy", "stability", "artifact_sha256", "path"],
                path,
                field,
            )?;
            require_text_eq(identity, "stability", "artifact-version", path, field)?;
            validate_sha256(identity.get("artifact_sha256"), path, field)?;
            validate_relative_path(identity.get("path"), path, field)?;
        }
        "structural-fingerprint" => {
            exact_fields(
                identity,
                &[
                    "strategy",
                    "stability",
                    "algorithm",
                    "fingerprint_sha256",
                    "basis",
                ],
                path,
                field,
            )?;
            require_text_eq(
                identity,
                "stability",
                "cross-version-inference",
                path,
                field,
            )?;
            require_nonempty_text(identity.get("algorithm"), path, field)?;
            validate_sha256(identity.get("fingerprint_sha256"), path, field)?;
            let basis = string_array(identity.get("basis"), path, &format!("{field}.basis"), true)?;
            if basis.is_empty()
                || basis.iter().any(|basis| {
                    ![
                        "syntax-tree",
                        "control-flow",
                        "imports",
                        "exports",
                        "literals",
                        "api-usage",
                    ]
                    .contains(&basis.as_str())
                })
            {
                return Err(invalid(path, "Structural fingerprint basis is unsupported"));
            }
            ensure_sorted_unique(&basis, path, &format!("{field}.basis"))?;
        }
        "artifact-local-key" => {
            exact_fields(
                identity,
                &[
                    "strategy",
                    "stability",
                    "artifact_sha256",
                    "namespace",
                    "key",
                ],
                path,
                field,
            )?;
            require_text_eq(identity, "stability", "artifact-version", path, field)?;
            validate_sha256(identity.get("artifact_sha256"), path, field)?;
            require_nonempty_text(identity.get("namespace"), path, field)?;
            require_text(identity.get("key"), path, field)?;
        }
        "runtime-instance" => {
            exact_fields(
                identity,
                &["strategy", "stability", "capture_sha256", "runtime_key"],
                path,
                field,
            )?;
            require_text_eq(identity, "stability", "capture-only", path, field)?;
            validate_sha256(identity.get("capture_sha256"), path, field)?;
            require_nonempty_text(identity.get("runtime_key"), path, field)?;
        }
        "observation-fingerprint" => {
            exact_fields(
                identity,
                &["strategy", "stability", "observation_sha256", "scope"],
                path,
                field,
            )?;
            require_text_eq(identity, "stability", "observation-only", path, field)?;
            validate_sha256(identity.get("observation_sha256"), path, field)?;
            require_nonempty_text(identity.get("scope"), path, field)?;
        }
        _ => {
            return Err(invalid(
                path,
                "Application node identity strategy is unsupported",
            ));
        }
    }
    Ok(())
}

fn validate_identifier_strategy(
    value: Option<&Value>,
    path: &str,
    field: &str,
    expected_stability: &str,
) -> Result<(), super::Failure> {
    let strategy = object(value, path, field)?;
    exact_fields(strategy, &["strategy", "stability"], path, field)?;
    require_text_eq(strategy, "strategy", "semantic-content-sha256", path, field)?;
    require_text_eq(strategy, "stability", expected_stability, path, field)
}

fn validate_source_map_reference(
    value: &Value,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    let reference = object(Some(value), path, field)?;
    exact_fields(
        reference,
        &["source_name", "source_root", "map_path", "resolution"],
        path,
        field,
    )?;
    require_text(reference.get("source_name"), path, field)?;
    nullable_text(reference.get("source_root"), path, field, false)?;
    require_nonempty_text(reference.get("map_path"), path, field)?;

    let resolution = object(
        reference.get("resolution"),
        path,
        &format!("{field}.resolution"),
    )?;
    match string(
        resolution.get("kind"),
        path,
        &format!("{field}.resolution.kind"),
    )? {
        "artifact-relative" | "suffix" => {
            exact_fields(resolution, &["kind", "path"], path, field)?;
            require_nonempty_text(resolution.get("path"), path, field)?;
        }
        "unresolved" => {
            exact_fields(resolution, &["kind", "reason"], path, field)?;
            require_nonempty_text(resolution.get("reason"), path, field)?;
        }
        _ => return Err(invalid(path, "Source map resolution kind is unsupported")),
    }
    Ok(())
}

fn parse_coverage(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<GraphCoverage, super::Failure> {
    let coverage = object(value, path, field)?;
    exact_fields(
        coverage,
        &["status", "truncated", "omitted_count", "limits"],
        path,
        field,
    )?;
    let status = string(coverage.get("status"), path, &format!("{field}.status"))?;
    let truncated = coverage
        .get("truncated")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(path, &format!("{field}.truncated must be a boolean")))?;
    let omitted_count = match coverage.get("omitted_count") {
        Some(Value::Null) => None,
        Some(value) => Some(safe_nonnegative_integer(
            Some(value),
            path,
            &format!("{field}.omitted_count"),
        )?),
        None => return Err(invalid(path, &format!("{field}.omitted_count is required"))),
    };
    let limits = array(coverage.get("limits"), path, &format!("{field}.limits"))?;
    for (index, limit) in limits.iter().enumerate() {
        validate_limit(limit, path, &format!("{field}.limits[{index}]"))?;
    }
    let limits = limits.to_vec();
    ensure_normalized_limits(&limits, path, field)?;

    match (status, truncated, omitted_count) {
        ("complete", false, Some(0)) => {}
        ("partial", false, Some(_)) | ("partial", false, None) => {}
        ("partial", true, Some(value)) if value > 0 => {}
        ("partial", true, None) => {}
        ("unknown" | "unavailable", false, None) => {}
        _ => {
            return Err(invalid(
                path,
                &format!("{field} has inconsistent status, truncation, or omission values"),
            ));
        }
    }
    if status != "complete" && truncated && limits.is_empty() {
        return Err(invalid(
            path,
            &format!("{field} truncation requires a named limit"),
        ));
    }

    Ok(GraphCoverage {
        status: status.to_owned(),
        truncated,
        omitted_count,
        limits,
    })
}

fn validate_limit(value: &Value, path: &str, field: &str) -> Result<(), super::Failure> {
    let limit = object(Some(value), path, field)?;
    exact_fields(limit, &["name", "value", "unit"], path, field)?;
    require_nonempty_text(limit.get("name"), path, field)?;
    safe_nonnegative_integer(limit.get("value"), path, field)?;
    match string(limit.get("unit"), path, field)? {
        "items" | "bytes" | "milliseconds" | "depth" | "characters" | "instructions" | "other" => {
            Ok(())
        }
        _ => Err(invalid(path, "Coverage limit unit is unsupported")),
    }
}

fn ensure_normalized_limits(
    limits: &[Value],
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    let keys = limits
        .iter()
        .map(|limit| canonical_string(limit, path, field))
        .collect::<Result<Vec<_>, _>>()?;
    ensure_sorted_unique(&keys, path, &format!("{field}.limits"))
}

fn validate_application_evidence(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    let evidence = object(value, path, field)?;
    exact_fields(
        evidence,
        &[
            "authority",
            "state",
            "confidence",
            "artifact",
            "location",
            "extractor",
            "coverage",
            "limitations",
            "evidence_ids",
        ],
        path,
        field,
    )?;

    let authority = string(evidence.get("authority"), path, field)?;
    if !APPLICATION_EVIDENCE_AUTHORITIES.contains(&authority) {
        return Err(invalid(
            path,
            "Application evidence authority is unsupported",
        ));
    }
    let state = string(evidence.get("state"), path, field)?;
    if !["observed", "inferred", "unknown", "unavailable"].contains(&state) {
        return Err(invalid(path, "Application evidence state is unsupported"));
    }
    let confidence = string(evidence.get("confidence"), path, field)?;
    if !["exact", "high", "medium", "low", "unknown"].contains(&confidence) {
        return Err(invalid(
            path,
            "Application evidence confidence is unsupported",
        ));
    }

    validate_application_artifact(evidence.get("artifact"), path, field)?;
    validate_application_location(evidence.get("location"), path, field)?;
    validate_extractor(evidence.get("extractor"), path, field)?;
    let coverage = parse_coverage(evidence.get("coverage"), path, &format!("{field}.coverage"))?;
    let limitations = string_array(
        evidence.get("limitations"),
        path,
        &format!("{field}.limitations"),
        false,
    )?;
    let evidence_ids = string_array(
        evidence.get("evidence_ids"),
        path,
        &format!("{field}.evidence_ids"),
        false,
    )?;
    ensure_sorted_unique(&limitations, path, &format!("{field}.limitations"))?;
    for id in &evidence_ids {
        validate_prefixed_digest_text(id, "ev_", path, &format!("{field}.evidence_ids"))?;
    }
    ensure_sorted_unique(&evidence_ids, path, &format!("{field}.evidence_ids"))?;

    if authority == "static-relationship-inference" && state != "inferred"
        || authority == "cross-layer-reconciliation" && state != "inferred"
        || authority == "cross-version-comparison" && state != "inferred"
        || authority == "unknown" && !["unknown", "unavailable"].contains(&state)
    {
        return Err(invalid(
            path,
            "Application authority and fact state are inconsistent",
        ));
    }
    if ["unknown", "unavailable"].contains(&state)
        && (confidence != "unknown" || limitations.is_empty())
    {
        return Err(invalid(
            path,
            "Unknown or unavailable facts require unknown confidence and a limitation",
        ));
    }
    if state == "observed" && confidence == "unknown"
        || state == "inferred" && !["high", "medium", "low"].contains(&confidence)
        || confidence == "exact" && state != "observed"
    {
        return Err(invalid(
            path,
            "Application fact state and confidence are inconsistent",
        ));
    }
    if state == "observed"
        && evidence
            .get("location")
            .and_then(|location| location.get("available"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(invalid(
            path,
            "Observed facts require an actionable location",
        ));
    }
    if state == "inferred" && limitations.is_empty() {
        return Err(invalid(
            path,
            "Inferred facts require an explicit limitation",
        ));
    }
    if coverage.status != "complete" && limitations.is_empty() {
        return Err(invalid(
            path,
            "Non-complete fact coverage requires an explicit limitation",
        ));
    }
    if [
        "artifact-bytes",
        "ast-static-analysis",
        "controlled-replay",
        "native-analysis-provider",
        "managed-static-analysis",
    ]
    .contains(&authority)
        && state != "unavailable"
        && evidence
            .get("artifact")
            .and_then(|artifact| artifact.get("available"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(invalid(
            path,
            "Artifact-backed facts require a content digest",
        ));
    }
    let runtime_location = evidence
        .get("location")
        .and_then(|location| location.get("available"))
        .and_then(Value::as_bool)
        == Some(true)
        && evidence
            .get("location")
            .and_then(|location| location.get("value"))
            .and_then(|value| value.get("kind"))
            .and_then(Value::as_str)
            == Some("runtime");
    if runtime_location
        && [
            "artifact-bytes",
            "ast-static-analysis",
            "static-relationship-inference",
            "native-analysis-provider",
        ]
        .contains(&authority)
    {
        return Err(invalid(
            path,
            "Static and native authorities cannot claim a runtime location",
        ));
    }

    Ok(())
}

fn validate_application_artifact(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    let artifact = object(value, path, &format!("{field}.artifact"))?;
    match artifact.get("available").and_then(Value::as_bool) {
        Some(true) => {
            exact_fields(
                artifact,
                &["available", "artifact_id", "sha256"],
                path,
                field,
            )?;
            let digest = validate_sha256(artifact.get("sha256"), path, field)?;
            let identifier = prefixed_digest(artifact.get("artifact_id"), "art_", path, field)?;
            if identifier != format!("art_{digest}") {
                return Err(invalid(
                    path,
                    "Artifact identifier must commit the same SHA-256 digest",
                ));
            }
        }
        Some(false) => validate_unavailable_fact(artifact, path, &format!("{field}.artifact"))?,
        None => return Err(invalid(path, "Artifact availability must be a boolean")),
    }
    Ok(())
}

fn validate_application_location(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    let location = object(value, path, &format!("{field}.location"))?;
    match location.get("available").and_then(Value::as_bool) {
        Some(false) => validate_unavailable_fact(location, path, &format!("{field}.location")),
        Some(true) => {
            exact_fields(location, &["available", "value"], path, field)?;
            let value = object(
                location.get("value"),
                path,
                &format!("{field}.location.value"),
            )?;
            match string(value.get("kind"), path, field)? {
                "artifact-path" => {
                    exact_fields(value, &["kind", "path"], path, field)?;
                    validate_relative_path(value.get("path"), path, field)?;
                }
                "source-range" => validate_source_range(value, path, field)?,
                "file-offset-range" => validate_file_offset_range(value, path, field)?,
                "url" => {
                    exact_fields(value, &["kind", "url"], path, field)?;
                    require_nonempty_text(value.get("url"), path, field)?;
                }
                "runtime" => validate_runtime_location(value, path, field)?,
                "native-address" => {
                    exact_fields(value, &["kind", "address", "symbol"], path, field)?;
                    require_nonempty_text(value.get("address"), path, field)?;
                    nullable_text(value.get("symbol"), path, field, true)?;
                }
                "package-export" => {
                    exact_fields(value, &["kind", "package_name", "export_path"], path, field)?;
                    require_nonempty_text(value.get("package_name"), path, field)?;
                    require_nonempty_text(value.get("export_path"), path, field)?;
                }
                _ => return Err(invalid(path, "Application location kind is unsupported")),
            }
            Ok(())
        }
        None => Err(invalid(path, "Location availability must be a boolean")),
    }
}

fn validate_unavailable_fact(
    value: &Map<String, Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    exact_fields(value, &["available", "reason", "detail"], path, field)?;
    if value.get("available").and_then(Value::as_bool) != Some(false) {
        return Err(invalid(
            path,
            "Unavailable fact must declare available=false",
        ));
    }
    let reason = string(value.get("reason"), path, field)?;
    if !UNAVAILABLE_REASONS.contains(&reason) {
        return Err(invalid(path, "Unavailable fact reason is unsupported"));
    }
    require_nonempty_text(value.get("detail"), path, field)
}

fn validate_extractor(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    let extractor = object(value, path, &format!("{field}.extractor"))?;
    exact_fields(
        extractor,
        &["name", "version", "operation", "executable_sha256"],
        path,
        field,
    )?;
    require_nonempty_text(extractor.get("name"), path, field)?;
    require_nonempty_text(extractor.get("version"), path, field)?;
    require_nonempty_text(extractor.get("operation"), path, field)?;
    validate_nullable_sha256(extractor.get("executable_sha256"), path, field)
}

fn validate_source_range(
    value: &Map<String, Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    exact_fields(value, &["kind", "source", "start", "end"], path, field)?;
    require_text_eq(value, "kind", "source-range", path, field)?;
    require_nonempty_text(value.get("source"), path, field)?;
    let start = range_position(value.get("start"), path, field)?;
    let end = range_position(value.get("end"), path, field)?;
    if end.0 < start.0 || end.0 == start.0 && end.1 < start.1 {
        return Err(invalid(path, "Source range end must not precede its start"));
    }
    Ok(())
}

fn validate_file_offset_range(
    value: &Map<String, Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    exact_fields(value, &["kind", "start", "end"], path, field)?;
    require_text_eq(value, "kind", "file-offset-range", path, field)?;
    let start = safe_nonnegative_integer(value.get("start"), path, field)?;
    let end = safe_nonnegative_integer(value.get("end"), path, field)?;
    if end < start {
        return Err(invalid(
            path,
            "File offset range end must not precede its start",
        ));
    }
    Ok(())
}

fn validate_runtime_location(
    value: &Map<String, Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    exact_fields(
        value,
        &[
            "kind",
            "capture_sha256",
            "target_key",
            "frame_key",
            "script_key",
        ],
        path,
        field,
    )?;
    require_text_eq(value, "kind", "runtime", path, field)?;
    validate_sha256(value.get("capture_sha256"), path, field)?;
    require_nonempty_text(value.get("target_key"), path, field)?;
    nullable_text(value.get("frame_key"), path, field, true)?;
    nullable_text(value.get("script_key"), path, field, true)
}

fn range_position(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<(u64, u64), super::Failure> {
    let position = object(value, path, field)?;
    exact_fields(position, &["line", "column"], path, field)?;
    let line = safe_nonnegative_integer(position.get("line"), path, field)?;
    let column = safe_nonnegative_integer(position.get("column"), path, field)?;
    if line == 0 {
        return Err(invalid(path, "Source range lines start at one"));
    }
    Ok((line, column))
}

fn observation_matches_identity(identity: &Value, observation: &NodeObservation) -> bool {
    let Some(identity) = identity.as_object() else {
        return false;
    };
    let Some(evidence) = observation.evidence.as_object() else {
        return false;
    };
    let strategy = identity
        .get("strategy")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let state = evidence
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let artifact = evidence.get("artifact").and_then(Value::as_object);
    let artifact_available = artifact
        .and_then(|artifact| artifact.get("available"))
        .and_then(Value::as_bool)
        == Some(true);
    let artifact_digest = artifact
        .and_then(|artifact| artifact.get("sha256"))
        .and_then(Value::as_str);
    let location = evidence.get("location").and_then(Value::as_object);
    let location_available = location
        .and_then(|location| location.get("available"))
        .and_then(Value::as_bool)
        == Some(true);
    let location_value = location
        .and_then(|location| location.get("value"))
        .and_then(Value::as_object);

    match strategy {
        "content-digest" => {
            state == "observed"
                && artifact_available
                && artifact_digest == identity.get("sha256").and_then(Value::as_str)
        }
        "source-map-original" => source_map_observation_matches(identity, observation, evidence),
        "canonical-path" => {
            artifact_available
                && artifact_digest == identity.get("artifact_sha256").and_then(Value::as_str)
                && location_available
                && location_value
                    .and_then(|location| location.get("kind"))
                    .and_then(Value::as_str)
                    == Some("artifact-path")
                && location_value.and_then(|location| location.get("path")) == identity.get("path")
        }
        "artifact-local-key" => {
            artifact_available
                && artifact_digest == identity.get("artifact_sha256").and_then(Value::as_str)
        }
        "runtime-instance" => {
            ["passive-cdp-runtime", "controlled-replay"].contains(
                &evidence
                    .get("authority")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ) && location_available
                && location_value
                    .and_then(|location| location.get("kind"))
                    .and_then(Value::as_str)
                    == Some("runtime")
                && location_value.and_then(|location| location.get("capture_sha256"))
                    == identity.get("capture_sha256")
                && ["target_key", "frame_key", "script_key"]
                    .iter()
                    .any(|field| {
                        location_value.and_then(|location| location.get(*field))
                            == identity.get("runtime_key")
                    })
        }
        "structural-fingerprint" => state == "inferred",
        _ => state == "observed",
    }
}

fn source_map_observation_matches(
    identity: &Map<String, Value>,
    observation: &NodeObservation,
    evidence: &Map<String, Value>,
) -> bool {
    let source_sha256 = identity.get("source_sha256").unwrap_or(&Value::Null);
    let source_digests = [
        observation.properties.get("content_sha256"),
        observation.properties.get("source_sha256"),
    ];
    let has_known_source_digest = !source_sha256.is_null();
    let digest_facts_match = source_digests
        .iter()
        .all(|digest| digest.is_none_or(Value::is_null) || *digest == Some(source_sha256));
    let known_digest_is_retained = !has_known_source_digest
        || source_digests
            .iter()
            .any(|digest| *digest == Some(source_sha256));
    let content_availability_matches = (observation.properties.get("content_available")
        != Some(&json!(true))
        || has_known_source_digest)
        && (observation.properties.get("content_available") != Some(&json!(false))
            || !has_known_source_digest);
    let artifact = evidence.get("artifact").and_then(Value::as_object);
    let location = evidence.get("location").and_then(Value::as_object);
    let location_value = location
        .and_then(|location| location.get("value"))
        .and_then(Value::as_object);
    let reference = observation.source_map_reference.as_object();

    digest_facts_match
        && known_digest_is_retained
        && content_availability_matches
        && reference.is_some_and(|reference| {
            reference.get("source_name") == identity.get("original_source")
                && reference.get("source_root") == identity.get("source_root")
        })
        && evidence.get("state").and_then(Value::as_str) == Some("observed")
        && artifact
            .and_then(|artifact| artifact.get("available"))
            .and_then(Value::as_bool)
            == Some(true)
        && artifact.and_then(|artifact| artifact.get("sha256")) == identity.get("source_map_sha256")
        && location
            .and_then(|location| location.get("available"))
            .and_then(Value::as_bool)
            == Some(true)
        && location_value
            .and_then(|location| location.get("kind"))
            .and_then(Value::as_str)
            == Some("artifact-path")
        && reference.and_then(|reference| reference.get("map_path"))
            == location_value.and_then(|location| location.get("path"))
}

fn validate_relative_path(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    let value = string(value, path, field)?;
    if value.is_empty()
        || value.starts_with('/')
        || value.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid(
            path,
            "Expected a normalized relative POSIX path without traversal",
        ));
    }
    Ok(())
}

fn validate_sha256(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<String, super::Failure> {
    let digest = string(value, path, field)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            path,
            &format!("{field} must contain a lowercase SHA-256 digest"),
        ));
    }
    Ok(digest.to_owned())
}

fn validate_nullable_sha256(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    match value {
        Some(Value::Null) => Ok(()),
        Some(value) => validate_sha256(Some(value), path, field).map(|_| ()),
        None => Err(invalid(path, &format!("{field} is required"))),
    }
}

fn validate_prefixed_digest_text(
    value: &str,
    prefix: &str,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    if !is_prefixed_digest(value, prefix) {
        return Err(invalid(
            path,
            &format!("{field} must use the {prefix} digest prefix"),
        ));
    }
    Ok(())
}

fn is_prefixed_digest(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn prefixed_digest(
    value: Option<&Value>,
    prefix: &str,
    path: &str,
    field: &str,
) -> Result<String, super::Failure> {
    let value = string(value, path, field)?;
    validate_prefixed_digest_text(value, prefix, path, field)?;
    Ok(value.to_owned())
}

fn committed_id(
    prefix: &str,
    value: &Value,
    path: &str,
    field: &str,
) -> Result<String, super::Failure> {
    canonical_json::digest(value)
        .map(|digest| format!("{prefix}{digest}"))
        .map_err(|error| {
            invalid(
                path,
                &format!("Could not authenticate {field} identifier: {error}"),
            )
        })
}

pub(super) fn canonical_string(
    value: &Value,
    path: &str,
    field: &str,
) -> Result<String, super::Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid(path, &format!("Could not serialize {field}: {error}")))?;
    let mut output = Vec::new();
    canonical_json::write(&raw, &mut output)
        .map_err(|error| invalid(path, &format!("Could not canonicalize {field}: {error}")))?;
    String::from_utf8(output)
        .map_err(|error| invalid(path, &format!("Canonical {field} is not UTF-8: {error}")))
}

fn exact_fields(
    object: &Map<String, Value>,
    expected: &[&str],
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(invalid(
            path,
            &format!("{field} has missing or unsupported fields"),
        ));
    }
    Ok(())
}

fn object<'a>(
    value: Option<&'a Value>,
    path: &str,
    field: &str,
) -> Result<&'a Map<String, Value>, super::Failure> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(path, &format!("{field} must be an object")))
}

fn array<'a>(
    value: Option<&'a Value>,
    path: &str,
    field: &str,
) -> Result<&'a [Value], super::Failure> {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(path, &format!("{field} must be an array")))
}

fn string<'a>(
    value: Option<&'a Value>,
    path: &str,
    field: &str,
) -> Result<&'a str, super::Failure> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(path, &format!("{field} must be a string")))
}

fn require_text(value: Option<&Value>, path: &str, field: &str) -> Result<(), super::Failure> {
    string(value, path, field).map(|_| ())
}

fn require_nonempty_text(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<(), super::Failure> {
    string(value, path, field)
        .and_then(|value| {
            if value.is_empty() {
                Err(invalid(path, &format!("{field} must not be empty")))
            } else {
                Ok(value)
            }
        })
        .map(|_| ())
}

fn nullable_text(
    value: Option<&Value>,
    path: &str,
    field: &str,
    nonempty: bool,
) -> Result<(), super::Failure> {
    match value {
        Some(Value::Null) => Ok(()),
        Some(Value::String(value)) if !nonempty || !value.is_empty() => Ok(()),
        _ => Err(invalid(
            path,
            &format!(
                "{field} must be {}text or null",
                if nonempty { "non-empty " } else { "" }
            ),
        )),
    }
}

fn require_text_eq(
    object: &Map<String, Value>,
    field: &str,
    expected: &str,
    path: &str,
    context: &str,
) -> Result<(), super::Failure> {
    if object.get(field).and_then(Value::as_str) != Some(expected) {
        return Err(invalid(
            path,
            &format!("{context}.{field} must be {expected}"),
        ));
    }
    Ok(())
}

fn string_array(
    value: Option<&Value>,
    path: &str,
    field: &str,
    allow_empty: bool,
) -> Result<Vec<String>, super::Failure> {
    let values = array(value, path, field)?;
    values
        .iter()
        .map(|value| {
            let value = string(Some(value), path, field)?;
            if !allow_empty && value.is_empty() {
                return Err(invalid(
                    path,
                    &format!("{field} must contain non-empty strings"),
                ));
            }
            Ok(value.to_owned())
        })
        .collect()
}

fn ensure_sorted_unique(values: &[String], path: &str, field: &str) -> Result<(), super::Failure> {
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(invalid(
            path,
            &format!("{field} must be sorted and unique by Unicode code point"),
        ));
    }
    Ok(())
}

fn safe_nonnegative_integer(
    value: Option<&Value>,
    path: &str,
    field: &str,
) -> Result<u64, super::Failure> {
    let number = value
        .and_then(Value::as_f64)
        .filter(|number| number.is_finite() && *number >= 0.0 && number.fract() == 0.0)
        .filter(|number| *number <= 9_007_199_254_740_991.0)
        .ok_or_else(|| {
            invalid(
                path,
                &format!("{field} must be a safe non-negative integer"),
            )
        })?;
    Ok(number as u64)
}

fn invalid(path: &str, reason: &str) -> super::Failure {
    super::invalid(path, reason)
}
