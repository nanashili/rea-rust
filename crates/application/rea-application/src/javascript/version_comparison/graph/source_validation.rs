//! Boundary validation for application graph result envelopes.
//!
//! The comparison domain consumes only graph facts, but the graph is trusted
//! only after the complete producer result has been checked.  These helpers
//! intentionally validate the result shapes at this boundary instead of
//! rediscovering producer facts in matching or projection code.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const OPERATION: &str = "compare_application_versions";

pub(super) fn static_result(result: &Value, side: &str) -> Result<(), Failure> {
    let object = object(Some(result), side, "normalized_result")?;
    exact_fields_with_optional(
        object,
        &[
            "input_path",
            "format",
            "root_artifact_sha256",
            "inventory_manifest_id",
            "inventory_graph_sha256",
            "integrity_contradictions",
            "source_selection",
            "graph",
            "summary",
            "statistics",
            "limitations",
            "semantic_graph",
        ],
        &["source_selection"],
        side,
        "static result",
    )?;
    nonempty(object.get("input_path"), side, "input_path")?;
    enum_text(object.get("format"), side, "format", &["asar", "directory"])?;
    digest(
        object.get("root_artifact_sha256"),
        side,
        "root_artifact_sha256",
    )?;
    prefixed(
        object.get("inventory_manifest_id"),
        side,
        "inventory_manifest_id",
        "agm_",
    )?;
    digest(
        object.get("inventory_graph_sha256"),
        side,
        "inventory_graph_sha256",
    )?;
    let contradictions = array(
        object.get("integrity_contradictions"),
        side,
        "integrity_contradictions",
    )?;
    for contradiction in contradictions {
        validate_contradiction(contradiction, side)?;
    }
    if let Some(selection) = object.get("source_selection") {
        validate_source_selection(selection, side)?;
    }
    object_value(object.get("graph"), side, "graph")?;
    validate_summary(object.get("summary"), side)?;
    validate_statistics(object.get("statistics"), side)?;
    nonempty_string_array(object.get("limitations"), side, "limitations")?;
    validate_semantic_graph(
        object.get("semantic_graph"),
        object.get("graph"),
        object.get("root_artifact_sha256"),
        side,
    )?;
    Ok(())
}

pub(super) fn runtime_result(result: &Value, side: &str) -> Result<(), Failure> {
    let object = object(Some(result), side, "normalized_result")?;
    exact_fields(
        object,
        &[
            "reconciliation_id",
            "static_layers",
            "runtime_captures",
            "graph",
            "summary",
            "reconciliations",
            "static_load_states",
            "source_map_authority",
            "coverage",
            "evidence_links",
            "limitations",
        ],
        side,
        "runtime result",
        false,
    )?;
    prefixed(
        object.get("reconciliation_id"),
        side,
        "reconciliation_id",
        "jrr_",
    )?;
    let layers = array(object.get("static_layers"), side, "static_layers")?;
    if layers.is_empty() {
        return Err(invalid(side, "static_layers must not be empty"));
    }
    for layer in layers {
        validate_layer(layer, side)?;
    }
    let captures = array(object.get("runtime_captures"), side, "runtime_captures")?;
    if captures.is_empty() {
        return Err(invalid(side, "runtime_captures must not be empty"));
    }
    for capture in captures {
        validate_capture(capture, side)?;
    }
    object_value(object.get("graph"), side, "graph")?;
    validate_runtime_summary(object.get("summary"), side)?;
    for item in array(object.get("reconciliations"), side, "reconciliations")? {
        validate_reconciliation(item, side)?;
    }
    for item in array(object.get("static_load_states"), side, "static_load_states")? {
        validate_load_state(item, side)?;
    }
    validate_source_map_authority(object.get("source_map_authority"), side)?;
    validate_runtime_coverage(object.get("coverage"), side)?;
    let links = array(object.get("evidence_links"), side, "evidence_links")?;
    if links.len() < 2 {
        return Err(invalid(
            side,
            "runtime evidence_links must contain at least two identifiers",
        ));
    }
    for link in links {
        prefixed(Some(link), side, "evidence_links", "ev_")?;
    }
    nonempty_string_array(object.get("limitations"), side, "limitations")?;
    Ok(())
}

pub(super) fn managed_result(result: &Value, side: &str) -> Result<(), Failure> {
    let object = object(Some(result), side, "normalized_result")?;
    exact_fields(
        object,
        &[
            "projection_id",
            "root_artifact_sha256",
            "source_evidence",
            "summary",
            "graph",
            "coverage",
            "evidence_links",
            "limitations",
        ],
        side,
        "managed result",
        false,
    )?;
    prefixed(object.get("projection_id"), side, "projection_id", "magp_")?;
    digest(
        object.get("root_artifact_sha256"),
        side,
        "root_artifact_sha256",
    )?;
    validate_source_evidence(object.get("source_evidence"), side)?;
    validate_managed_summary(object.get("summary"), side)?;
    object_value(object.get("graph"), side, "graph")?;
    let coverage = object_value(object.get("coverage"), side, "coverage")?;
    exact_fields(coverage, &["status"], side, "coverage", false)?;
    enum_text(
        coverage.get("status"),
        side,
        "coverage.status",
        &["complete-within-inputs", "partial"],
    )?;
    let links = array(object.get("evidence_links"), side, "evidence_links")?;
    if links.is_empty() || links.len() > 3 {
        return Err(invalid(
            side,
            "managed evidence_links must contain one to three identifiers",
        ));
    }
    for link in links {
        prefixed(Some(link), side, "evidence_links", "ev_")?;
    }
    nonempty_string_array(object.get("limitations"), side, "limitations")?;
    Ok(())
}

fn validate_contradiction(value: &Value, side: &str) -> Result<(), Failure> {
    let object = object(Some(value), side, "integrity_contradiction")?;
    prefixed(
        object.get("contradiction_id"),
        side,
        "contradiction_id",
        "ic_",
    )?;
    prefixed(object.get("occurrence_id"), side, "occurrence_id", "occ_")?;
    prefixed(
        object.get("parent_artifact_id"),
        side,
        "parent_artifact_id",
        "art_",
    )?;
    nonempty(object.get("logical_path"), side, "logical_path")?;
    digest(object.get("declared_sha256"), side, "declared_sha256")?;
    digest(object.get("observed_sha256"), side, "observed_sha256")?;
    enum_text(
        object.get("entry_kind"),
        side,
        "entry_kind",
        &["file", "slice"],
    )?;
    boolean(object.get("unpacked"), side, "unpacked")?;
    enum_text(object.get("trust"), side, "trust", &["observed-untrusted"])?;
    enum_text(
        object.get("provenance"),
        side,
        "provenance",
        &["container-integrity-metadata-versus-observed-bytes"],
    )?;
    let limitations = nonempty_string_array(object.get("limitations"), side, "limitations")?;
    if limitations.is_empty() {
        return Err(invalid(side, "contradictions require a limitation"));
    }
    Ok(())
}

fn validate_source_selection(value: &Value, side: &str) -> Result<(), Failure> {
    let object = object(Some(value), side, "source_selection")?;
    exact_fields(
        object,
        &["requested_paths", "unselected_files"],
        side,
        "source_selection",
        false,
    )?;
    let paths = array(object.get("requested_paths"), side, "requested_paths")?;
    if paths.is_empty() {
        return Err(invalid(side, "requested_paths must not be empty"));
    }
    for path in paths {
        nonempty(Some(path), side, "requested_path")?;
    }
    nonnegative(object.get("unselected_files"), side, "unselected_files")?;
    Ok(())
}

fn validate_summary(value: Option<&Value>, side: &str) -> Result<(), Failure> {
    let summary = object(value, side, "summary")?;
    let fields = [
        "browser_windows",
        "explicit_web_preferences",
        "preload_entrypoints",
        "context_bridge_apis",
        "exposed_api_members",
        "sender_validation_observations",
        "utility_processes",
        "resolved_utility_entrypoints",
        "native_addon_bindings",
        "resolved_native_addon_bindings",
    ];
    exact_fields(
        summary,
        &[
            "browser_windows",
            "explicit_web_preferences",
            "preload_entrypoints",
            "context_bridge_apis",
            "exposed_api_members",
            "ipc",
            "sender_validation_observations",
            "utility_processes",
            "resolved_utility_entrypoints",
            "native_addon_bindings",
            "resolved_native_addon_bindings",
        ],
        side,
        "summary",
        false,
    )?;
    for field in fields {
        nonnegative(summary.get(field), side, field)?;
    }
    let ipc = object(summary.get("ipc"), side, "summary.ipc")?;
    exact_fields(
        ipc,
        &[
            "operations",
            "literal_channels",
            "dynamic_channel_operations",
            "renderer_transmissions",
            "renderer_listeners",
            "main_handlers",
            "paired_renderer_transmissions",
            "ambiguous_renderer_transmissions",
            "unpaired_literal_renderer_transmissions",
        ],
        side,
        "summary.ipc",
        false,
    )?;
    for value in ipc.values() {
        nonnegative(Some(value), side, "summary.ipc.count")?;
    }
    Ok(())
}

fn validate_statistics(value: Option<&Value>, side: &str) -> Result<(), Failure> {
    let object = object(value, side, "statistics")?;
    exact_fields_with_optional(
        object,
        &[
            "relevant_files",
            "nested_asar_containers",
            "text_bytes_read",
            "invalid_utf8_files",
            "parsed_javascript_files",
            "skipped_javascript_files",
            "visited_ast_nodes",
            "findings",
            "modules",
            "parse_failures",
        ],
        &["skipped_javascript_files"],
        side,
        "statistics",
    )?;
    for (name, value) in object {
        if name != "skipped_javascript_files" || !value.is_null() {
            nonnegative(Some(value), side, name)?;
        }
    }
    Ok(())
}

fn validate_semantic_graph(
    value: Option<&Value>,
    application_graph: Option<&Value>,
    root: Option<&Value>,
    side: &str,
) -> Result<(), Failure> {
    let semantic = object(value, side, "semantic_graph")?;
    exact_fields(
        semantic,
        &[
            "schema",
            "root_artifact_sha256",
            "application_graph_id",
            "root_node_ids",
            "evidence_contexts",
            "nodes",
            "relations",
            "fingerprints",
            "unknowns",
            "coverage",
            "limitations",
            "graph_id",
        ],
        side,
        "semantic_graph",
        false,
    )?;
    enum_text(
        semantic.get("schema"),
        side,
        "semantic_graph.schema",
        &["JavaScriptSemanticRelationGraph"],
    )?;
    if semantic.get("root_artifact_sha256") != root {
        return Err(invalid(
            side,
            "semantic graph root artifact does not match result",
        ));
    }
    let graph_id = object_value(application_graph, side, "graph")?.get("graph_id");
    if semantic.get("application_graph_id") != graph_id {
        return Err(invalid(
            side,
            "semantic graph application graph binding is stale",
        ));
    }
    prefixed(
        semantic.get("graph_id"),
        side,
        "semantic_graph.graph_id",
        "jsrg_",
    )?;
    let nodes = array(semantic.get("nodes"), side, "semantic_graph.nodes")?;
    if nodes.is_empty() {
        return Err(invalid(side, "semantic graph must contain nodes"));
    }
    let node_ids = nodes
        .iter()
        .map(|node| {
            node.get("node_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    for node in nodes {
        let node = object(Some(node), side, "semantic node")?;
        prefixed(node.get("node_id"), side, "semantic node_id", "jsrg_node_")?;
        for id in array(
            node.get("application_node_ids"),
            side,
            "application_node_ids",
        )? {
            let id = id
                .as_str()
                .ok_or_else(|| invalid(side, "application_node_ids must contain strings"))?;
            let application_nodes = array(
                object_value(application_graph, side, "graph")?.get("nodes"),
                side,
                "graph.nodes",
            )?;
            let present = application_nodes
                .iter()
                .any(|candidate| candidate.get("node_id").and_then(Value::as_str) == Some(id));
            if !present {
                return Err(invalid(
                    side,
                    "semantic node references an absent application node",
                ));
            }
        }
    }
    for root_id in array(
        semantic.get("root_node_ids"),
        side,
        "semantic_graph.root_node_ids",
    )? {
        let id = root_id
            .as_str()
            .ok_or_else(|| invalid(side, "semantic roots must contain strings"))?;
        if !node_ids.contains(id) {
            return Err(invalid(side, "semantic root names an absent node"));
        }
    }
    Ok(())
}

fn validate_layer(value: &Value, side: &str) -> Result<(), Failure> {
    let object = object(Some(value), side, "static layer")?;
    exact_fields(
        object,
        &[
            "layer_id",
            "role",
            "evidence_id",
            "graph_id",
            "root_artifact_sha256",
            "input_path",
            "format",
            "runtime_mappings",
        ],
        side,
        "static layer",
        false,
    )?;
    prefixed(object.get("layer_id"), side, "layer_id", "jrl_")?;
    enum_text(
        object.get("role"),
        side,
        "role",
        &["application", "cache", "assets"],
    )?;
    prefixed(object.get("evidence_id"), side, "evidence_id", "ev_")?;
    prefixed(object.get("graph_id"), side, "graph_id", "jag_")?;
    digest(
        object.get("root_artifact_sha256"),
        side,
        "root_artifact_sha256",
    )?;
    nonempty(object.get("input_path"), side, "input_path")?;
    enum_text(object.get("format"), side, "format", &["asar", "directory"])?;
    for mapping in array(object.get("runtime_mappings"), side, "runtime_mappings")? {
        validate_runtime_mapping(mapping, side)?;
    }
    Ok(())
}

fn validate_runtime_mapping(value: &Value, side: &str) -> Result<(), Failure> {
    let object = object(Some(value), side, "runtime mapping")?;
    enum_text(
        object.get("kind"),
        side,
        "runtime mapping kind",
        &["file-root", "url-prefix"],
    )?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    exact_fields(
        object,
        &[
            "kind",
            if kind == "file-root" {
                "root"
            } else {
                "prefix"
            },
            "artifact_prefix",
        ],
        side,
        "runtime mapping",
        false,
    )?;
    nonempty(
        object.get(if kind == "file-root" {
            "root"
        } else {
            "prefix"
        }),
        side,
        "runtime mapping source",
    )?;
    nonempty_or_empty(object.get("artifact_prefix"), side, "artifact_prefix")?;
    Ok(())
}

fn validate_capture(value: &Value, side: &str) -> Result<(), Failure> {
    let object = object(Some(value), side, "runtime capture")?;
    exact_fields(
        object,
        &[
            "evidence_id",
            "capture_sha256",
            "kind",
            "target_node_id",
            "target_key",
            "target_location",
            "frames",
            "scripts",
            "workers",
            "scripts_complete_within_scope",
        ],
        side,
        "runtime capture",
        false,
    )?;
    prefixed(object.get("evidence_id"), side, "evidence_id", "ev_")?;
    digest(object.get("capture_sha256"), side, "capture_sha256")?;
    enum_text(
        object.get("kind"),
        side,
        "kind",
        &["browser", "electron", "v8-inspector", "electron-active"],
    )?;
    prefixed(
        object.get("target_node_id"),
        side,
        "target_node_id",
        "jag_node_",
    )?;
    nonempty(object.get("target_key"), side, "target_key")?;
    validate_runtime_location(object.get("target_location"), side)?;
    nonnegative(object.get("frames"), side, "frames")?;
    nonnegative(object.get("scripts"), side, "scripts")?;
    nonnegative(object.get("workers"), side, "workers")?;
    boolean(
        object.get("scripts_complete_within_scope"),
        side,
        "scripts_complete_within_scope",
    )?;
    Ok(())
}

fn validate_runtime_location(value: Option<&Value>, side: &str) -> Result<(), Failure> {
    if value
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
    {
        return Ok(());
    }

    let object = object(value, side, "target_location")?;
    exact_fields(
        object,
        &["kind", "reported_url", "reason"],
        side,
        "unresolved target location",
        false,
    )?;
    enum_text(
        object.get("kind"),
        side,
        "target_location.kind",
        &["unresolved"],
    )?;
    enum_text(
        object.get("reason"),
        side,
        "target_location.reason",
        &[
            "unverifiable-file-location",
            "location-authorization-not-attempted",
        ],
    )?;

    Ok(())
}

fn validate_runtime_summary(value: Option<&Value>, side: &str) -> Result<(), Failure> {
    let object = object(value, side, "summary")?;
    exact_fields(
        object,
        &[
            "runtime_targets",
            "runtime_frames",
            "runtime_scripts",
            "runtime_workers",
            "matched",
            "ambiguous",
            "unmatched",
            "unknown",
            "static_loaded",
            "static_resident",
            "static_not_observed",
            "static_unknown",
        ],
        side,
        "summary",
        false,
    )?;
    for field in [
        "runtime_targets",
        "runtime_frames",
        "runtime_scripts",
        "runtime_workers",
        "matched",
        "ambiguous",
        "unmatched",
        "unknown",
        "static_loaded",
        "static_resident",
        "static_not_observed",
        "static_unknown",
    ] {
        nonnegative(object.get(field), side, field)?;
    }
    Ok(())
}

fn validate_reconciliation(value: &Value, side: &str) -> Result<(), Failure> {
    let reconciliation = object(Some(value), side, "reconciliation")?;
    exact_fields(
        reconciliation,
        &[
            "reconciliation_id",
            "entity_kind",
            "runtime_evidence_id",
            "runtime_node_id",
            "basis",
            "confidence",
            "reason",
            "candidate_static_count",
            "candidate_static_nodes",
            "static_layer_id",
            "static_node_id",
            "status",
        ],
        side,
        "reconciliation",
        false,
    )?;
    prefixed(
        reconciliation.get("reconciliation_id"),
        side,
        "reconciliation_id",
        "jrr_item_",
    )?;
    enum_text(
        reconciliation.get("entity_kind"),
        side,
        "entity_kind",
        &["target", "frame", "script", "worker"],
    )?;
    prefixed(
        reconciliation.get("runtime_evidence_id"),
        side,
        "runtime_evidence_id",
        "ev_",
    )?;
    prefixed(
        reconciliation.get("runtime_node_id"),
        side,
        "runtime_node_id",
        "jag_node_",
    )?;
    enum_text(
        reconciliation.get("basis"),
        side,
        "basis",
        &[
            "content-and-location",
            "content-sha256",
            "module-source-sha256",
            "artifact-path",
            "operator-file-mapping",
            "operator-url-mapping",
            "none",
        ],
    )?;
    enum_text(
        reconciliation.get("confidence"),
        side,
        "confidence",
        &["exact", "high", "medium", "low", "unknown"],
    )?;
    enum_text(
        reconciliation.get("reason"),
        side,
        "reason",
        &[
            "content-and-location-match",
            "unique-content-match",
            "unique-location-match",
            "ambiguous-static-candidates",
            "captured-content-disagrees-with-static-location",
            "no-static-content-match",
            "no-authorized-location-mapping",
            "runtime-location-unresolved",
            "runtime-frame-unattributed",
            "static-or-runtime-coverage-incomplete",
            "reconciliation-limit-reached",
        ],
    )?;
    nonnegative(
        reconciliation.get("candidate_static_count"),
        side,
        "candidate_static_count",
    )?;
    for candidate in array(
        reconciliation.get("candidate_static_nodes"),
        side,
        "candidate_static_nodes",
    )? {
        let candidate = object(Some(candidate), side, "candidate static node")?;
        exact_fields(
            candidate,
            &["static_layer_id", "static_node_id"],
            side,
            "candidate static node",
            false,
        )?;
        prefixed(
            candidate.get("static_layer_id"),
            side,
            "static_layer_id",
            "jrl_",
        )?;
        prefixed(
            candidate.get("static_node_id"),
            side,
            "static_node_id",
            "jag_node_",
        )?;
    }
    enum_text(
        reconciliation.get("status"),
        side,
        "status",
        &["matched", "ambiguous", "unmatched", "unknown"],
    )?;
    let status = reconciliation
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if status == "matched" {
        prefixed(
            reconciliation.get("static_layer_id"),
            side,
            "static_layer_id",
            "jrl_",
        )?;
        prefixed(
            reconciliation.get("static_node_id"),
            side,
            "static_node_id",
            "jag_node_",
        )?;
    } else if !reconciliation
        .get("static_layer_id")
        .is_some_and(Value::is_null)
        || !reconciliation
            .get("static_node_id")
            .is_some_and(Value::is_null)
    {
        return Err(invalid(
            side,
            "unmatched reconciliation must use null static identifiers",
        ));
    }
    Ok(())
}

fn validate_load_state(value: &Value, side: &str) -> Result<(), Failure> {
    let object = object(Some(value), side, "static load state")?;
    exact_fields(
        object,
        &[
            "static_layer_id",
            "static_node_id",
            "kind",
            "status",
            "runtime_node_ids",
            "reason",
        ],
        side,
        "static load state",
        false,
    )?;
    prefixed(
        object.get("static_layer_id"),
        side,
        "static_layer_id",
        "jrl_",
    )?;
    prefixed(
        object.get("static_node_id"),
        side,
        "static_node_id",
        "jag_node_",
    )?;
    enum_text(
        object.get("kind"),
        side,
        "kind",
        &["javascript-asset", "javascript-chunk", "javascript-module"],
    )?;
    enum_text(
        object.get("status"),
        side,
        "status",
        &[
            "loaded",
            "resident-in-loaded-asset",
            "not-observed-in-capture",
            "unknown",
        ],
    )?;
    for id in array(object.get("runtime_node_ids"), side, "runtime_node_ids")? {
        prefixed(Some(id), side, "runtime_node_id", "jag_node_")?;
    }
    enum_text(
        object.get("reason"),
        side,
        "reason",
        &[
            "runtime-script-correspondence",
            "containing-asset-was-loaded",
            "not-observed-in-bounded-capture",
            "layer-outside-runtime-scope",
            "static-or-runtime-coverage-incomplete",
            "ambiguous-runtime-candidate",
        ],
    )?;
    Ok(())
}
fn validate_source_map_authority(value: Option<&Value>, side: &str) -> Result<(), Failure> {
    let object = object(value, side, "source_map_authority")?;
    exact_fields(
        object,
        &[
            "used_for_primary_matching",
            "static_layer_count",
            "runtime_script_declarations",
            "limitation",
        ],
        side,
        "source_map_authority",
        false,
    )?;
    if object.get("used_for_primary_matching") != Some(&Value::Bool(false)) {
        return Err(invalid(
            side,
            "source map must not provide primary matching",
        ));
    }
    nonnegative(object.get("static_layer_count"), side, "static_layer_count")?;
    nonnegative(
        object.get("runtime_script_declarations"),
        side,
        "runtime_script_declarations",
    )?;
    nonempty(object.get("limitation"), side, "limitation")
}

fn validate_runtime_coverage(value: Option<&Value>, side: &str) -> Result<(), Failure> {
    let object = object(value, side, "coverage")?;
    exact_fields(
        object,
        &[
            "status",
            "truncated",
            "omitted_runtime_entities",
            "omitted_reconciliation_items",
            "omitted_static_load_states",
            "omitted_graph_items",
        ],
        side,
        "coverage",
        false,
    )?;
    enum_text(
        object.get("status"),
        side,
        "coverage.status",
        &["complete-within-inputs", "partial", "truncated"],
    )?;
    boolean(object.get("truncated"), side, "coverage.truncated")?;
    for field in [
        "omitted_runtime_entities",
        "omitted_reconciliation_items",
        "omitted_static_load_states",
        "omitted_graph_items",
    ] {
        nonnegative(object.get(field), side, field)?;
    }
    Ok(())
}

fn validate_source_evidence(value: Option<&Value>, side: &str) -> Result<(), Failure> {
    let object = object(value, side, "source_evidence")?;
    exact_fields(
        object,
        &[
            "managed_artifact_evidence_id",
            "managed_members_evidence_id",
            "managed_native_boundaries_evidence_id",
        ],
        side,
        "source_evidence",
        false,
    )?;
    for value in object.values() {
        if !value.is_null() {
            prefixed(Some(value), side, "source_evidence", "ev_")?;
        }
    }
    Ok(())
}

fn validate_managed_summary(value: Option<&Value>, side: &str) -> Result<(), Failure> {
    let object = object(value, side, "summary")?;
    exact_fields(
        object,
        &[
            "graph_nodes",
            "graph_edges",
            "assemblies",
            "modules",
            "types",
            "methods",
            "fields",
            "pinvoke_imports",
            "native_implementations",
        ],
        side,
        "summary",
        false,
    )?;
    for field in [
        "graph_nodes",
        "graph_edges",
        "assemblies",
        "modules",
        "types",
        "methods",
        "fields",
        "pinvoke_imports",
        "native_implementations",
    ] {
        nonnegative(object.get(field), side, field)?;
    }
    Ok(())
}

fn object<'a>(
    value: Option<&'a Value>,
    side: &str,
    field: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(side, &format!("{field} must be an object")))
}
fn object_value<'a>(
    value: Option<&'a Value>,
    side: &str,
    field: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    object(value, side, field)
}
fn array<'a>(value: Option<&'a Value>, side: &str, field: &str) -> Result<&'a [Value], Failure> {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(side, &format!("{field} must be an array")))
}
fn exact_fields(
    object: &Map<String, Value>,
    expected: &[&str],
    side: &str,
    field: &str,
    _unused: bool,
) -> Result<(), Failure> {
    exact_fields_with_optional(object, expected, &[], side, field)
}

fn exact_fields_with_optional(
    object: &Map<String, Value>,
    expected: &[&str],
    optional: &[&str],
    side: &str,
    field: &str,
) -> Result<(), Failure> {
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected
        .iter()
        .copied()
        .filter(|name| !optional.contains(name) || object.contains_key(*name))
        .collect::<BTreeSet<_>>();

    if actual != expected {
        return Err(invalid(
            side,
            &format!("{field} has missing or unsupported fields"),
        ));
    }

    Ok(())
}
fn nonempty(value: Option<&Value>, side: &str, field: &str) -> Result<(), Failure> {
    match value.and_then(Value::as_str) {
        Some(text) if !text.is_empty() => Ok(()),
        _ => Err(invalid(side, &format!("{field} must be non-empty text"))),
    }
}
fn nonempty_or_empty(value: Option<&Value>, side: &str, field: &str) -> Result<(), Failure> {
    match value.and_then(Value::as_str) {
        Some(_) => Ok(()),
        _ => Err(invalid(side, &format!("{field} must be text"))),
    }
}
fn nonempty_string_array<'a>(
    value: Option<&'a Value>,
    side: &str,
    field: &str,
) -> Result<&'a [Value], Failure> {
    let values = array(value, side, field)?;
    for value in values {
        nonempty(Some(value), side, field)?;
    }
    Ok(values)
}
fn digest(value: Option<&Value>, side: &str, field: &str) -> Result<(), Failure> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(side, &format!("{field} must be a digest")))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(side, &format!("{field} must be lowercase SHA-256")));
    }
    Ok(())
}
fn prefixed(value: Option<&Value>, side: &str, field: &str, prefix: &str) -> Result<(), Failure> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(side, &format!("{field} must be a prefixed digest")))?;
    if !value.starts_with(prefix)
        || value[prefix.len()..].len() != 64
        || !value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            side,
            &format!("{field} has an invalid digest prefix"),
        ));
    }
    Ok(())
}
fn enum_text(
    value: Option<&Value>,
    side: &str,
    field: &str,
    values: &[&str],
) -> Result<(), Failure> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(side, &format!("{field} must be text")))?;
    if values.contains(&value) {
        Ok(())
    } else {
        Err(invalid(side, &format!("{field} has an unsupported value")))
    }
}
fn nonnegative(value: Option<&Value>, side: &str, field: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_u64).is_some() {
        Ok(())
    } else {
        Err(invalid(
            side,
            &format!("{field} must be a non-negative integer"),
        ))
    }
}
fn boolean(value: Option<&Value>, side: &str, field: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_bool).is_some() {
        Ok(())
    } else {
        Err(invalid(side, &format!("{field} must be boolean")))
    }
}
fn invalid(side: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Application graph Evidence result is invalid.".into(),
        false,
        "Provide a complete authenticated application graph result.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("side", Detail::Text(side.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
