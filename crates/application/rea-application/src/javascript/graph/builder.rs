//! `JavaScriptArtifactGraphBuilder`: compose the application graph from
//! inventory, file and analysis facts.

use std::{borrow::Cow, collections::HashMap};

use super::application_graph::{Accumulator, GraphInput, seal_graph};
use super::bundlers::add_bundler_nodes;
use super::context::{
    GraphContext, html_inline_script_location_limit, omitted_html_inline_script_locations,
    self_reference_omissions,
};
use super::documents::{add_html_roles, add_source_map_originals};
use super::electron::{add_electron_boundaries, classify_pairings, collect_ipc_records};
use super::evidence::{complete_coverage, partial_coverage, truncated_coverage};
use super::findings::add_static_findings;
use super::json::{Json, js_int};
use super::leaves::{
    analysis_coverage_limits, semantic_resource_limit_coverage, semantic_resource_limit_reason,
    semantic_resource_limits,
};
use super::modules::{add_module_relationships, add_source_modules};
use super::resolution::ArtifactPathResolver;
use super::structure::{add_containers, add_files, add_package_nodes, create_root_node};

/// `ELECTRON_IDENTITY_LIMITATION`.
pub const ELECTRON_IDENTITY_LIMITATION: &str = "Electron API identity follows proven lexical module aliases and structurally verified module-namespace interop. Other reassignments, dynamic selections, and visibly overwritten namespace members are unresolved; missing findings do not establish absence. Arbitrary call side effects and runtime registration are not evaluated.";

/// Why graph construction could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationGraphError {
    /// The inventory snapshot does not name its root node.
    MissingInventoryRoot,
}

/// `buildImmutableJavaScriptArtifactGraphSteps`: the sealed application graph.
///
/// `snapshot` needs `manifest`, the root entry of `nodes` and
/// `integrity_contradictions`; `file_set` is the JavaScript artifact file set
/// metadata and `analysis` the module artifact analysis, including source
/// text owned by analyzed file records.
pub fn build_application_graph(
    snapshot: &Json,
    file_set: &Json,
    analysis: &Json,
    resolver: &dyn ArtifactPathResolver,
) -> Result<Json, ApplicationGraphError> {
    let mut accumulator = Accumulator::default();
    let root = create_root_node(&mut accumulator, snapshot)
        .ok_or(ApplicationGraphError::MissingInventoryRoot)?;
    let mut container_nodes = HashMap::new();
    container_nodes.insert(
        snapshot.at("manifest").at("root_sha256").str().to_owned(),
        root.clone(),
    );
    // Analysis records own the authenticated source text. The file-set JSON
    // passed here contains metadata only, so indexing it would discard source
    // facts needed by relationship and finding builders.
    let files_by_path = analysis
        .at("files")
        .arr()
        .iter()
        .filter_map(|entry| {
            let file = entry.get("file")?;
            Some((file.at("path").text().clone(), file.clone()))
        })
        .collect();
    let mut context = GraphContext {
        accumulator,
        snapshot,
        file_set,
        raw_analysis: analysis,
        analysis: admitted_analysis(analysis),
        root: root.clone(),
        files_by_path,
        file_nodes: HashMap::new(),
        asset_nodes: HashMap::new(),
        source_module_nodes: HashMap::new(),
        chunk_nodes: HashMap::new(),
        module_nodes: HashMap::new(),
        container_nodes,
        resolver,
    };
    add_containers(&mut context);
    add_files(&mut context);
    let package_roots = add_package_nodes(&mut context);
    add_source_modules(&mut context);
    let bundler_limitations = add_bundler_nodes(&mut context);
    let self_imports = add_module_relationships(&mut context);
    let finding_limitations = add_static_findings(&mut context);
    add_electron_boundaries(&mut context);
    add_html_roles(&mut context);
    add_source_map_originals(&mut context);
    let coverage = graph_coverage(&context);
    let mut limitations = bundler_limitations;
    limitations.extend(finding_limitations);
    limitations.extend(graph_limitations(
        &context,
        coverage.at("status").str(),
        self_imports,
    ));
    let root_node_ids = if package_roots.is_empty() {
        vec![root.node_id]
    } else {
        package_roots.into_iter().map(|node| node.node_id).collect()
    };
    let nodes = context.accumulator.nodes();
    let edges = context.accumulator.edges();
    Ok(seal_graph(GraphInput {
        root_node_ids,
        nodes,
        edges,
        coverage,
        limitations,
    }))
}

/// Raw observations stay on file nodes; relationship builders see only admitted expansions.
fn admitted_analysis<'a>(analysis: &'a Json) -> Cow<'a, Json> {
    if !analysis
        .at("files")
        .arr()
        .iter()
        .any(|file| file.get("application_projection_failure").is_some())
    {
        return Cow::Borrowed(analysis);
    }
    let mut admitted = analysis.obj();
    let files = analysis
        .at("files")
        .arr()
        .iter()
        .map(|file| {
            if file.get("application_projection_failure").is_none() {
                return file.clone();
            }
            let mut object = file.obj();
            object.set("javascript", Json::Null);
            object.set("semantic", Json::Null);
            object.into()
        })
        .collect();
    admitted.set("files", Json::array(files));
    Cow::Owned(admitted.into())
}

fn sorted_semantic_limits(analysis: &Json) -> Vec<String> {
    let mut limits: Vec<String> = Vec::new();
    for file in analysis.at("files").arr() {
        let semantic = file.at("semantic");
        if semantic.is_null() {
            continue;
        }
        let metadata_coverage = semantic.at("metadata").at("coverage");
        let coverage = if metadata_coverage.is_null() {
            semantic.at("ir").at("coverage")
        } else {
            metadata_coverage
        };
        for limit in semantic_resource_limits(coverage) {
            if !limits.contains(&limit) {
                limits.push(limit);
            }
        }
    }
    limits.sort_by(|left, right| super::json::compare_utf16_str(left, right));
    limits
}

fn graph_coverage(context: &GraphContext<'_>) -> Json {
    let analysis = context.raw_analysis;
    let resource_limits = sorted_semantic_limits(analysis);
    let files = analysis.at("files").arr();
    let source_maps = analysis.at("source_maps").arr();
    let source_map_gap = source_maps
        .iter()
        .any(|map| map.at("status").str() == "invalid");
    let malformed = analysis
        .at("packages")
        .arr()
        .iter()
        .any(|package| package.at("status").str() != "included")
        || analysis
            .at("json_modules")
            .arr()
            .iter()
            .any(|json| json.at("status").str() != "included")
        || source_map_gap;
    let partial_javascript = files.iter().any(|file| {
        let javascript = file.at("javascript");
        !javascript.is_null() && javascript.at("parse_status").str() == "partial"
    });
    let file_set = context.file_set;
    let unknown_gap = file_set.at("source_selection").at("unselected_files").num() > 0.0
        || !file_set.at("unavailable_relevant_files").arr().is_empty()
        || files.iter().any(|file| {
            file.get("analysis_failure").is_some()
                || file.get("application_projection_failure").is_some()
        })
        || analysis.at("parse_failures").num() > 0.0
        || file_set.at("invalid_utf8_files").num() > 0.0
        || !analysis.at("html_inline_scripts").arr().is_empty()
        || source_map_gap
        || malformed
        || partial_javascript;
    let execution_limits: Vec<Json> = files
        .iter()
        .flat_map(|file| {
            ["analysis_failure", "application_projection_failure"]
                .into_iter()
                .filter_map(|key| file.get(key))
                .flat_map(|failure| analysis_coverage_limits(failure.at("limits")))
                .collect::<Vec<_>>()
        })
        .collect();
    let inline_truncated =
        omitted_html_inline_script_locations(analysis.at("html_inline_scripts").arr()) > 0.0;
    if !resource_limits.is_empty() || !execution_limits.is_empty() || inline_truncated {
        let mut limits: Vec<(String, Json)> = Vec::new();
        let mut all = semantic_resource_limit_coverage(&resource_limits);
        all.extend(execution_limits);
        if inline_truncated {
            all.push(html_inline_script_location_limit());
        }
        for limit in all {
            let key = limit.stringify();
            if let Some(entry) = limits.iter_mut().find(|(existing, _)| *existing == key) {
                entry.1 = limit;
            } else {
                limits.push((key, limit));
            }
        }
        let limits = limits.into_iter().map(|(_, limit)| limit).collect();
        return if inline_truncated {
            truncated_coverage(limits, None)
        } else {
            partial_coverage(limits, None)
        };
    }
    if unknown_gap {
        return partial_coverage(Vec::new(), None);
    }
    let contradictions = context.snapshot.at("integrity_contradictions").arr();
    if !contradictions.is_empty() {
        let opaque = contradictions.iter().any(|contradiction| {
            contradiction
                .at("logical_path")
                .str()
                .to_lowercase()
                .ends_with(".asar")
        });
        return partial_coverage(Vec::new(), if opaque { None } else { Some(0.0) });
    }
    complete_coverage()
}

fn graph_limitations(
    context: &GraphContext<'_>,
    coverage: &str,
    self_imports: usize,
) -> Vec<String> {
    let analysis = context.raw_analysis;
    let records = collect_ipc_records(analysis);
    let pairings = classify_pairings(&records);
    let javascript: Vec<&Json> = analysis
        .at("files")
        .arr()
        .iter()
        .map(|file| file.at("javascript"))
        .filter(|value| !value.is_null())
        .collect();
    let electron_findings: usize = javascript
        .iter()
        .map(|value| {
            let electron = value.at("electron");
            [
                "browser_windows",
                "context_bridge_apis",
                "ipc",
                "sender_validations",
                "utility_processes",
                "native_addon_bindings",
            ]
            .iter()
            .map(|key| electron.at(key).arr().len())
            .sum::<usize>()
        })
        .sum();
    let mut limitations: Vec<String> = analysis
        .at("limitations")
        .arr()
        .iter()
        .map(|value| value.str().to_owned())
        .collect();
    if let Some(selection) = context.file_set.get("source_selection") {
        limitations.push(format!(
            "Caller-selected source analysis leaves {} inventoried files outside analysis scope. Inventory identity covers the complete artifact; relationships through unselected sources remain unknown.",
            js_int(selection.at("unselected_files").num())
        ));
    }
    for contradiction in context.snapshot.at("integrity_contradictions").arr() {
        limitations.push(format!(
            "Artifact integrity metadata contradicts observed bytes at {}; the observed bytes are untrusted.",
            contradiction.at("logical_path").str()
        ));
    }
    limitations.extend(self_reference_omissions(
        self_imports,
        "import specifier",
        "import specifiers",
        "the importing module",
    ));
    limitations.extend(
        [
            "CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.",
            "Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.",
            "Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.",
        ]
        .map(str::to_owned),
    );
    if javascript.iter().any(|value| {
        value
            .at("limitations")
            .arr()
            .iter()
            .any(|item| item.str() == ELECTRON_IDENTITY_LIMITATION)
    }) {
        limitations.push(ELECTRON_IDENTITY_LIMITATION.to_owned());
    }
    if electron_findings > 0 {
        limitations.push("Electron relationships are derived from inert syntax; runtime registration, reachability, defaults, and enforcement remain unproven.".to_owned());
    }
    if records
        .iter()
        .any(|record| record.finding.at("channel").is_null())
    {
        limitations.push("Dynamic IPC channel expressions remain unresolved and are never paired by textual similarity.".to_owned());
    }
    if pairings.iter().any(|(_, candidates)| candidates.len() > 1) {
        limitations.push("Some literal IPC channels have multiple compatible main handlers; ambiguous calls are not paired to any handler.".to_owned());
    }
    if javascript.iter().any(|value| {
        !value
            .at("electron")
            .at("sender_validations")
            .arr()
            .is_empty()
    }) {
        limitations.push("Sender, frame, URL, and origin checks are observations only; REA does not claim that they enforce a complete authorization policy.".to_owned());
    }
    limitations.extend(
        sorted_semantic_limits(analysis)
            .iter()
            .map(|limit| semantic_resource_limit_reason(limit).to_owned()),
    );
    if javascript.iter().any(|value| {
        !value
            .at("electron")
            .at("native_addon_bindings")
            .arr()
            .is_empty()
    }) {
        limitations.push("Native member names are requested by JavaScript syntax and are not verified binary exports in this workflow.".to_owned());
    }
    if coverage != "complete" {
        limitations.push("Graph coverage is incomplete; unavailable facts remain explicit and must not be read as absence.".to_owned());
    }
    limitations
}
