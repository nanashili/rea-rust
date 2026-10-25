//! `JavaScriptArtifactGraphContext`: construction state and shared helpers.

use std::collections::HashMap;

use super::super::semantic::value_types::JsString;
use super::application_graph::{Accumulator, AppNode, EdgeInput, NodeInput, ObservationInput};
use super::evidence::{
    EvidenceInput, artifact_observation, ast_observation, complete_coverage, limit,
    partial_coverage, static_inference, truncated_coverage, unavailable_static,
};
use super::json::{Json, Obj, composite_key, js_int};
use super::resolution::{ArtifactPathResolver, ResolveRequest, limitations, resolution_properties};

/// `HTML_INLINE_SCRIPT_LOCATION_LIMIT`.
pub const HTML_INLINE_SCRIPT_LOCATION_LIMIT: f64 = 100.0;
const HTML_INLINE_SCRIPT_LIMITATION_LINES: usize = 10;

/// `HTML_INLINE_SCRIPT_LOCATION_COVERAGE_LIMIT`.
pub fn html_inline_script_location_limit() -> Json {
    limit(
        "html_inline_script_locations_per_file",
        HTML_INLINE_SCRIPT_LOCATION_LIMIT,
        "items",
    )
}

/// Mutable graph-construction state scoped to one reconstruction.
pub struct GraphContext<'a> {
    /// Node and edge owner.
    pub accumulator: Accumulator,
    /// Reduced inventory snapshot (`manifest`, root `nodes`, `integrity_contradictions`).
    pub snapshot: &'a Json,
    /// The JavaScript artifact file set.
    pub file_set: &'a Json,
    /// Raw analysis, as file nodes and coverage observe it.
    pub raw_analysis: &'a Json,
    /// Admitted analysis for relationship builders (projection failures expanded to null).
    pub analysis: Json,
    /// Root artifact node.
    pub root: AppNode,
    /// Files by logical path.
    pub files_by_path: HashMap<JsString, Json>,
    /// Relevant-file nodes by path.
    pub file_nodes: HashMap<JsString, AppNode>,
    /// JavaScript asset nodes by path.
    pub asset_nodes: HashMap<JsString, AppNode>,
    /// Source-module nodes by path.
    pub source_module_nodes: HashMap<JsString, AppNode>,
    /// Bundler chunk nodes by lookup key.
    pub chunk_nodes: HashMap<String, AppNode>,
    /// Bundler module nodes by lookup key.
    pub module_nodes: HashMap<String, AppNode>,
    /// Container nodes by digest.
    pub container_nodes: HashMap<String, AppNode>,
    /// Resolution owner.
    pub resolver: &'a dyn ArtifactPathResolver,
}

impl GraphContext<'_> {
    /// Analyzed files in producer order (admitted projection).
    pub fn files(&self) -> &[Json] {
        self.analysis.at("files").arr()
    }

    /// Resolve one declaration through the resolution owner.
    pub fn resolve(&self, request: &ResolveRequest<'_>) -> Json {
        self.resolver.resolve(request)
    }

    /// The root manifest digest.
    pub fn root_sha256(&self) -> &str {
        self.snapshot.at("manifest").at("root_sha256").str()
    }
}

/// `javascriptAnalysisCoverage`.
pub fn javascript_analysis_coverage(javascript: &Json) -> Json {
    if javascript.at("parse_status").str() == "complete" {
        complete_coverage()
    } else {
        partial_coverage(Vec::new(), None)
    }
}

/// `artifactLocalIdentity`.
pub fn artifact_local_identity<K: Into<JsString>>(sha256: &str, namespace: &str, key: K) -> Json {
    Obj::new()
        .with("strategy", "artifact-local-key")
        .with("stability", "artifact-version")
        .with("artifact_sha256", sha256)
        .with("namespace", namespace)
        .with("key", Json::String(key.into()))
        .into()
}

/// Content-digest identity.
pub fn content_identity(sha256: &str) -> Json {
    Obj::new()
        .with("strategy", "content-digest")
        .with("stability", "global-exact")
        .with("sha256", sha256)
        .into()
}

/// Canonical-path identity.
pub fn canonical_path_identity<P: Into<JsString>>(sha256: &str, path: P) -> Json {
    Obj::new()
        .with("strategy", "canonical-path")
        .with("stability", "artifact-version")
        .with("artifact_sha256", sha256)
        .with("path", Json::String(path.into()))
        .into()
}

/// `artifactFileNodeKind`.
pub fn artifact_file_node_kind(kind: &str) -> &'static str {
    match kind {
        "javascript" => "javascript-asset",
        "source-map" => "source-map",
        "native-addon" => "native-addon",
        _ => "artifact",
    }
}

/// `omittedHtmlInlineScriptLocations`.
pub fn omitted_html_inline_script_locations<'j>(files: impl IntoIterator<Item = &'j Json>) -> f64 {
    files
        .into_iter()
        .map(|file| {
            #[allow(clippy::cast_precision_loss)]
            let retained = file.at("scripts").arr().len() as f64;
            file.at("script_count").num() - retained
        })
        .sum()
}

/// `htmlInlineScriptLimitation` (formatting of the analysis owner's observation).
pub fn html_inline_script_limitation(observation: &Json) -> JsString {
    let path = observation.at("path").text();
    let count = observation.at("script_count").num();
    let lines: Vec<String> = observation
        .at("scripts")
        .arr()
        .iter()
        .take(HTML_INLINE_SCRIPT_LIMITATION_LINES)
        .map(|script| js_int(script.at("location").at("start").at("line").num()))
        .collect();
    #[allow(clippy::cast_precision_loss)]
    let unnamed = count - lines.len() as f64;
    let one = count == 1.0;
    let mut message = path.clone().concat_str(" has ");
    message = message.concat_str(&js_int(count));
    message = message.concat_str(" inline JavaScript ");
    message = message.concat_str(if one { "body" } else { "bodies" });
    message = message.concat_str(" starting at line");
    message = message.concat_str(if one { "" } else { "s" });
    message = message.concat_str(" ");
    message = message.concat_str(&lines.join(", "));
    if unnamed > 0.0 {
        message = message.concat_str(" and ");
        message = message.concat_str(&js_int(unnamed));
        message = message.concat_str(" more");
    }
    message = message.concat_str(if one {
        " that was not analyzed; "
    } else {
        " that were not analyzed; "
    });
    message = message.concat_str("endpoints, storage, imports and other facts in ");
    message = message.concat_str(if one { "it" } else { "them" });
    message = message.concat_str(" are absent from the evidence.");
    message
}

/// `addArtifactContainsEdge`.
pub fn add_artifact_contains_edge(
    context: &mut GraphContext<'_>,
    source: &AppNode,
    target: &AppNode,
    file: &Json,
    operation: &str,
) {
    let sha = if operation == "inventory-entry" {
        file.at("container_sha256").str()
    } else {
        file.at("sha256").str()
    };
    let evidence = artifact_observation(&EvidenceInput::new(
        sha,
        file.at("path").text(),
        operation,
        complete_coverage(),
    ));
    context.accumulator.add_edge(EdgeInput {
        source: source.node_id.clone(),
        target: target.node_id.clone(),
        relation: "contains".into(),
        properties: Obj::new().with("path", Json::String(file.at("path").text().clone())),
        evidence,
    });
}

/// `addAstContainsEdge`.
pub fn add_ast_contains_edge(
    context: &mut GraphContext<'_>,
    source: &AppNode,
    target: &AppNode,
    file: &Json,
    range: &Json,
    coverage: &Json,
    properties: Obj,
) {
    let evidence = ast_observation(
        &EvidenceInput::new(
            file.at("sha256").str(),
            file.at("path").text(),
            "map-bundler-structure",
            coverage.clone(),
        )
        .range(range),
    );
    context.accumulator.add_edge(EdgeInput {
        source: source.node_id.clone(),
        target: target.node_id.clone(),
        relation: "contains".into(),
        properties,
        evidence,
    });
}

/// `addStaticInferenceEdge` inputs.
pub struct InferenceEdge<'a> {
    /// Source node.
    pub source: &'a AppNode,
    /// Target node.
    pub target: &'a AppNode,
    /// Declaring file.
    pub file: &'a Json,
    /// Exact range.
    pub range: &'a Json,
    /// Coverage.
    pub coverage: &'a Json,
    /// Relation.
    pub relation: &'a str,
    /// Properties.
    pub properties: Obj,
    /// Confidence override.
    pub confidence: Option<&'a str>,
    /// Limitations.
    pub limitations: Option<Vec<JsString>>,
}

/// `addStaticInferenceEdge`.
pub fn add_static_inference_edge(context: &mut GraphContext<'_>, input: InferenceEdge<'_>) {
    let mut evidence_input = EvidenceInput::new(
        input.file.at("sha256").str(),
        input.file.at("path").text(),
        "map-static-relationship",
        input.coverage.clone(),
    )
    .range(input.range);
    evidence_input.limitations = input.limitations;
    let evidence = static_inference(&evidence_input, input.confidence);
    context.accumulator.add_edge(EdgeInput {
        source: input.source.node_id.clone(),
        target: input.target.node_id.clone(),
        relation: input.relation.into(),
        properties: input.properties,
        evidence,
    });
}

/// `addUnavailableStaticParseScope` inputs.
pub struct UnavailableParse<'a> {
    /// Declaring file.
    pub file: &'a Json,
    /// File node.
    pub asset: &'a AppNode,
    /// Processing operation.
    pub operation: &'a str,
    /// Applicable authority.
    pub authority: &'a str,
    /// Limitation.
    pub limitation: JsString,
    /// Projected failure.
    pub failure: Option<Json>,
    /// Coverage limits.
    pub limits: Option<Vec<Json>>,
    /// Items a named limit dropped, when known.
    pub omitted_count: Option<f64>,
    /// Structured gap details.
    pub details: Option<Obj>,
}

impl<'a> UnavailableParse<'a> {
    /// A gap without failure, limits or details.
    pub fn new<L: Into<JsString>>(
        file: &'a Json,
        asset: &'a AppNode,
        operation: &'a str,
        authority: &'a str,
        limitation: L,
    ) -> Self {
        Self {
            file,
            asset,
            operation,
            authority,
            limitation: limitation.into(),
            failure: None,
            limits: None,
            omitted_count: None,
            details: None,
        }
    }
}

/// `addUnavailableStaticParseScope`.
pub fn add_unavailable_static_parse_scope(
    context: &mut GraphContext<'_>,
    input: UnavailableParse<'_>,
) {
    let sha = input.file.at("sha256").str();
    let path = input.file.at("path").text();
    let mut properties = input.details.unwrap_or_default();
    properties.set("path", Json::String(path.clone()));
    properties.set("operation", input.operation);
    properties.set("limitation", Json::String(input.limitation.clone()));
    if let Some(failure) = input.failure {
        properties.set("analysis_failure", failure);
    }
    let limits = input.limits.unwrap_or_default();
    let coverage = match input.omitted_count {
        Some(omitted) if omitted > 0.0 => truncated_coverage(limits, Some(omitted)),
        _ => partial_coverage(limits, None),
    };
    let evidence = unavailable_static(
        &EvidenceInput::new(sha, input.file.at("path").text(), input.operation, coverage),
        input.authority,
        &input.limitation,
    );
    let scope_key = JsString::from(input.operation)
        .concat_str(":")
        .concat(input.file.at("path").text());
    let node = context.accumulator.add_node(NodeInput {
        kind: "unknown".into(),
        identity: artifact_local_identity(sha, "static-parse-scope", scope_key),
        observations: vec![ObservationInput::new_js(
            Some(
                input
                    .file
                    .at("path")
                    .text()
                    .clone()
                    .concat_str(" parse scope"),
            ),
            properties,
            evidence,
        )],
    });
    let evidence = artifact_observation(&EvidenceInput::new(
        sha,
        input.file.at("path").text(),
        "associate-unavailable-parse-scope",
        complete_coverage(),
    ));
    context.accumulator.add_edge(EdgeInput {
        source: input.asset.node_id.clone(),
        target: node.node_id,
        relation: "contains".into(),
        properties: Obj::new().with("scope", "unavailable-static-analysis"),
        evidence,
    });
}

/// `createElectronRoleNode` inputs.
pub struct RoleNode<'a> {
    /// Role kind.
    pub kind: &'a str,
    /// Anchoring file.
    pub anchor: &'a Json,
    /// Path resolution.
    pub resolution: &'a Json,
    /// Discovery mechanism.
    pub mechanism: &'a str,
    /// Exact range.
    pub range: Option<&'a Json>,
    /// Coverage.
    pub coverage: Option<&'a Json>,
}

fn resolved_or_declared(resolution: &Json) -> JsString {
    resolution
        .at("resolved_path")
        .as_js_string()
        .cloned()
        .unwrap_or_else(|| resolution.at("declared_path").text().clone())
}

/// `createElectronRoleNode`.
pub fn create_electron_role_node(context: &mut GraphContext<'_>, input: RoleNode<'_>) -> AppNode {
    let resolution = input.resolution;
    let target = resolved_or_declared(resolution);
    let mut properties = resolution_properties(Some(resolution));
    properties.set("declared_path", resolution.at("declared_path").clone());
    properties.set(
        "resolution_context",
        resolution.at("resolution_context").clone(),
    );
    properties.set("resolved_path", resolution.at("resolved_path").clone());
    properties.set(
        "resolution_status",
        resolution.at("resolution_status").clone(),
    );
    properties.set("limitations", resolution.at("limitations").clone());
    properties.set("mechanism", input.mechanism);
    let mut evidence_input = EvidenceInput::new(
        input.anchor.at("sha256").str(),
        input.anchor.at("path").text(),
        "discover-electron-entrypoint",
        input.coverage.cloned().unwrap_or_else(complete_coverage),
    )
    .limitations(limitations(resolution));
    evidence_input.range = input.range;
    let evidence = static_inference(&evidence_input, None);
    let role_key = JsString::from(input.kind)
        .concat_str(":")
        .concat(&JsString::from(resolution.at("resolution_context").str()))
        .concat_str(":")
        .concat(&target);
    context.accumulator.add_node(NodeInput {
        kind: input.kind.into(),
        identity: artifact_local_identity(
            input.anchor.at("sha256").str(),
            "electron-role",
            role_key,
        ),
        observations: vec![ObservationInput::new_js(Some(target), properties, evidence)],
    })
}

/// `linkElectronRoleToAsset`.
pub fn link_electron_role_to_asset(
    context: &mut GraphContext<'_>,
    role: &AppNode,
    anchor: &Json,
    resolution: &Json,
    range: Option<&Json>,
    coverage: Option<&Json>,
) {
    let Some(path) = resolution.at("resolved_path").as_js_string() else {
        return;
    };
    let Some(asset) = context
        .asset_nodes
        .get(path)
        .or_else(|| context.file_nodes.get(path))
        .cloned()
    else {
        return;
    };
    let properties = Obj::new()
        .with("declared_path", resolution.at("declared_path").clone())
        .with(
            "resolution_context",
            resolution.at("resolution_context").clone(),
        )
        .with("resolved_path", Json::String(path.clone()))
        .with(
            "resolution_status",
            resolution.at("resolution_status").clone(),
        );
    let mut evidence_input = EvidenceInput::new(
        anchor.at("sha256").str(),
        anchor.at("path").text(),
        "resolve-electron-entrypoint",
        coverage.cloned().unwrap_or_else(complete_coverage),
    )
    .limitations(limitations(resolution));
    evidence_input.range = range;
    let evidence = static_inference(&evidence_input, None);
    context.accumulator.add_edge(EdgeInput {
        source: role.node_id.clone(),
        target: asset.node_id,
        relation: "maps_to".into(),
        properties,
        evidence,
    });
}

/// `selfReferenceOmissions`.
pub fn self_reference_omissions(
    count: usize,
    singular: &str,
    plural: &str,
    owner: &str,
) -> Vec<String> {
    if count == 0 {
        return Vec::new();
    }
    let one = count == 1;
    vec![format!(
        "{count} {} resolved back to {owner} itself and {} omitted; application graph edges cannot be self-referential.",
        if one { singular } else { plural },
        if one { "was" } else { "were" },
    )]
}

/// `moduleLookupKey` / `chunkLookupKey`.
///
/// The resulting map key is an ASCII JSON serialization, but each component
/// is first retained as a `JsString`. This keeps lone UTF-16 surrogates
/// distinguishable from ordinary text and from literal escape sequences.
pub fn lookup_key<P, R, K>(path: P, runtime: R, key: K) -> String
where
    P: Into<JsString>,
    R: Into<JsString>,
    K: Into<JsString>,
{
    composite_key(vec![
        Json::String(path.into()),
        Json::String(runtime.into()),
        Json::String(key.into()),
    ])
}

/// `sourceNodeFor`.
pub fn source_node_for(
    context: &GraphContext<'_>,
    path: &JsString,
    module_key: &Json,
    runtime: Option<&Json>,
) -> Option<AppNode> {
    if module_key.is_null() {
        return context.source_module_nodes.get(path).cloned();
    }

    let key = module_key.as_js_string()?;
    let runtime = runtime?.as_js_string()?;
    let lookup = lookup_key(path.clone(), runtime.clone(), key.clone());
    context.module_nodes.get(&lookup).cloned()
}

/// Strings of a JSON string array.
pub fn string_list(value: &Json) -> Vec<String> {
    value
        .arr()
        .iter()
        .map(|item| item.str().to_owned())
        .collect()
}

/// Exact JavaScript strings in a JSON string array.
pub fn string_list_js(value: &Json) -> Vec<JsString> {
    value
        .arr()
        .iter()
        .filter_map(Json::as_js_string)
        .cloned()
        .collect()
}
