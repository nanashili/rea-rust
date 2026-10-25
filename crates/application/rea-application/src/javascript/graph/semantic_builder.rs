//! `JavaScriptSemanticGraphBuilder`: file-local projection and parent-side
//! adoption, unavailable-file frontiers and graph sealing.

use std::collections::HashMap;

use super::super::semantic::value_types::JsString;
use super::evidence::{limit, partial_coverage};
use super::json::{Json, Obj, strings};
use super::leaves::{RETURNED_REFERENCE_WIDENING_LIMITATION, analysis_coverage_limits};
use super::semantic_graph::{
    NodeSpec, ProjectionState, RELATION_FAMILIES, RELATIONS, RelationSpec, SemanticGraphContent,
    UnknownSpec, add_fallback_root, add_relation, add_root, add_unknown, bind_application_nodes,
    inferred_evidence_at, observed_evidence, record_unknown_omission, retain_node,
    seal_semantic_graph, unknown_evidence,
};
use super::semantic_lookup::{CallableOwnerLookup, NodeRangeLookup, range_key};
use super::semantic_projection::{
    FileContext, project_boundaries, project_calls, project_child_processes,
    project_closure_captures, project_configuration, project_electron_paths, project_events,
    project_fingerprints, project_frontiers, project_objects, project_promises, project_requests,
    project_resource_limits, project_resources, project_timers, project_values,
};

/// `JAVASCRIPT_SEMANTIC_ITEM_MAXIMUM`.
pub const SEMANTIC_ITEM_MAXIMUM: usize = 1_000_000;

/// Why a semantic projection request was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticProjectionError {
    /// A capacity is outside `0..=1_000_000` (or below 1 for ceilings).
    InvalidCapacity,
    /// A transferred projection exceeds the offered capacity.
    CapacityExceeded(&'static str),
    /// A transferred evidence context is stale or collides.
    InvalidEvidenceContext(String),
}

/// One file's transferable projection (`JavaScriptSemanticFileProjection`).
pub fn project_file(
    file: &Json,
    ir: &Json,
    capacity_nodes: usize,
    capacity_unknowns: usize,
    paths: &[Json],
) -> Result<Json, SemanticProjectionError> {
    if capacity_nodes > SEMANTIC_ITEM_MAXIMUM || capacity_unknowns > SEMANTIC_ITEM_MAXIMUM {
        return Err(SemanticProjectionError::InvalidCapacity);
    }
    let mut state = ProjectionState {
        file_node_budget: Some(capacity_nodes),
        unknown_capacity: Some(capacity_unknowns),
        ..ProjectionState::default()
    };
    let fingerprints = project_source(file, ir, &mut state, paths);
    let mut projection = Obj::new()
        .with("roots", strings(state.roots.clone()))
        .with("evidenceContexts", Json::Array(state.evidence.contexts()))
        .with("nodes", Json::Array(state.nodes.values()))
        .with("relations", Json::Array(state.relations.values()))
        .with("unknowns", Json::Array(state.unknowns.values()))
        .with("fingerprints", Json::Array(fingerprints));
    if !state.unknown_omissions.is_empty() {
        projection.set(
            "omittedUnknownOccurrences",
            Json::Array(state.unknown_omissions.values()),
        );
    }
    projection.set("nodesTruncated", state.file_nodes_dropped);
    Ok(projection.into())
}

fn first_definition_location(binding: &Json) -> Json {
    binding
        .at("definitions")
        .arr()
        .first()
        .map_or(Json::Null, |definition| definition.at("location").clone())
}

/// `projectFileSteps`: project one file into `state`, returning its fingerprints.
fn project_source(
    file: &Json,
    ir: &Json,
    state: &mut ProjectionState,
    paths: &[Json],
) -> Vec<Json> {
    let path = file.at("path").text().clone();
    let Some(module_node) = retain_node(
        state,
        file,
        NodeSpec {
            kind: "module",
            role_key: "module".into(),
            location: Json::Null,
            label: Some(path),
            function_node_id: None,
            properties: Obj::new(),
        },
    ) else {
        return Vec::new();
    };
    add_root(state, module_node.at("node_id").str());
    project_resource_limits(state, file, ir, &module_node);
    for location in ir.at("coverage").at("widenedReturnedReferences").arr() {
        let mut evidence = unknown_evidence(file, location).obj();
        evidence.set(
            "limitations",
            strings([RETURNED_REFERENCE_WIDENING_LIMITATION]),
        );
        add_unknown(
            state,
            UnknownSpec {
                node_id: Some(module_node.at("node_id").str().to_owned()),
                family: "data-flow",
                relation_kinds: vec!["defines".into()],
                reason: "dynamic-property",
                detail: JsString::from(RETURNED_REFERENCE_WIDENING_LIMITATION),
                candidate_node_ids: Vec::new(),
                evidence: evidence.into(),
            },
        );
    }
    project_electron_paths(state, file, paths);
    let mut callable_nodes = HashMap::new();
    for callable in ir.at("callables").arr() {
        let name = callable.at("name");
        if let Some(node) = retain_node(
            state,
            file,
            NodeSpec {
                kind: "function",
                role_key: format!("callable:{}", callable.at("callableId").str()).into(),
                location: callable.at("location").clone(),
                label: name.as_js_string().cloned(),
                function_node_id: None,
                properties: Obj::new().with("name", name.clone()),
            },
        ) {
            callable_nodes.insert(callable.at("callableId").str().to_owned(), node);
        }
    }
    let owners = CallableOwnerLookup::new(ir);
    let mut binding_nodes = HashMap::new();
    for binding in ir.at("bindings").arr() {
        let location = first_definition_location(binding);
        let owner = owners
            .owner(&location, &callable_nodes)
            .map(|node| node.at("node_id").str().to_owned());
        if let Some(node) = retain_node(
            state,
            file,
            NodeSpec {
                kind: if binding.at("kind").str() == "parameter" {
                    "parameter"
                } else {
                    "binding"
                },
                role_key: format!("binding:{}", binding.at("bindingId").str()).into(),
                location,
                label: binding.at("name").as_js_string().cloned(),
                function_node_id: owner.map(Into::into),
                properties: Obj::new(),
            },
        ) {
            binding_nodes.insert(binding.at("bindingId").str().to_owned(), node);
        }
    }
    let mut return_site_nodes = HashMap::new();
    for callable in ir.at("callables").arr() {
        let Some(owner) = callable_nodes
            .get(callable.at("callableId").str())
            .map(|node| node.at("node_id").str().to_owned())
        else {
            continue;
        };
        for site in callable.at("returnSites").arr() {
            let id = site.at("returnSiteId").str().to_owned();
            if let Some(node) = retain_node(
                state,
                file,
                NodeSpec {
                    kind: "return-site",
                    role_key: id.clone().into(),
                    location: site.at("location").clone(),
                    label: Some(JsString::from("return")),
                    function_node_id: Some(owner.clone().into()),
                    properties: Obj::new(),
                },
            ) {
                return_site_nodes.insert(id, node);
            }
        }
    }
    let mut call_site_nodes = HashMap::new();
    for call in ir.at("callSites").arr() {
        let owner = call
            .at("callerCallableId")
            .as_str()
            .and_then(|id| callable_nodes.get(id))
            .map(|node| node.at("node_id").str().to_owned());
        if let Some(node) = retain_node(
            state,
            file,
            NodeSpec {
                kind: "call-site",
                role_key: format!("call:{}", call.at("callSiteId").str()).into(),
                location: call.at("location").clone(),
                label: call.at("kind").as_js_string().cloned(),
                function_node_id: owner.map(Into::into),
                properties: Obj::new(),
            },
        ) {
            call_site_nodes.insert(call.at("callSiteId").str().to_owned(), node);
        }
    }
    let mut call_resolutions = HashMap::new();
    let mut call_sites_by_range = HashMap::new();
    for call in ir.at("callSites").arr() {
        let id = call.at("callSiteId").str().to_owned();
        call_resolutions.insert(
            id.clone(),
            if call.at("resolution").str() == "exact" {
                "resolved"
            } else {
                "candidate"
            },
        );
        call_sites_by_range
            .entry(range_key(call.at("location")))
            .or_insert(id);
    }
    let mut context = FileContext {
        file: file.clone(),
        ir: ir.clone(),
        state,
        module_node,
        binding_nodes,
        callable_nodes,
        call_site_nodes,
        return_site_nodes,
        argument_nodes: HashMap::new(),
        reference_nodes: Vec::new(),
        call_resolutions,
        owners,
        call_sites_by_range,
        references: None,
    };
    project_definitions_and_references(&mut context);
    context.references = Some(NodeRangeLookup::new(&context.reference_nodes));
    project_values(&mut context);
    project_objects(&mut context);
    project_calls(&mut context);
    project_promises(&mut context);
    project_events(&mut context);
    project_timers(&mut context);
    project_child_processes(&mut context);
    project_configuration(&mut context);
    project_requests(&mut context);
    project_boundaries(&mut context);
    project_resources(&mut context);
    project_closure_captures(&mut context);
    project_frontiers(&mut context);
    project_fingerprints(&mut context)
}

fn project_definitions_and_references(context: &mut FileContext<'_>) {
    let bindings = context.ir.at("bindings").arr().to_vec();
    for binding in &bindings {
        let id = binding.at("bindingId").str();
        let Some(binding_node) = context.binding_nodes.get(id).cloned() else {
            continue;
        };
        for (index, definition) in binding.at("definitions").arr().iter().enumerate() {
            let node = retain_node(
                context.state,
                &context.file,
                NodeSpec {
                    kind: "expression",
                    role_key: format!("definition:{id}:{index}").into(),
                    location: definition.at("location").clone(),
                    label: definition.at("kind").as_js_string().cloned(),
                    function_node_id: binding_node.at("function_node_id").as_js_string().cloned(),
                    properties: Obj::new(),
                },
            );
            add_relation(
                context.state,
                RelationSpec::new(node.as_ref(), Some(&binding_node), "defines", "resolved"),
            );
        }
    }
    let references = context.ir.at("references").arr().to_vec();
    for (index, reference) in references.iter().enumerate() {
        let location = reference.at("location");
        let owner = context
            .owners
            .owner(location, &context.callable_nodes)
            .map(|node| node.at("node_id").str().to_owned());
        let role = reference.at("role").text();
        let name = reference.at("name").text();
        let expression = retain_node(
            context.state,
            &context.file,
            NodeSpec {
                kind: "expression",
                role_key: JsString::from(format!("reference:{index}:"))
                    .concat(role)
                    .concat_str(":")
                    .concat(name),
                location: location.clone(),
                label: reference.at("name").as_js_string().cloned(),
                function_node_id: owner.map(Into::into),
                properties: Obj::new(),
            },
        );
        let binding = reference
            .at("bindingId")
            .as_str()
            .and_then(|id| context.binding_nodes.get(id))
            .cloned();
        if let Some(expression) = &expression {
            context.reference_nodes.push(expression.clone());
        }
        let (Some(binding), Some(expression)) = (binding, expression) else {
            continue;
        };
        match role.as_str().unwrap_or("") {
            "read" => {
                let mut spec =
                    RelationSpec::new(Some(&binding), Some(&expression), "reads", "resolved");
                spec.evidence = Some(inferred_evidence_at(&context.file, location));
                add_relation(context.state, spec);
            }
            "write" => add_relation(
                context.state,
                RelationSpec::new(Some(&expression), Some(&binding), "writes", "resolved"),
            ),
            _ => {}
        }
    }
}

/// Parent-side retained capacities (`createJavaScriptSemanticGraphProjection` limits).
#[derive(Clone, Copy, Debug)]
pub struct SemanticLimits {
    /// Tree node ceiling.
    pub total_nodes: usize,
    /// Per-file node ceiling.
    pub file_nodes: usize,
    /// Tree unknown ceiling.
    pub total_unknowns: usize,
    /// Per-file unknown ceiling.
    pub file_unknowns: usize,
}

impl Default for SemanticLimits {
    fn default() -> Self {
        Self {
            total_nodes: 100_000,
            file_nodes: 20_000,
            total_unknowns: 100_000,
            file_unknowns: 20_000,
        }
    }
}

/// `JavaScriptSemanticGraphProjection` (parent realm).
pub struct SemanticGraphProjection {
    limits: SemanticLimits,
    state: ProjectionState,
    fingerprints: Vec<Json>,
    truncated_files: usize,
    unavailable_files: usize,
    resource_truncated_files: usize,
    execution_limits: Vec<(String, Json)>,
}

impl SemanticGraphProjection {
    /// Create a projection with validated capacities.
    pub fn new(limits: SemanticLimits) -> Result<Self, SemanticProjectionError> {
        for value in [
            limits.total_nodes,
            limits.file_nodes,
            limits.total_unknowns,
            limits.file_unknowns,
        ] {
            if !(1..=SEMANTIC_ITEM_MAXIMUM).contains(&value) {
                return Err(SemanticProjectionError::InvalidCapacity);
            }
        }
        Ok(Self {
            limits,
            state: ProjectionState::default(),
            fingerprints: Vec::new(),
            truncated_files: 0,
            unavailable_files: 0,
            resource_truncated_files: 0,
            execution_limits: Vec::new(),
        })
    }

    /// `remainingFileCapacity`: `(nodes, unknowns)` offered to the next file.
    pub fn remaining_file_capacity(&self) -> (usize, usize) {
        (
            self.limits.file_nodes.min(
                self.limits
                    .total_nodes
                    .saturating_sub(self.state.nodes.len()),
            ),
            self.limits.file_unknowns.min(
                self.limits
                    .total_unknowns
                    .saturating_sub(self.state.unknowns.len()),
            ),
        )
    }

    /// `adoptFileProjection`.
    pub fn adopt_file_projection(
        &mut self,
        projection: &Json,
    ) -> Result<(), SemanticProjectionError> {
        let new_nodes: Vec<&Json> = projection
            .at("nodes")
            .arr()
            .iter()
            .filter(|node| !self.state.nodes.has(node.at("node_id").str()))
            .collect();
        let (node_capacity, unknown_capacity) = (
            self.limits.file_nodes.min(
                self.limits
                    .total_nodes
                    .saturating_sub(self.state.nodes.len()),
            ),
            self.limits.file_unknowns.min(
                self.limits
                    .total_unknowns
                    .saturating_sub(self.state.unknowns.len()),
            ),
        );
        if new_nodes.len() > node_capacity {
            return Err(SemanticProjectionError::CapacityExceeded(
                "Transferred semantic nodes exceed the offered tree capacity",
            ));
        }
        let new_unknowns: Vec<&Json> = projection
            .at("unknowns")
            .arr()
            .iter()
            .filter(|unknown| !self.state.unknowns.has(unknown.at("unknown_id").str()))
            .collect();
        if new_unknowns.len() > unknown_capacity {
            return Err(SemanticProjectionError::CapacityExceeded(
                "Transferred semantic unknowns exceed the offered tree capacity",
            ));
        }
        for omission in projection.at("omittedUnknownOccurrences").arr() {
            record_unknown_omission(&mut self.state, omission);
        }
        for context in projection.at("evidenceContexts").arr() {
            self.state
                .evidence
                .adopt(context)
                .map_err(SemanticProjectionError::InvalidEvidenceContext)?;
        }
        for node in new_nodes {
            self.state
                .nodes
                .set(node.at("node_id").str().to_owned(), node.clone());
        }
        for relation in projection.at("relations").arr() {
            self.state.relations.set(
                relation.at("relation_id").str().to_owned(),
                relation.clone(),
            );
        }
        for unknown in new_unknowns {
            self.state
                .unknowns
                .set(unknown.at("unknown_id").str().to_owned(), unknown.clone());
        }
        for root in projection.at("roots").arr() {
            add_root(&mut self.state, root.str());
        }
        self.fingerprints
            .extend(projection.at("fingerprints").arr().iter().cloned());
        if projection.at("nodesTruncated").as_bool() == Some(true) {
            self.truncated_files += 1;
        }
        Ok(())
    }

    /// `recordUnavailableFile`.
    pub fn record_unavailable_file(
        &mut self,
        file: &Json,
        reason: &str,
        limits: &Json,
        unknown_reason: &str,
    ) {
        if file.at("kind").str() != "javascript" {
            return;
        }
        let retained = analysis_coverage_limits(limits);
        for limit in &retained {
            let key = Json::Array(vec![
                limit.at("name").clone(),
                limit.at("value").clone(),
                limit.at("unit").clone(),
            ])
            .stringify();
            if let Some(entry) = self
                .execution_limits
                .iter_mut()
                .find(|(existing, _)| *existing == key)
            {
                entry.1 = limit.clone();
            } else {
                self.execution_limits.push((key, limit.clone()));
            }
        }
        let state = &mut self.state;
        state.file_node_budget = Some(
            self.limits
                .file_nodes
                .min(self.limits.total_nodes.saturating_sub(state.nodes.len())),
        );
        let module = retain_node(
            state,
            file,
            NodeSpec {
                kind: "module",
                role_key: "module".into(),
                location: Json::Null,
                label: Some(file.at("path").text().clone()),
                function_node_id: None,
                properties: Obj::new(),
            },
        );
        state.file_node_budget = None;
        if let Some(module) = &module {
            add_root(state, module.at("node_id").str());
        }
        let mut evidence = observed_evidence(file, &Json::Null).obj();
        evidence.set("authority", "unknown");
        evidence.set("state", "unknown");
        evidence.set("confidence", "unknown");
        evidence.set("coverage", partial_coverage(retained.clone(), None));
        evidence.set("limitations", strings([reason]));
        let evidence: Json = evidence.into();
        state.unknown_capacity = Some(
            self.limits
                .total_unknowns
                .min(state.unknowns.len() + self.limits.file_unknowns),
        );
        for family in RELATION_FAMILIES {
            add_unknown(
                state,
                UnknownSpec {
                    node_id: module
                        .as_ref()
                        .map(|module| module.at("node_id").str().to_owned()),
                    family,
                    relation_kinds: RELATIONS
                        .iter()
                        .filter(|(_, owner)| *owner == family)
                        .map(|(relation, _)| (*relation).to_owned())
                        .collect(),
                    reason: unknown_reason,
                    detail: JsString::from(reason),
                    candidate_node_ids: Vec::new(),
                    evidence: evidence.clone(),
                },
            );
        }
        state.unknown_capacity = None;
        self.unavailable_files += 1;
        if unknown_reason == "resource-limit" && !retained.is_empty() {
            self.resource_truncated_files += 1;
        }
    }

    /// `projectFile` in the parent realm (full construction).
    pub fn project_file(&mut self, file: &Json, ir: &Json, paths: &[Json]) {
        if self.state.nodes.len() >= self.limits.total_nodes {
            self.truncated_files += 1;
            return;
        }
        let remaining = self.limits.total_nodes - self.state.nodes.len();
        self.state.file_node_budget = Some(self.limits.file_nodes.min(remaining));
        self.state.file_nodes_dropped = false;
        self.state.unknown_capacity = Some(
            self.limits
                .total_unknowns
                .min(self.state.unknowns.len() + self.limits.file_unknowns),
        );
        let fingerprints = project_source(file, ir, &mut self.state, paths);
        self.fingerprints.extend(fingerprints);
        if self.state.file_nodes_dropped {
            self.truncated_files += 1;
        }
        self.state.file_node_budget = None;
        self.state.unknown_capacity = None;
    }

    /// `finishImmutableSteps`: bind application nodes and seal the graph.
    pub fn finish(
        mut self,
        root_artifact_sha256: &str,
        application_graph_id: &str,
        application_nodes: &[Json],
    ) -> Json {
        bind_application_nodes(&mut self.state, application_nodes);
        if self.state.roots.is_empty() {
            add_fallback_root(root_artifact_sha256, &mut self.state);
        }
        let relations = self.state.relations.values();
        let unknowns = self.state.unknowns.values();
        let omissions = self.state.unknown_omissions.values();
        let dropped = !omissions.is_empty();
        let incomplete = self.truncated_files > 0 || self.unavailable_files > 0;
        let omitted: Json = if incomplete {
            Json::Null
        } else {
            Json::Number(0.0)
        };
        let families = RELATION_FAMILIES
            .iter()
            .map(|family| {
                let retained = relations
                    .iter()
                    .filter(|relation| {
                        super::semantic_graph::relation_family(relation.at("relation").str())
                            == *family
                    })
                    .count();
                let ids: Vec<String> = unknowns
                    .iter()
                    .filter(|unknown| unknown.at("family").str() == *family)
                    .map(|unknown| unknown.at("unknown_id").str().to_owned())
                    .collect();
                Json::from(
                    Obj::new()
                        .with("family", *family)
                        .with("status", "partial")
                        .with("retained_relations", retained)
                        .with("omitted_relations", omitted.clone())
                        .with("unknown_ids", strings(ids)),
                )
            })
            .collect();
        let mut limits: Vec<Json> = self
            .execution_limits
            .iter()
            .map(|(_, limit)| limit.clone())
            .collect();
        #[allow(clippy::cast_precision_loss)]
        let number = |value: usize| value as f64;
        if dropped {
            limits.push(limit(
                "semantic_graph_unknown_ceiling",
                number(self.limits.total_unknowns),
                "items",
            ));
            limits.push(limit(
                "semantic_graph_file_unknown_ceiling",
                number(self.limits.file_unknowns),
                "items",
            ));
        }
        if self.truncated_files > 0 {
            limits.push(limit(
                "semantic_graph_node_ceiling",
                number(self.limits.total_nodes),
                "items",
            ));
            limits.push(limit(
                "semantic_graph_file_node_ceiling",
                number(self.limits.file_nodes),
                "items",
            ));
        }
        let mut coverage = Obj::new()
            .with(
                "status",
                if incomplete || dropped {
                    "partial"
                } else {
                    "unknown"
                },
            )
            .with(
                "truncated",
                self.truncated_files > 0 || self.resource_truncated_files > 0 || dropped,
            );
        if dropped {
            coverage.set("omitted_unknown_occurrences", Json::Array(omissions));
        }
        coverage.set("omitted_nodes", omitted.clone());
        coverage.set("omitted_relations", omitted);
        coverage.set("limits", Json::Array(limits));
        coverage.set("families", Json::Array(families));
        let mut limitations = Vec::new();
        if dropped {
            limitations.push("Semantic unknown retention reached an effective capacity. Omission coverage counts examined emission occurrences by family and reason, including repeats; it does not count unexamined source frontiers or distinct discarded identities.".to_owned());
        }
        limitations.extend(
            [
                "The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.",
                "Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.",
                "Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.",
                "Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.",
                "Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.",
                "Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.",
                "Child-process extraction covers asynchronous node:child_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.",
                "Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.",
                "Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.",
                "Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.",
                "Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.",
            ]
            .map(str::to_owned),
        );
        seal_semantic_graph(SemanticGraphContent {
            root_artifact_sha256: root_artifact_sha256.to_owned(),
            application_graph_id: application_graph_id.to_owned(),
            root_node_ids: self.state.roots.clone(),
            evidence_contexts: self.state.evidence.contexts(),
            nodes: self.state.nodes.values(),
            relations,
            fingerprints: self.fingerprints,
            unknowns,
            coverage: coverage.into(),
            limitations,
        })
    }
}
