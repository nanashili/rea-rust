//! Domain `javascriptSemanticGraph` (evidence-context registry, canonical
//! facts and sealing) and `JavaScriptSemanticGraphConstruction` (projection
//! state, budgets and unknown admission).

use std::collections::HashMap;

use super::super::semantic::value_types::JsString;
use super::json::{Json, Obj, compare_code_points, strings, unique_sorted};

/// Semantic relation families in canonical order.
pub const RELATION_FAMILIES: [&str; 12] = [
    "boundary",
    "call-flow",
    "child-process",
    "closure",
    "configuration",
    "data-flow",
    "event",
    "object-flow",
    "promise-ownership",
    "request",
    "resource-lifecycle",
    "timer",
];

/// Semantic relations in declaration order with their families.
pub const RELATIONS: [(&str, &str); 44] = [
    ("acquires", "resource-lifecycle"),
    ("aggregates", "promise-ownership"),
    ("aliases", "data-flow"),
    ("argument-to-parameter", "call-flow"),
    ("awaits", "promise-ownership"),
    ("calls", "call-flow"),
    ("cancels-timer", "timer"),
    ("captures", "closure"),
    ("chains", "promise-ownership"),
    ("coerces", "boundary"),
    ("connects-stdio", "child-process"),
    ("consumed-by", "request"),
    ("constructs-request", "request"),
    ("creates-promise", "promise-ownership"),
    ("defaults", "configuration"),
    ("defines", "data-flow"),
    ("destructures", "object-flow"),
    ("detaches-task", "promise-ownership"),
    ("dispatches-candidate", "event"),
    ("forwards-signal", "child-process"),
    ("listens-error", "child-process"),
    ("listens-exit", "child-process"),
    ("owns", "promise-ownership"),
    ("overrides", "configuration"),
    ("parses", "boundary"),
    ("reads", "data-flow"),
    ("reads-argv", "configuration"),
    ("reads-config", "configuration"),
    ("reads-environment", "configuration"),
    ("reads-property", "object-flow"),
    ("registers-listener", "event"),
    ("releases", "resource-lifecycle"),
    ("removes-listener", "event"),
    ("returns-task", "promise-ownership"),
    ("returns-to-call", "call-flow"),
    ("schedules-timer", "timer"),
    ("spawns", "child-process"),
    ("spreads", "object-flow"),
    ("supplies-argv", "child-process"),
    ("supplies-env", "child-process"),
    ("supplies-request-field", "request"),
    ("validates", "boundary"),
    ("writes", "data-flow"),
    ("writes-property", "object-flow"),
];

/// `JAVASCRIPT_SEMANTIC_RELATION_FAMILY[relation]`.
pub fn relation_family(relation: &str) -> &'static str {
    RELATIONS
        .iter()
        .find(|(name, _)| *name == relation)
        .map_or("data-flow", |(_, family)| family)
}

fn normalize_evidence(evidence: &Json) -> Json {
    let mut object = evidence.obj();
    let mut coverage = evidence.at("coverage").obj();
    let mut limits: Vec<Json> = evidence.at("coverage").at("limits").arr().to_vec();
    limits.sort_by(|left, right| compare_code_points(&left.canonical(), &right.canonical()));
    coverage.set("limits", Json::Array(limits));
    object.set("coverage", coverage);
    let sorted = |value: &Json| {
        strings(unique_sorted(
            value.arr().iter().map(|item| item.str().to_owned()),
        ))
    };
    object.set("limitations", sorted(evidence.at("limitations")));
    object.set("evidence_ids", sorted(evidence.at("evidence_ids")));
    object.into()
}

/// `JavaScriptSemanticEvidenceContextRegistry`.
#[derive(Default)]
pub struct EvidenceRegistry {
    contexts: HashMap<String, Json>,
    ids_by_canonical: HashMap<String, String>,
}

impl EvidenceRegistry {
    /// Intern normalized non-location provenance; returns `{ context_id, location }`.
    pub fn intern(&mut self, evidence: &Json) -> Json {
        let mut context = normalize_evidence(evidence).obj();
        let location = context.remove("location").unwrap_or(Json::Null);
        let canonical = Json::from(context.clone()).canonical();
        let id = match self.ids_by_canonical.get(&canonical) {
            Some(id) => id.clone(),
            None => {
                let id = format!(
                    "jsrg_evidence_{}",
                    super::json::sha256_hex(canonical.as_bytes())
                );
                assert!(
                    !self.contexts.contains_key(&id),
                    "JavaScript semantic evidence context digest collision"
                );
                self.contexts
                    .insert(id.clone(), context.with("context_id", id.as_str()).into());
                self.ids_by_canonical.insert(canonical, id.clone());
                id
            }
        };
        Obj::new()
            .with("context_id", id)
            .with("location", location)
            .into()
    }

    /// Resolve one interned reference to full evidence.
    pub fn resolve(&self, reference: &Json) -> Json {
        let mut context = self
            .contexts
            .get(reference.at("context_id").str())
            .map(Json::obj)
            .unwrap_or_default();
        context.remove("context_id");
        context.set("location", reference.at("location").clone());
        context.into()
    }

    /// Adopt a transferred context, verifying its identifier.
    pub fn adopt(&mut self, context: &Json) -> Result<(), String> {
        let mut value = context.obj();
        let identifier = value
            .remove("context_id")
            .map(|id| id.str().to_owned())
            .unwrap_or_default();
        let canonical = Json::from(value).canonical();
        if identifier
            != format!(
                "jsrg_evidence_{}",
                super::json::sha256_hex(canonical.as_bytes())
            )
        {
            return Err("Transferred semantic evidence context identifier is stale".into());
        }
        if let Some(existing) = self.contexts.get(&identifier) {
            let mut existing = existing.obj();
            existing.remove("context_id");
            if Json::from(existing).canonical() != canonical {
                return Err("Transferred semantic evidence context digest collision".into());
            }
        }
        self.contexts.insert(identifier.clone(), context.clone());
        self.ids_by_canonical.insert(canonical, identifier);
        Ok(())
    }

    /// The context table sorted by identifier.
    pub fn contexts(&self) -> Vec<Json> {
        let mut contexts: Vec<Json> = self.contexts.values().cloned().collect();
        contexts.sort_by(|left, right| {
            compare_code_points(left.at("context_id").str(), right.at("context_id").str())
        });
        contexts
    }

    /// Release interned contexts.
    pub fn clear(&mut self) {
        self.contexts.clear();
        self.ids_by_canonical.clear();
    }
}

/// `javaScriptSemanticNodeId`.
pub fn semantic_node_id(kind: &str, identity: &Json) -> String {
    let semantic = Obj::new()
        .with("kind", kind)
        .with("identity", identity.clone());
    format!("jsrg_node_{}", Json::from(semantic).digest())
}

/// An insertion-ordered map keyed by fact identifier (JavaScript `Map` semantics).
#[derive(Default, Clone)]
pub struct OrderedFacts {
    order: Vec<String>,
    values: HashMap<String, Json>,
}

impl OrderedFacts {
    /// Whether the identifier is present.
    pub fn has(&self, id: &str) -> bool {
        self.values.contains_key(id)
    }
    /// Read one fact.
    pub fn get(&self, id: &str) -> Option<&Json> {
        self.values.get(id)
    }
    /// `Map.set`: replace in place or append.
    pub fn set(&mut self, id: String, value: Json) {
        if !self.values.contains_key(&id) {
            self.order.push(id.clone());
        }
        self.values.insert(id, value);
    }
    /// Number of facts.
    pub fn len(&self) -> usize {
        self.order.len()
    }
    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
    /// Facts in insertion order.
    pub fn values(&self) -> Vec<Json> {
        self.order
            .iter()
            .filter_map(|id| self.values.get(id).cloned())
            .collect()
    }
    /// Identifiers in insertion order.
    pub fn keys(&self) -> &[String] {
        &self.order
    }
    /// Remove all facts.
    pub fn clear(&mut self) {
        self.order.clear();
        self.values.clear();
    }
}

/// `SemanticGraphProjectionState`.
#[derive(Default)]
pub struct ProjectionState {
    /// Retained nodes.
    pub nodes: OrderedFacts,
    /// Retained relations.
    pub relations: OrderedFacts,
    /// Retained unknowns.
    pub unknowns: OrderedFacts,
    /// Absolute unknown capacity during admission.
    pub unknown_capacity: Option<usize>,
    /// Omitted unknown occurrences by `family:reason`.
    pub unknown_omissions: OrderedFacts,
    /// Evidence contexts.
    pub evidence: EvidenceRegistry,
    /// Root node identifiers in insertion order.
    pub roots: Vec<String>,
    /// Remaining node budget for the current file.
    pub file_node_budget: Option<usize>,
    /// Whether the current file lost nodes to its budget.
    pub file_nodes_dropped: bool,
}

/// `SemanticNodeConstructionInput`.
pub struct NodeSpec<'a> {
    /// Node kind.
    pub kind: &'a str,
    /// Role key.
    pub role_key: JsString,
    /// Source range or `null`.
    pub location: Json,
    /// Display label.
    pub label: Option<JsString>,
    /// Owning function node.
    pub function_node_id: Option<JsString>,
    /// Properties.
    pub properties: Obj,
}

/// Semantic evidence for observed syntax (`observedSemanticEvidence`).
pub fn observed_evidence(file: &Json, location: &Json) -> Json {
    let path = file.at("path").text();
    let sha = file.at("sha256").str();
    let location = if location.is_null() {
        Obj::new().with("available", true).with(
            "value",
            Obj::new().with("kind", "artifact-path").with("path", path),
        )
    } else {
        let mut value = Obj::new().with("kind", "source-range").with("source", path);
        value.extend_from(&location.obj());
        Obj::new().with("available", true).with("value", value)
    };
    Obj::new()
        .with("authority", "ast-static-analysis")
        .with("state", "observed")
        .with("confidence", "exact")
        .with(
            "artifact",
            Obj::new()
                .with("available", true)
                .with("artifact_id", format!("art_{sha}"))
                .with("sha256", sha),
        )
        .with("location", location)
        .with(
            "extractor",
            Obj::new()
                .with("name", "rea-javascript-semantic-analysis")
                .with("version", "1")
                .with("operation", "analyze_javascript_application")
                .with("executable_sha256", Json::Null),
        )
        .with(
            "coverage",
            Obj::new()
                .with("status", "complete")
                .with("truncated", false)
                .with("omitted_count", 0.0)
                .with("limits", Json::Array(Vec::new())),
        )
        .with("limitations", Json::Array(Vec::new()))
        .with("evidence_ids", Json::Array(Vec::new()))
        .into()
}

const INFERENCE_LIMITATION: &str = "This relationship is a conservative static candidate; it does not prove runtime execution or causal flow.";

/// `inferredSemanticEvidence`.
pub fn inferred_evidence(source: &Json) -> Json {
    let mut object = source.obj();
    object.set("authority", "static-relationship-inference");
    object.set("state", "inferred");
    object.set("confidence", "high");
    object.set("limitations", strings([INFERENCE_LIMITATION]));
    object.into()
}

/// `inferredSemanticEvidenceAt`.
pub fn inferred_evidence_at(file: &Json, location: &Json) -> Json {
    inferred_evidence(&observed_evidence(file, location))
}

/// `unknownSemanticEvidence`.
pub fn unknown_evidence(file: &Json, location: &Json) -> Json {
    let mut object = observed_evidence(file, location).obj();
    object.set("authority", "unknown");
    object.set("state", "unknown");
    object.set("confidence", "unknown");
    object.set(
        "limitations",
        strings(["Dynamic syntax prevents an exact static relationship."]),
    );
    object.into()
}

fn display_text(label: &JsString) -> JsString {
    if label.is_empty() {
        JsString::from("\"\"")
    } else {
        label.clone()
    }
}

fn node_identity(file: &Json, location: &Json, role_key: &JsString) -> Json {
    Obj::new()
        .with("artifact_sha256", file.at("sha256").clone())
        .with("module_path", file.at("path").clone())
        .with("source_range", location.clone())
        .with("role_key", role_key)
        .into()
}

/// `addSemanticGraphNode` budget admission for one constructed node.
fn admit_node(state: &mut ProjectionState, node: Json) -> Option<Json> {
    let id = node.at("node_id").str().to_owned();
    if let Some(existing) = state.nodes.get(&id) {
        return Some(existing.clone());
    }
    if let Some(budget) = state.file_node_budget {
        if budget == 0 {
            state.file_nodes_dropped = true;
            return None;
        }
        state.file_node_budget = Some(budget - 1);
    }
    state.nodes.set(id, node.clone());
    Some(node)
}

/// `retainSemanticGraphNode`.
pub fn retain_node(state: &mut ProjectionState, file: &Json, spec: NodeSpec<'_>) -> Option<Json> {
    let identity = node_identity(file, &spec.location, &spec.role_key);
    let id = semantic_node_id(spec.kind, &identity);
    if let Some(existing) = state.nodes.get(&id) {
        return Some(existing.clone());
    }
    if state.file_node_budget == Some(0) {
        state.file_nodes_dropped = true;
        return None;
    }
    let evidence = state
        .evidence
        .intern(&observed_evidence(file, &spec.location));
    let node: Json = Obj::new()
        .with("kind", spec.kind)
        .with("identity", identity)
        .with("function_node_id", spec.function_node_id)
        .with("application_node_ids", Json::Array(Vec::new()))
        .with("label", spec.label.map(|label| display_text(&label)))
        .with("properties", spec.properties)
        .with("evidence", evidence)
        .with("node_id", id)
        .into();
    admit_node(state, node)
}

/// `addSemanticGraphRelation` inputs.
pub struct RelationSpec<'a> {
    /// Source node.
    pub source: Option<&'a Json>,
    /// Target node.
    pub target: Option<&'a Json>,
    /// Relation.
    pub relation: &'a str,
    /// Resolution; defaults to `candidate`.
    pub resolution: &'a str,
    /// Explicit evidence; defaults to inference from the source node.
    pub evidence: Option<Json>,
    /// Properties.
    pub properties: Obj,
}

impl<'a> RelationSpec<'a> {
    /// A relation with default evidence and no properties.
    pub fn new(
        source: Option<&'a Json>,
        target: Option<&'a Json>,
        relation: &'a str,
        resolution: &'a str,
    ) -> Self {
        Self {
            source,
            target,
            relation,
            resolution,
            evidence: None,
            properties: Obj::new(),
        }
    }
}

/// `addSemanticGraphRelation`.
pub fn add_relation(state: &mut ProjectionState, spec: RelationSpec<'_>) {
    let (Some(source), Some(target)) = (spec.source, spec.target) else {
        return;
    };
    if source.at("node_id") == target.at("node_id") {
        return;
    }
    let evidence = spec
        .evidence
        .unwrap_or_else(|| inferred_evidence(&state.evidence.resolve(source.at("evidence"))));
    let semantic = Obj::new()
        .with("source_node_id", source.at("node_id").clone())
        .with("target_node_id", target.at("node_id").clone())
        .with("relation", spec.relation)
        .with("resolution", spec.resolution)
        .with("properties", spec.properties)
        .with("evidence", state.evidence.intern(&evidence));
    let id = format!("jsrg_relation_{}", Json::from(semantic.clone()).digest());
    if state.relations.has(&id) {
        return;
    }
    state
        .relations
        .set(id.clone(), semantic.with("relation_id", id).into());
}

/// `recordSemanticUnknownOmission`.
pub fn record_unknown_omission(state: &mut ProjectionState, omission: &Json) {
    let key = format!(
        "{}:{}",
        omission.at("family").str(),
        omission.at("reason").str()
    );
    let occurrences = state
        .unknown_omissions
        .get(&key)
        .map_or(0.0, |existing| existing.at("occurrences").num())
        + omission.at("occurrences").num();
    let mut value = omission.obj();
    value.set("occurrences", occurrences);
    state.unknown_omissions.set(key, value.into());
}

/// `addSemanticGraphUnknown` inputs.
pub struct UnknownSpec<'a> {
    /// Frontier node.
    pub node_id: Option<String>,
    /// Family.
    pub family: &'a str,
    /// Relation kinds.
    pub relation_kinds: Vec<String>,
    /// Reason.
    pub reason: &'a str,
    /// Detail.
    pub detail: JsString,
    /// Candidate nodes.
    pub candidate_node_ids: Vec<String>,
    /// Evidence.
    pub evidence: Json,
}

/// `addSemanticGraphUnknown`.
pub fn add_unknown(state: &mut ProjectionState, spec: UnknownSpec<'_>) {
    if let Some(capacity) = state.unknown_capacity
        && state.unknowns.len() >= capacity
    {
        let omission = Obj::new()
            .with("family", spec.family)
            .with("reason", spec.reason)
            .with("occurrences", 1.0);
        record_unknown_omission(state, &omission.into());
        return;
    }
    let semantic = Obj::new()
        .with("node_id", spec.node_id)
        .with("family", spec.family)
        .with(
            "relation_kinds",
            strings(unique_sorted(spec.relation_kinds)),
        )
        .with("reason", spec.reason)
        .with("detail", spec.detail)
        .with(
            "candidate_node_ids",
            strings(unique_sorted(spec.candidate_node_ids)),
        )
        .with("evidence", state.evidence.intern(&spec.evidence));
    let id = format!("jsrg_unknown_{}", Json::from(semantic.clone()).digest());
    if state.unknowns.has(&id) {
        return;
    }
    state
        .unknowns
        .set(id.clone(), semantic.with("unknown_id", id).into());
}

/// `createJavaScriptSemanticFingerprint`.
pub fn create_fingerprint(state: &mut ProjectionState, input: Obj) -> Json {
    let input: Json = input.into();
    let mut components = input.at("components").obj();
    components.set(
        "effects",
        strings(unique_sorted(
            input
                .at("components")
                .at("effects")
                .arr()
                .iter()
                .map(|item| item.str().to_owned()),
        )),
    );
    let components: Json = components.into();
    let fingerprint_sha256 = components.digest();
    let mut semantic = input.obj();
    semantic.set("components", components);
    semantic.set(
        "limitations",
        strings(unique_sorted(
            input
                .at("limitations")
                .arr()
                .iter()
                .map(|item| item.str().to_owned()),
        )),
    );
    semantic.set("evidence", state.evidence.intern(input.at("evidence")));
    let id_input = Obj::new()
        .with("function_node_id", input.at("function_node_id").clone())
        .with("algorithm", input.at("algorithm").clone())
        .with("fingerprint_sha256", fingerprint_sha256.as_str());
    let id = format!("jsrg_fingerprint_{}", Json::from(id_input).digest());
    semantic
        .with("fingerprint_sha256", fingerprint_sha256)
        .with("fingerprint_id", id)
        .into()
}

/// `addSemanticFallbackRoot`.
pub fn add_fallback_root(root_sha256: &str, state: &mut ProjectionState) {
    let identity: Json = Obj::new()
        .with("artifact_sha256", root_sha256)
        .with("module_path", "unknown-semantic-root")
        .with("source_range", Json::Null)
        .with("role_key", "artifact-root")
        .into();
    let evidence: Json = Obj::new()
        .with("authority", "unknown")
        .with("state", "unavailable")
        .with("confidence", "unknown")
        .with(
            "artifact",
            Obj::new()
                .with("available", true)
                .with("artifact_id", format!("art_{root_sha256}"))
                .with("sha256", root_sha256),
        )
        .with(
            "location",
            Obj::new()
                .with("available", false)
                .with("reason", "not-observed")
                .with(
                    "detail",
                    "No admitted JavaScript source produced semantic IR.",
                ),
        )
        .with(
            "extractor",
            Obj::new()
                .with("name", "rea-javascript-semantic-analysis")
                .with("version", "1")
                .with("operation", "analyze_javascript_application")
                .with("executable_sha256", Json::Null),
        )
        .with(
            "coverage",
            Obj::new()
                .with("status", "unavailable")
                .with("truncated", false)
                .with("omitted_count", Json::Null)
                .with("limits", Json::Array(Vec::new())),
        )
        .with(
            "limitations",
            strings(["This synthetic graph root does not claim a source location."]),
        )
        .with("evidence_ids", Json::Array(Vec::new()))
        .into();
    let id = semantic_node_id("module", &identity);
    let node: Json = Obj::new()
        .with("kind", "module")
        .with("identity", identity)
        .with("function_node_id", Json::Null)
        .with("application_node_ids", Json::Array(Vec::new()))
        .with("label", "unavailable semantic root")
        .with("properties", Obj::new())
        .with("evidence", state.evidence.intern(&evidence))
        .with("node_id", id)
        .into();
    if let Some(node) = admit_node(state, node) {
        add_root(state, node.at("node_id").str());
    }
}

/// `state.roots.add`.
pub fn add_root(state: &mut ProjectionState, id: &str) {
    if !state.roots.iter().any(|root| root == id) {
        state.roots.push(id.to_owned());
    }
}

fn location_key(sha: &JsString, path: &JsString, range: &Json) -> JsString {
    let range = if range.is_null() {
        JsString::from("artifact-path")
    } else {
        let point = |point: &Json| {
            format!(
                "{}:{}",
                super::json::js_int(point.at("line").num()),
                super::json::js_int(point.at("column").num())
            )
        };
        JsString::from(format!(
            "{}-{}",
            point(range.at("start")),
            point(range.at("end"))
        ))
    };
    sha.concat_str("\0")
        .concat(path)
        .concat_str("\0")
        .concat(&range)
}

/// `bindSemanticGraphApplicationNodes`.
pub fn bind_application_nodes(state: &mut ProjectionState, application_nodes: &[Json]) {
    let mut index: HashMap<JsString, Vec<String>> = HashMap::new();
    for node in application_nodes {
        let id = node.at("node_id").str();
        for observation in node.at("observations").arr() {
            let evidence = observation.at("evidence");
            let (artifact, location) = (evidence.at("artifact"), evidence.at("location"));
            if artifact.at("available").as_bool() != Some(true)
                || location.at("available").as_bool() != Some(true)
            {
                continue;
            }
            let value = location.at("value");
            let sha = artifact.at("sha256").text();
            let key = match value.at("kind").str() {
                "artifact-path" => location_key(sha, value.at("path").text(), &Json::Null),
                "source-range" => location_key(
                    sha,
                    value.at("source").text(),
                    &Obj::new()
                        .with("start", value.at("start").clone())
                        .with("end", value.at("end").clone())
                        .into(),
                ),
                _ => continue,
            };
            let entry = index.entry(key).or_default();
            if !entry.iter().any(|existing| existing == id) {
                entry.push(id.to_owned());
            }
        }
    }
    for values in index.values_mut() {
        values.sort_by(|left, right| super::json::compare_utf16_str(left, right));
    }
    let ids: Vec<String> = state.nodes.keys().to_vec();
    for id in ids {
        let Some(node) = state.nodes.get(&id) else {
            continue;
        };
        let identity = node.at("identity");
        let key = location_key(
            identity.at("artifact_sha256").text(),
            identity.at("module_path").text(),
            identity.at("source_range"),
        );
        let mut updated = node.obj();
        updated.set(
            "application_node_ids",
            strings(index.get(&key).cloned().unwrap_or_default()),
        );
        state.nodes.set(id, updated.into());
    }
}

/// Graph-level inputs for sealing.
pub struct SemanticGraphContent {
    /// Root artifact digest.
    pub root_artifact_sha256: String,
    /// Application graph identifier.
    pub application_graph_id: String,
    /// Root node identifiers.
    pub root_node_ids: Vec<String>,
    /// Evidence contexts.
    pub evidence_contexts: Vec<Json>,
    /// Nodes.
    pub nodes: Vec<Json>,
    /// Relations.
    pub relations: Vec<Json>,
    /// Fingerprints.
    pub fingerprints: Vec<Json>,
    /// Unknowns.
    pub unknowns: Vec<Json>,
    /// Coverage.
    pub coverage: Json,
    /// Limitations.
    pub limitations: Vec<String>,
}

fn sort_by_field(values: &mut [Json], field: &str) {
    values.sort_by(|left, right| compare_code_points(left.at(field).str(), right.at(field).str()));
}

/// `sealTransferredJavaScriptSemanticGraphSteps`: normalize and derive `graph_id`.
pub fn seal_semantic_graph(content: SemanticGraphContent) -> Json {
    let SemanticGraphContent {
        root_artifact_sha256,
        application_graph_id,
        root_node_ids,
        mut evidence_contexts,
        mut nodes,
        mut relations,
        mut fingerprints,
        mut unknowns,
        coverage,
        limitations,
    } = content;
    sort_by_field(&mut evidence_contexts, "context_id");
    sort_by_field(&mut nodes, "node_id");
    sort_by_field(&mut relations, "relation_id");
    sort_by_field(&mut fingerprints, "fingerprint_id");
    sort_by_field(&mut unknowns, "unknown_id");
    let mut normalized = coverage.obj();
    let mut limits = coverage.at("limits").arr().to_vec();
    limits.sort_by(|left, right| compare_code_points(&left.canonical(), &right.canonical()));
    normalized.set("limits", Json::Array(limits));
    if let Some(omitted) = coverage.get("omitted_unknown_occurrences") {
        let mut omitted = omitted.arr().to_vec();
        omitted.sort_by(|left, right| {
            let key =
                |value: &Json| format!("{}:{}", value.at("family").str(), value.at("reason").str());
            compare_code_points(&key(left), &key(right))
        });
        normalized.set("omitted_unknown_occurrences", Json::Array(omitted));
    }
    let mut families: Vec<Json> = coverage
        .at("families")
        .arr()
        .iter()
        .map(|family| {
            let mut object = family.obj();
            object.set(
                "unknown_ids",
                strings(unique_sorted(
                    family
                        .at("unknown_ids")
                        .arr()
                        .iter()
                        .map(|id| id.str().to_owned()),
                )),
            );
            object.into()
        })
        .collect();
    sort_by_field(&mut families, "family");
    normalized.set("families", Json::Array(families));
    let content = Obj::new()
        .with("schema", "JavaScriptSemanticRelationGraph")
        .with("root_artifact_sha256", root_artifact_sha256)
        .with("application_graph_id", application_graph_id)
        .with("root_node_ids", strings(unique_sorted(root_node_ids)))
        .with("evidence_contexts", Json::Array(evidence_contexts))
        .with("nodes", Json::Array(nodes))
        .with("relations", Json::Array(relations))
        .with("fingerprints", Json::Array(fingerprints))
        .with("unknowns", Json::Array(unknowns))
        .with("coverage", normalized)
        .with("limitations", strings(unique_sorted(limitations)));
    let id = format!("jsrg_{}", Json::from(content.clone()).digest());
    content.with("graph_id", id).into()
}

#[cfg(test)]
mod tests {
    use super::super::super::semantic::value_types::JsString;
    use super::*;

    #[test]
    fn observed_evidence_preserves_unpaired_path_units() {
        let path = JsString::from_utf16(vec![0x0061, 0xd800, 0x0062]);
        let file: Json = Obj::new()
            .with("path", path.clone())
            .with("sha256", "sha")
            .into();

        let evidence = observed_evidence(&file, &Json::Null);
        let stored = evidence
            .at("location")
            .at("value")
            .at("path")
            .as_js_string()
            .expect("artifact path should remain a JavaScript string");

        assert_eq!(stored.units(), path.units());
        assert_ne!(stored.units(), JsString::from("a\\ud800b").units());
    }
}
