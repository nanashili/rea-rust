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
    coverage.set("limits", Json::array(limits));
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
                self.contexts.insert(
                    id.clone(),
                    context.with_static("context_id", id.as_str()).into(),
                );
                self.ids_by_canonical.insert(canonical, id.clone());
                id
            }
        };
        Obj::new()
            .with_static("context_id", id)
            .with_static("location", location)
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
    format!(
        "jsrg_node_{}",
        super::json::digest_kind_identity(kind, identity)
    )
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

    /// Move facts out in insertion order without cloning their JSON trees.
    pub fn take_values(&mut self) -> Vec<Json> {
        let mut values = std::mem::take(&mut self.values);
        self.order
            .drain(..)
            .filter_map(|id| values.remove(&id))
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
    /// File-scoped immutable evidence fields reused by this projection.
    pub evidence_template: Option<EvidenceTemplate>,
    /// Root node identifiers in insertion order.
    pub roots: Vec<String>,
    /// Remaining node budget for the current file.
    pub file_node_budget: Option<usize>,
    /// Whether the current file lost nodes to its budget.
    pub file_nodes_dropped: bool,
}

/// Immutable evidence fields shared by locations in one source file.
#[derive(Clone)]
pub struct EvidenceTemplate {
    file_path: JsString,
    file_key: (JsString, JsString),
    base: Json,
}

impl EvidenceTemplate {
    fn for_file(file: &Json) -> Self {
        let path = file.at("path").text().clone();
        let sha = file.at("sha256").str().to_owned();
        let base = Obj::new()
            .with_static("authority", "ast-static-analysis")
            .with_static("state", "observed")
            .with_static("confidence", "exact")
            .with_static(
                "artifact",
                Obj::new()
                    .with_static("available", true)
                    .with_static("artifact_id", format!("art_{sha}"))
                    .with_static("sha256", sha.as_str()),
            )
            .with_static("location", Json::Null)
            .with_static(
                "extractor",
                Obj::new()
                    .with_static("name", "rea-javascript-semantic-analysis")
                    .with_static("version", "1")
                    .with_static("operation", "analyze_javascript_application")
                    .with_static("executable_sha256", Json::Null),
            )
            .with_static(
                "coverage",
                Obj::new()
                    .with_static("status", "complete")
                    .with_static("truncated", false)
                    .with_static("omitted_count", 0.0)
                    .with_static("limits", Json::array(Vec::new())),
            )
            .with_static("limitations", Json::array(Vec::new()))
            .with_static("evidence_ids", Json::array(Vec::new()))
            .into();
        Self {
            file_path: path.clone(),
            file_key: (path, sha.into()),
            base,
        }
    }

    fn matches(&self, file: &Json) -> bool {
        self.file_key.0 == file.at("path").text() && self.file_key.1 == file.at("sha256").str()
    }

    fn location(&self, location: &Json) -> Json {
        if location.is_null() {
            Obj::new()
                .with_static("available", true)
                .with_static(
                    "value",
                    Obj::new()
                        .with_static("kind", "artifact-path")
                        .with_static("path", self.file_path.clone()),
                )
                .into()
        } else {
            let mut value = Obj::new()
                .with_static("kind", "source-range")
                .with_static("source", self.file_path.clone());
            value.extend_from(&location.obj());
            Obj::new()
                .with_static("available", true)
                .with_static("value", value)
                .into()
        }
    }

    fn observed(&self, location: &Json) -> Json {
        let mut evidence = self.base.obj();
        evidence.set("location", self.location(location));
        evidence.into()
    }

    fn unknown(&self, location: &Json) -> Json {
        let mut evidence = self.observed(location).obj();
        evidence.set("authority", "unknown");
        evidence.set("state", "unknown");
        evidence.set("confidence", "unknown");
        evidence.set(
            "limitations",
            strings(["Dynamic syntax prevents an exact static relationship."]),
        );
        evidence.into()
    }
}

impl ProjectionState {
    pub fn unknown_capacity_reached(&self) -> bool {
        self.unknown_capacity
            .is_some_and(|capacity| self.unknowns.len() >= capacity)
    }

    pub fn record_unknown_capacity_omission(&mut self, family: &str, reason: &str) {
        let omission = Obj::new()
            .with_static("family", family)
            .with_static("reason", reason)
            .with_static("occurrences", 1.0);
        record_unknown_omission(self, &omission.into());
    }

    fn template_for(&mut self, file: &Json) -> &EvidenceTemplate {
        let replace = self
            .evidence_template
            .as_ref()
            .is_none_or(|template| !template.matches(file));
        if replace {
            self.evidence_template = Some(EvidenceTemplate::for_file(file));
        }
        self.evidence_template
            .as_ref()
            .expect("evidence template was just installed")
    }

    pub fn observed_evidence(&mut self, file: &Json, location: &Json) -> Json {
        self.template_for(file).observed(location)
    }

    pub fn inferred_evidence(&mut self, file: &Json, location: &Json) -> Json {
        inferred_evidence(&self.observed_evidence(file, location))
    }

    pub fn unknown_evidence(&mut self, file: &Json, location: &Json) -> Json {
        self.template_for(file).unknown(location)
    }
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
    EvidenceTemplate::for_file(file).observed(location)
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
    EvidenceTemplate::for_file(file).unknown(location)
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
        .with_static("artifact_sha256", file.at("sha256").clone())
        .with_static("module_path", file.at("path").clone())
        .with_static("source_range", location.clone())
        .with_static("role_key", role_key)
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
    let observed = state.observed_evidence(file, &spec.location);
    let evidence = state.evidence.intern(&observed);
    let node: Json = Obj::new()
        .with_static("kind", spec.kind)
        .with_static("identity", identity)
        .with_static("function_node_id", spec.function_node_id)
        .with_static("application_node_ids", Json::array(Vec::new()))
        .with_static("label", spec.label.map(|label| display_text(&label)))
        .with_static("properties", spec.properties)
        .with_static("evidence", evidence)
        .with_static("node_id", id)
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
        .with_static("source_node_id", source.at("node_id").clone())
        .with_static("target_node_id", target.at("node_id").clone())
        .with_static("relation", spec.relation)
        .with_static("resolution", spec.resolution)
        .with_static("properties", spec.properties)
        .with_static("evidence", state.evidence.intern(&evidence));
    let id = format!("jsrg_relation_{}", Json::from(semantic.clone()).digest());
    if state.relations.has(&id) {
        return;
    }
    state
        .relations
        .set(id.clone(), semantic.with_static("relation_id", id).into());
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
    if state.unknown_capacity_reached() {
        state.record_unknown_capacity_omission(spec.family, spec.reason);
        return;
    }
    let semantic = Obj::new()
        .with_static("node_id", spec.node_id)
        .with_static("family", spec.family)
        .with_static(
            "relation_kinds",
            strings(unique_sorted(spec.relation_kinds)),
        )
        .with_static("reason", spec.reason)
        .with_static("detail", spec.detail)
        .with_static(
            "candidate_node_ids",
            strings(unique_sorted(spec.candidate_node_ids)),
        )
        .with_static("evidence", state.evidence.intern(&spec.evidence));
    let id = format!("jsrg_unknown_{}", Json::from(semantic.clone()).digest());
    if state.unknowns.has(&id) {
        return;
    }
    state
        .unknowns
        .set(id.clone(), semantic.with_static("unknown_id", id).into());
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
        .with_static("function_node_id", input.at("function_node_id").clone())
        .with_static("algorithm", input.at("algorithm").clone())
        .with_static("fingerprint_sha256", fingerprint_sha256.as_str());
    let id = format!("jsrg_fingerprint_{}", Json::from(id_input).digest());
    semantic
        .with_static("fingerprint_sha256", fingerprint_sha256)
        .with_static("fingerprint_id", id)
        .into()
}

/// `addSemanticFallbackRoot`.
pub fn add_fallback_root(root_sha256: &str, state: &mut ProjectionState) {
    let identity: Json = Obj::new()
        .with_static("artifact_sha256", root_sha256)
        .with_static("module_path", "unknown-semantic-root")
        .with_static("source_range", Json::Null)
        .with_static("role_key", "artifact-root")
        .into();
    let evidence: Json = Obj::new()
        .with_static("authority", "unknown")
        .with_static("state", "unavailable")
        .with_static("confidence", "unknown")
        .with_static(
            "artifact",
            Obj::new()
                .with_static("available", true)
                .with_static("artifact_id", format!("art_{root_sha256}"))
                .with_static("sha256", root_sha256),
        )
        .with_static(
            "location",
            Obj::new()
                .with_static("available", false)
                .with_static("reason", "not-observed")
                .with_static(
                    "detail",
                    "No admitted JavaScript source produced semantic IR.",
                ),
        )
        .with_static(
            "extractor",
            Obj::new()
                .with_static("name", "rea-javascript-semantic-analysis")
                .with_static("version", "1")
                .with_static("operation", "analyze_javascript_application")
                .with_static("executable_sha256", Json::Null),
        )
        .with_static(
            "coverage",
            Obj::new()
                .with_static("status", "unavailable")
                .with_static("truncated", false)
                .with_static("omitted_count", Json::Null)
                .with_static("limits", Json::array(Vec::new())),
        )
        .with_static(
            "limitations",
            strings(["This synthetic graph root does not claim a source location."]),
        )
        .with_static("evidence_ids", Json::array(Vec::new()))
        .into();
    let id = semantic_node_id("module", &identity);
    let node: Json = Obj::new()
        .with_static("kind", "module")
        .with_static("identity", identity)
        .with_static("function_node_id", Json::Null)
        .with_static("application_node_ids", Json::array(Vec::new()))
        .with_static("label", "unavailable semantic root")
        .with_static("properties", Obj::new())
        .with_static("evidence", state.evidence.intern(&evidence))
        .with_static("node_id", id)
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
                        .with_static("start", value.at("start").clone())
                        .with_static("end", value.at("end").clone())
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
    normalized.set("limits", Json::array(limits));
    if let Some(omitted) = coverage.get("omitted_unknown_occurrences") {
        let mut omitted = omitted.arr().to_vec();
        omitted.sort_by(|left, right| {
            let key =
                |value: &Json| format!("{}:{}", value.at("family").str(), value.at("reason").str());
            compare_code_points(&key(left), &key(right))
        });
        normalized.set("omitted_unknown_occurrences", Json::array(omitted));
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
    normalized.set("families", Json::array(families));
    let content = Obj::new()
        .with_static("schema", "JavaScriptSemanticRelationGraph")
        .with_static("root_artifact_sha256", root_artifact_sha256)
        .with_static("application_graph_id", application_graph_id)
        .with_static("root_node_ids", strings(unique_sorted(root_node_ids)))
        .with_static("evidence_contexts", Json::array(evidence_contexts))
        .with_static("nodes", Json::array(nodes))
        .with_static("relations", Json::array(relations))
        .with_static("fingerprints", Json::array(fingerprints))
        .with_static("unknowns", Json::array(unknowns))
        .with_static("coverage", normalized)
        .with_static("limitations", strings(unique_sorted(limitations)));
    let id = format!("jsrg_{}", Json::from(content.clone()).digest());
    content.with_static("graph_id", id).into()
}

#[cfg(test)]
mod tests {
    use super::super::super::semantic::value_types::JsString;
    use super::*;

    fn test_file(path: JsString, sha: &str) -> Json {
        Obj::new()
            .with_static("path", path)
            .with_static("sha256", sha)
            .into()
    }

    fn test_location(start: f64, end: f64) -> Json {
        Obj::new()
            .with_static("start", start)
            .with_static("end", end)
            .into()
    }

    #[test]
    fn observed_evidence_preserves_unpaired_path_units() {
        let path = JsString::from_utf16(vec![0x0061, 0xd800, 0x0062]);
        let file = test_file(path.clone(), "sha");

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

    #[test]
    fn cached_evidence_preserves_the_evidence_contract_and_field_order() {
        let file = test_file(JsString::from("source.js"), "sha-1");
        let location = test_location(12.0, 19.0);
        let mut state = ProjectionState::default();

        let cached_observed = state.observed_evidence(&file, &location);
        let expected = super::super::json::parse(
            r#"{
                "authority":"ast-static-analysis",
                "state":"observed",
                "confidence":"exact",
                "artifact":{"available":true,"artifact_id":"art_sha-1","sha256":"sha-1"},
                "location":{"available":true,"value":{"kind":"source-range","source":"source.js","start":12,"end":19}},
                "extractor":{"name":"rea-javascript-semantic-analysis","version":"1","operation":"analyze_javascript_application","executable_sha256":null},
                "coverage":{"status":"complete","truncated":false,"omitted_count":0,"limits":[]},
                "limitations":[],
                "evidence_ids":[]
            }"#,
        )
        .expect("valid evidence contract");
        assert_eq!(
            cached_observed.stringify(),
            expected.stringify(),
            "evidence values and field order are part of the transfer contract"
        );

        let mut expected_unknown = expected.obj();
        expected_unknown.set("authority", "unknown");
        expected_unknown.set("state", "unknown");
        expected_unknown.set("confidence", "unknown");
        expected_unknown.set(
            "limitations",
            strings(["Dynamic syntax prevents an exact static relationship."]),
        );
        assert_eq!(
            state.unknown_evidence(&file, &location),
            Json::from(expected_unknown)
        );
    }

    #[test]
    fn cached_evidence_switches_file_keys_and_is_mutation_isolated() {
        let first_file = test_file(JsString::from("first.js"), "sha-first");
        let changed_digest = test_file(JsString::from("first.js"), "sha-second");
        let changed_path = test_file(JsString::from("second.js"), "sha-second");
        let location = test_location(1.0, 2.0);
        let mut state = ProjectionState::default();

        let first = state.observed_evidence(&first_file, &location);
        let second = state.observed_evidence(&changed_digest, &location);
        assert_eq!(second.at("artifact").at("sha256").str(), "sha-second");
        let third = state.observed_evidence(&changed_path, &location);
        assert_eq!(
            third.at("location").at("value").at("source").text(),
            "second.js"
        );

        let mut mutated = first.obj();
        mutated.set("authority", "caller-mutated");
        let fresh_first = state.observed_evidence(&first_file, &location);
        assert_eq!(fresh_first.at("authority").str(), "ast-static-analysis");
        let mutated: Json = mutated.into();
        assert_eq!(mutated.at("authority").str(), "caller-mutated");
    }

    #[test]
    fn cached_location_preserves_utf16_path_and_location_override() {
        let path = JsString::from_utf16(vec![0x0061, 0xd800, 0x0062]);
        let file = test_file(path.clone(), "sha");
        let mut state = ProjectionState::default();

        let range = state.observed_evidence(&file, &test_location(3.0, 8.0));
        let source = range
            .at("location")
            .at("value")
            .at("source")
            .as_js_string()
            .expect("source-range evidence should retain the source path");
        assert_eq!(source.units(), path.units());
        assert_eq!(range.at("location").at("value").at("start").num(), 3.0);
        assert_eq!(range.at("location").at("value").at("end").num(), 8.0);

        let artifact_path = state.observed_evidence(&file, &Json::Null);
        assert_eq!(
            artifact_path.at("location").at("value").at("kind").str(),
            "artifact-path"
        );
        assert_eq!(
            artifact_path
                .at("location")
                .at("value")
                .at("path")
                .as_js_string()
                .expect("artifact path should remain a JavaScript string")
                .units(),
            path.units()
        );

        let override_location: Json = Obj::new()
            .with_static("kind", "caller-kind")
            .with_static("source", "caller-source")
            .with_static("start", 4.0)
            .into();
        let overridden = state.observed_evidence(&file, &override_location);
        let value = overridden.at("location").at("value");
        assert_eq!(value.at("kind").str(), "caller-kind");
        assert_eq!(value.at("source").str(), "caller-source");
        assert_eq!(value.at("start").num(), 4.0);
    }

    #[test]
    fn unknown_capacity_omissions_are_counted_without_admitting_extra_unknowns() {
        let mut state = ProjectionState {
            unknown_capacity: Some(1),
            ..ProjectionState::default()
        };
        let spec = || UnknownSpec {
            node_id: None,
            family: "call-flow",
            relation_kinds: vec!["calls".to_owned()],
            reason: "dynamic-call",
            detail: JsString::from("target is not statically known"),
            candidate_node_ids: Vec::new(),
            evidence: Json::Null,
        };

        add_unknown(&mut state, spec());
        add_unknown(&mut state, spec());
        add_unknown(&mut state, spec());

        assert_eq!(state.unknowns.len(), 1);
        assert_eq!(
            state
                .unknown_omissions
                .get("call-flow:dynamic-call")
                .expect("capacity omissions should be retained")
                .at("occurrences")
                .num(),
            2.0
        );
    }
}
