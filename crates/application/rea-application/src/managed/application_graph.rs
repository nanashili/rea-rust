//! Provider-neutral graph projection for managed inspection Evidence.
//!
//! The projection consumes already authenticated inspection records. It never
//! reparses metadata or treats build-local tokens as global identities.

use rea_core::canonical_json;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const ARTIFACT_OPERATION: &str = "inspect_managed_artifact";
const MEMBERS_OPERATION: &str = "inspect_managed_members";
const BOUNDARIES_OPERATION: &str = "inspect_managed_native_boundaries";

/// Project one or more managed inspection Evidence records into the shared graph shape.
pub fn project(input: &Value) -> Result<Value, String> {
    let sources = Sources::parse(input)?;
    let identity = sources.identity()?;
    let mut graph = Graph::new(identity.sha256.clone(), identity.path.clone(), &sources);

    let artifact_node = graph.node(
        "artifact",
        json!({"strategy":"content-digest","stability":"global-exact","sha256":identity.sha256}),
        json!({"label": basename(&identity.path), "properties":{"format":"pe","source":"managed-application-graph"}, "evidence":graph.evidence(None)}),
    )?;

    graph.add_identities(&sources, &artifact_node)?;
    graph.add_members(&sources, &artifact_node)?;
    graph.add_boundaries(&sources, &artifact_node)?;

    graph.finish(artifact_node, &sources)
}

struct Sources<'a> {
    artifact: Option<Source<'a>>,
    members: Option<Source<'a>>,
    boundaries: Option<Source<'a>>,
}

#[derive(Clone, Copy)]
struct Source<'a> {
    evidence: &'a Value,
    result: &'a Value,
}

impl<'a> Sources<'a> {
    fn parse(input: &'a Value) -> Result<Self, String> {
        let object = input
            .as_object()
            .ok_or("managed graph input must be an object")?;
        let source = |key: &str, operation: &str| -> Result<Option<Source<'a>>, String> {
            let Some(evidence) = object.get(key) else {
                return Ok(None);
            };
            let actual = evidence
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if actual != operation {
                return Err(format!(
                    "{key} Evidence operation is {actual:?}, expected {operation:?}"
                ));
            }
            let result = evidence
                .get("normalized_result")
                .or_else(|| evidence.get("result"))
                .ok_or_else(|| format!("{key} Evidence has no normalized_result"))?;
            Ok(Some(Source { evidence, result }))
        };
        let sources = Self {
            artifact: source("managed_artifact", ARTIFACT_OPERATION)?,
            members: source("managed_members", MEMBERS_OPERATION)?,
            boundaries: source("managed_native_boundaries", BOUNDARIES_OPERATION)?,
        };
        if sources.artifact.is_none() && sources.members.is_none() && sources.boundaries.is_none() {
            return Err("at least one managed Evidence source is required".into());
        }
        Ok(sources)
    }

    fn identity(&self) -> Result<Identity, String> {
        let first = [self.artifact, self.members, self.boundaries]
            .into_iter()
            .flatten()
            .next()
            .unwrap();
        let sha256 = first
            .result
            .pointer("/artifact/sha256")
            .or_else(|| first.result.get("sha256"))
            .and_then(Value::as_str)
            .ok_or("managed artifact identity has no sha256")?
            .to_owned();
        let path = first
            .result
            .pointer("/artifact/path")
            .or_else(|| first.result.get("path"))
            .and_then(Value::as_str)
            .or_else(|| {
                first
                    .evidence
                    .pointer("/subject/local_path")
                    .and_then(Value::as_str)
            })
            .unwrap_or("artifact.pe")
            .to_owned();
        let mut known_mvids = Vec::new();
        for source in [self.artifact, self.members, self.boundaries]
            .into_iter()
            .flatten()
        {
            let candidate = source
                .result
                .pointer("/artifact/sha256")
                .or_else(|| source.result.get("sha256"))
                .and_then(Value::as_str)
                .ok_or("managed Evidence has no artifact sha256")?;
            if candidate != sha256 {
                return Err("managed graph inputs must describe the same artifact SHA-256".into());
            }
            if let Some(scope_sha256) = source
                .result
                .pointer("/identity_scope/requires_artifact_sha256")
                .and_then(Value::as_str)
            {
                if scope_sha256 != sha256 {
                    return Err(
                        "managed Evidence token scope does not match artifact SHA-256".into(),
                    );
                }
            }
            let module_mvid = source
                .result
                .pointer("/module/mvid")
                .and_then(Value::as_str);
            let scoped_mvid = source
                .result
                .pointer("/identity_scope/requires_mvid")
                .and_then(Value::as_str);
            if scoped_mvid.is_some() && !token_scopes_match(scoped_mvid, module_mvid) {
                return Err("managed Evidence token scope does not match module MVID".into());
            }
            known_mvids.extend(module_mvid.into_iter().chain(scoped_mvid));
        }
        if known_mvids
            .windows(2)
            .any(|pair| !pair[0].eq_ignore_ascii_case(pair[1]))
        {
            return Err("managed graph inputs report conflicting known module MVIDs".into());
        }
        Ok(Identity { sha256, path })
    }
}

struct Identity {
    sha256: String,
    path: String,
}

struct Graph {
    sha256: String,
    path: String,
    evidence_ids: Vec<String>,
    nodes: Vec<Value>,
    edges: Vec<Value>,
    type_ids: BTreeMap<String, String>,
    method_ids: BTreeMap<String, String>,
}

impl Graph {
    fn new(sha256: String, path: String, sources: &Sources<'_>) -> Self {
        let evidence_ids = [sources.artifact, sources.members, sources.boundaries]
            .into_iter()
            .flatten()
            .filter_map(|source| {
                source
                    .evidence
                    .get("evidence_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
        Self {
            sha256,
            path,
            evidence_ids,
            nodes: Vec::new(),
            edges: Vec::new(),
            type_ids: BTreeMap::new(),
            method_ids: BTreeMap::new(),
        }
    }

    fn node(&mut self, kind: &str, identity: Value, observation: Value) -> Result<String, String> {
        let node_id = format!(
            "jag_node_{}",
            digest(&json!({"kind":kind,"identity":identity}))?
        );
        let mut obs = observation;
        let observation_id = format!(
            "jag_observation_{}",
            digest(
                &json!({"node_id":node_id,"label":obs["label"],"source_map_reference":obs["source_map_reference"],"properties":obs["properties"],"evidence":obs["evidence"]})
            )?
        );
        obs["observation_id"] = Value::String(observation_id);
        obs["identifier_strategy"] =
            json!({"strategy":"semantic-content-sha256","stability":"observation-exact"});
        self.nodes
            .push(json!({"node_id":node_id,"kind":kind,"identity":identity,"observations":[obs]}));
        Ok(node_id)
    }

    fn evidence(&self, source: Option<&Source<'_>>) -> Value {
        let operation = source
            .and_then(|s| s.evidence.get("operation"))
            .cloned()
            .unwrap_or_else(|| json!("project_managed_application_graph"));
        let coverage_state = source
            .and_then(|value| value.result.pointer("/coverage/state"))
            .and_then(Value::as_str)
            .unwrap_or("complete");
        let coverage = source_coverage(coverage_state);
        let limitations = if coverage_state == "complete" {
            Vec::new()
        } else {
            vec!["The source managed Evidence slice is incomplete; unreturned or unavailable items remain unobserved.".to_owned()]
        };
        let evidence_ids = source
            .and_then(|value| value.evidence.get("evidence_id"))
            .and_then(Value::as_str)
            .map(|value| vec![value.to_owned()])
            .unwrap_or_else(|| self.evidence_ids.clone());
        json!({"authority":"managed-static-analysis","state":"observed","confidence":"exact","artifact":{"available":true,"artifact_id":format!("art_{}",self.sha256),"sha256":self.sha256},"location":{"available":true,"value":{"kind":"artifact-path","path":graph_artifact_path(&self.path)}},"extractor":{"name":"rea-dotnet-static","version":"1","operation":operation,"executable_sha256":null},"coverage":coverage,"limitations":limitations,"evidence_ids":evidence_ids})
    }

    fn add_identities(&mut self, sources: &Sources<'_>, artifact: &str) -> Result<(), String> {
        let module_source = [sources.artifact, sources.members, sources.boundaries]
            .into_iter()
            .flatten()
            .find(|source| {
                result_payload(*source)
                    .get("module")
                    .and_then(|module| module.get("mvid"))
                    .is_some_and(|mvid| !mvid.is_null())
            })
            .or(sources.artifact)
            .or(sources.members)
            .or(sources.boundaries);
        if let Some(source) = module_source {
            if let Some(module) = result_payload(source)
                .get("module")
                .filter(|v| !v.is_null())
            {
                let token = module
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let key = module
                    .get("mvid")
                    .and_then(Value::as_str)
                    .map(|mvid| mvid.to_lowercase())
                    .unwrap_or_else(|| token.to_owned());
                let properties = json!({
                    "name": module.get("name").cloned().unwrap_or(Value::Null),
                    "mvid": module.get("mvid").cloned().unwrap_or(Value::Null),
                    "generation": module.get("generation").cloned().unwrap_or(Value::Null),
                    "token": module.get("token").cloned().unwrap_or(Value::Null),
                });
                let id = self.node(
                    "managed-module",
                    json!({"strategy":"artifact-local-key","stability":"artifact-version","artifact_sha256":self.sha256,"namespace":"managed-module","key":key}),
                    json!({"label":metadata_label(module.get("name")),"properties":properties,"evidence":self.evidence(Some(&source))}),
                )?;
                self.contains(artifact, &id, "declares-managed-module", Some(&source));
            }
        }
        if let Some(assembly) = sources
            .artifact
            .and_then(|s| result_payload(s).get("assembly"))
            .filter(|v| !v.is_null())
        {
            let token = assembly
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let properties = json!({
                "name": assembly.get("name").cloned().unwrap_or(Value::Null),
                "version": assembly.get("version").cloned().unwrap_or(Value::Null),
                "culture": assembly.get("culture").cloned().unwrap_or(Value::Null),
                "public_key_kind": assembly.pointer("/public_key/kind").cloned().unwrap_or(Value::Null),
            });
            let id = self.node("managed-assembly", json!({"strategy":"artifact-local-key","stability":"artifact-version","artifact_sha256":self.sha256,"namespace":"managed-assembly","key":token}), json!({"label":metadata_label(assembly.get("name")),"properties":properties,"evidence":self.evidence(sources.artifact.as_ref())}))?;
            self.contains(
                artifact,
                &id,
                "declares-managed-assembly",
                sources.artifact.as_ref(),
            );
        }
        for candidate in [sources.artifact, sources.members, sources.boundaries]
            .into_iter()
            .flatten()
        {
            self.add_references(candidate, artifact)?;
        }
        Ok(())
    }

    fn add_references(&mut self, source: Source<'_>, artifact: &str) -> Result<(), String> {
        let result = result_payload(source);
        for (collection, fallback_collection, kind, namespace, relation_kind) in [
            (
                "references",
                "references",
                "managed-assembly",
                "managed-assembly-reference",
                "declares-managed-assembly-reference",
            ),
            (
                "module_refs",
                "module_references",
                "managed-module",
                "managed-module-reference",
                "declares-managed-module-reference",
            ),
        ] {
            let Some(rows) = result
                .get(collection)
                .or_else(|| result.get(fallback_collection))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for row in rows {
                let token = row
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let mut properties = row.clone();
                let state = if row.get("issue").is_some_and(|issue| !issue.is_null()) {
                    "unresolved"
                } else {
                    "observed"
                };
                properties["reference_state"] = Value::String(state.to_owned());
                let id = self.node(kind, json!({"strategy":"artifact-local-key","stability":"artifact-version","artifact_sha256":self.sha256,"namespace":namespace,"key":token}), json!({"label":row.get("name").cloned().unwrap_or(Value::Null),"properties":properties,"evidence":self.evidence(Some(&source))}))?;
                self.contains(artifact, &id, relation_kind, Some(&source));
            }
        }
        Ok(())
    }

    fn add_members(&mut self, sources: &Sources<'_>, artifact: &str) -> Result<(), String> {
        let Some(source) = sources.members else {
            return Ok(());
        };
        let result = result_payload(source);
        // Index every type before resolving method and field ownership. The
        // metadata tables are not required to be ordered by declaring type.
        if let Some(rows) = result.get("types").and_then(Value::as_array) {
            for row in rows {
                let token = token(row);
                let id = self.node(
                    "managed-type",
                    artifact_local_identity(&self.sha256, "managed-type-token", &token),
                    json!({
                        "label": metadata_label(row.get("full_name").or_else(|| row.get("name"))),
                        "properties": {
                            "token": row.get("token").cloned().unwrap_or(Value::Null),
                            "namespace": row.get("namespace").cloned().unwrap_or(Value::Null),
                            "name": row.get("name").cloned().unwrap_or(Value::Null),
                            "full_name": row.get("full_name").cloned().unwrap_or(Value::Null),
                            "flags": row.get("flags").cloned().unwrap_or(Value::Null),
                            "extends_token": row.get("extends_token").cloned().unwrap_or(Value::Null),
                        },
                        "evidence": self.evidence(Some(&source))
                    }),
                )?;
                self.type_ids.insert(token, id.clone());
                self.contains(artifact, &id, "declares-managed-type", Some(&source));
            }
        }
        if let Some(rows) = result.get("methods").and_then(Value::as_array) {
            for row in rows {
                let token = token(row);
                let id = self.node(
                    "managed-method",
                    artifact_local_identity(&self.sha256, "managed-method-token", &token),
                    json!({
                        "label": member_label(row),
                        "properties": member_properties(row, true),
                        "evidence": self.evidence(Some(&source))
                    }),
                )?;
                self.method_ids.insert(token, id.clone());
                let owner = declaring_type_owner(row, &self.type_ids, artifact);
                self.contains(&owner, &id, "declares-managed-method", Some(&source));
            }
        }
        for row in result
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let token = token(row);
            let id = self.node("managed-field", artifact_local_identity(&self.sha256, "managed-field-token", &token), json!({"label":member_label(row),"properties":member_properties(row, false),"evidence":self.evidence(Some(&source))}))?;
            let owner = declaring_type_owner(row, &self.type_ids, artifact);
            self.contains(&owner, &id, "declares-managed-field", Some(&source));
        }
        Ok(())
    }

    fn add_boundaries(&mut self, sources: &Sources<'_>, artifact: &str) -> Result<(), String> {
        let Some(source) = sources.boundaries else {
            return Ok(());
        };
        let can_join_member_tokens = sources.members.is_some_and(|members| {
            let left = result_payload(members)
                .pointer("/identity_scope/requires_mvid")
                .and_then(Value::as_str);
            let right = result_payload(source)
                .pointer("/identity_scope/requires_mvid")
                .and_then(Value::as_str);
            token_scopes_match(left, right)
        });
        for (collection, kind, namespace, relation) in [
            (
                "pinvoke_imports",
                "managed-pinvoke-import",
                "managed-pinvoke-token",
                "imports",
            ),
            (
                "native_implementations",
                "managed-native-implementation",
                "managed-native-implementation-token",
                "contains",
            ),
        ] {
            for row in source
                .result
                .get(collection)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let token = token(row);
                let properties = boundary_properties(row, kind);
                let label = if kind == "managed-pinvoke-import" {
                    row.get("import_name")
                } else {
                    row.get("name")
                };
                let id = self.node(kind, artifact_local_identity(&self.sha256, namespace, &token), json!({"label":metadata_label(label),"properties":properties,"evidence":self.evidence(Some(&source))}))?;
                let owner = row
                    .get("member_token")
                    .or_else(|| row.get("token"))
                    .and_then(Value::as_str)
                    .filter(|_| can_join_member_tokens)
                    .and_then(|t| self.method_ids.get(t))
                    .cloned()
                    .unwrap_or_else(|| artifact.to_owned());
                let properties = if kind == "managed-pinvoke-import" {
                    json!({
                        "kind": "managed-pinvoke",
                        "import_name": row.get("import_name").cloned().unwrap_or(Value::Null),
                        "import_scope_name": row.get("import_scope_name").cloned().unwrap_or(Value::Null),
                    })
                } else {
                    json!({"kind":"declares-managed-native-implementation"})
                };
                self.edge(&owner, &id, relation, &properties, Some(&source));
            }
        }
        Ok(())
    }

    fn contains(&mut self, source: &str, target: &str, kind: &str, evidence: Option<&Source<'_>>) {
        self.edge(source, target, "contains", &json!({"kind":kind}), evidence);
    }
    fn edge(
        &mut self,
        source: &str,
        target: &str,
        relation: &str,
        properties: &Value,
        evidence: Option<&Source<'_>>,
    ) {
        let semantic = json!({"source_node_id":source,"target_node_id":target,"relation":relation,"properties":properties,"evidence":self.evidence(evidence)});
        let edge_id = format!(
            "jag_edge_{}",
            digest(&semantic).unwrap_or_else(|_| "unknown".to_owned())
        );
        self.edges.push(json!({"edge_id":edge_id,"identifier_strategy":{"strategy":"semantic-content-sha256","stability":"relationship-exact"},"source_node_id":source,"target_node_id":target,"relation":relation,"properties":properties,"evidence":self.evidence(evidence)}));
    }

    fn finish(self, root: String, sources: &Sources<'_>) -> Result<Value, String> {
        let coverage_status = if sources_have_complete_coverage(sources) {
            "complete"
        } else {
            "partial"
        };
        let graph_limitations = [
            "Managed graph projection preserves static metadata observations only; it does not execute managed code or map managed tokens to native addresses.",
        ];
        let graph_coverage = if coverage_status == "complete" {
            json!({"status":"complete","truncated":false,"omitted_count":0,"limits":[]})
        } else {
            json!({"status":"partial","truncated":false,"omitted_count":null,"limits":[]})
        };
        let graph = json!({"schema":"JavaScriptApplicationGraph","root_node_ids":[root],"nodes":self.nodes,"edges":self.edges,"coverage":graph_coverage,"limitations":graph_limitations});
        let mut limitations = graph_limitations
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        if has_unscoped_boundary_relationships(sources) {
            limitations.push("Managed boundary tokens were not linked to member nodes because matching module MVID scope was not established.".to_owned());
        }
        if coverage_status == "partial" {
            limitations.push("At least one source Evidence record has partial or unavailable coverage; graph absence is not proof of absence in the artifact.".to_owned());
        }
        if has_selected_member_types(sources) {
            limitations.push("Managed member Evidence selected only specific declaring types; type, method, and field nodes of other types are omitted, not absent.".to_owned());
        }
        let result = json!({"root_artifact_sha256":self.sha256,"source_evidence":{"managed_artifact_evidence_id":id(sources.artifact),"managed_members_evidence_id":id(sources.members),"managed_native_boundaries_evidence_id":id(sources.boundaries)},"summary":{"graph_nodes":graph["nodes"].as_array().map_or(0,Vec::len),"graph_edges":graph["edges"].as_array().map_or(0,Vec::len),"assemblies":count_kind(&graph,"managed-assembly"),"modules":count_kind(&graph,"managed-module"),"types":count_kind(&graph,"managed-type"),"methods":count_kind(&graph,"managed-method"),"fields":count_kind(&graph,"managed-field"),"pinvoke_imports":count_kind(&graph,"managed-pinvoke-import"),"native_implementations":count_kind(&graph,"managed-native-implementation")},"graph":graph,"coverage":{"status":if coverage_status == "complete" {"complete-within-inputs"} else {"partial"}},"evidence_links":self.evidence_ids,"limitations":limitations});
        let projection_id = format!("magp_{}", digest(&result)?);
        let mut output = result;
        output["projection_id"] = Value::String(projection_id);
        Ok(output)
    }
}

fn sources_have_complete_coverage(sources: &Sources<'_>) -> bool {
    let source_coverage_complete = [sources.artifact, sources.members, sources.boundaries]
        .into_iter()
        .flatten()
        .all(|source| {
            source
                .result
                .pointer("/coverage/state")
                .and_then(Value::as_str)
                .unwrap_or("complete")
                == "complete"
        });
    source_coverage_complete
        && !has_unscoped_boundary_relationships(sources)
        && !has_selected_member_types(sources)
}

fn has_selected_member_types(sources: &Sources<'_>) -> bool {
    sources
        .members
        .and_then(|source| source.result.pointer("/selection/type_names"))
        .is_some_and(|types| types.is_array())
}

fn has_unscoped_boundary_relationships(sources: &Sources<'_>) -> bool {
    let (Some(members), Some(boundaries)) = (sources.members, sources.boundaries) else {
        return false;
    };
    let has_member_relationship = result_payload(boundaries)
        .get("pinvoke_imports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|row| {
            row.get("member_token")
                .is_some_and(|value| !value.is_null())
        })
        || result_payload(boundaries)
            .get("native_implementations")
            .and_then(Value::as_array)
            .is_some_and(|rows| !rows.is_empty());
    if !has_member_relationship {
        return false;
    }
    let members_mvid = result_payload(members)
        .pointer("/identity_scope/requires_mvid")
        .and_then(Value::as_str);
    let boundaries_mvid = result_payload(boundaries)
        .pointer("/identity_scope/requires_mvid")
        .and_then(Value::as_str);
    !token_scopes_match(members_mvid, boundaries_mvid)
}

fn id(source: Option<Source<'_>>) -> Value {
    source
        .and_then(|s| s.evidence.get("evidence_id").cloned())
        .unwrap_or(Value::Null)
}

fn token(row: &Value) -> String {
    row.get("token")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned()
}

fn artifact_local_identity(sha256: &str, namespace: &str, key: &str) -> Value {
    json!({
        "strategy": "artifact-local-key",
        "stability": "artifact-version",
        "artifact_sha256": sha256,
        "namespace": namespace,
        "key": key,
    })
}

fn metadata_label(value: Option<&Value>) -> Value {
    match value.and_then(Value::as_str) {
        Some(name) if !name.is_empty() => Value::String(name.to_owned()),
        _ => Value::Null,
    }
}

fn member_label(row: &Value) -> Value {
    let declaring_type = row.get("declaring_type").and_then(Value::as_str);
    let name = row.get("name").and_then(Value::as_str).unwrap_or("");
    match declaring_type {
        Some(declaring_type) if !declaring_type.is_empty() => {
            Value::String(format!("{declaring_type}.{name}"))
        }
        _ => metadata_label(row.get("name")),
    }
}

fn member_properties(row: &Value, method: bool) -> Value {
    let mut properties = json!({
        "token": row.get("token").cloned().unwrap_or(Value::Null),
        "declaring_type_token": row.get("declaring_type_token").cloned().unwrap_or(Value::Null),
        "declaring_type": row.get("declaring_type").cloned().unwrap_or(Value::Null),
        "name": row.get("name").cloned().unwrap_or(Value::Null),
    });
    if method {
        properties["rva"] = row.get("rva").cloned().unwrap_or(Value::Null);
        properties["signature_sha256"] = row
            .pointer("/signature/raw_sha256")
            .cloned()
            .unwrap_or(Value::Null);
        properties["signature_status"] = row
            .pointer("/signature/parse_status")
            .cloned()
            .unwrap_or(Value::Null);
        properties["body_status"] = row.pointer("/body/status").cloned().unwrap_or(Value::Null);
        properties["normalized_il_sha256"] = row
            .pointer("/body/normalized_il_sha256")
            .cloned()
            .unwrap_or(Value::Null);
        properties["il_size"] = row.pointer("/body/il_size").cloned().unwrap_or(Value::Null);
    } else {
        properties["flags"] = row.get("flags").cloned().unwrap_or(Value::Null);
        properties["signature_sha256"] = row
            .pointer("/signature/raw_sha256")
            .cloned()
            .unwrap_or(Value::Null);
        properties["signature_status"] = row
            .pointer("/signature/parse_status")
            .cloned()
            .unwrap_or(Value::Null);
    }
    properties
}

fn boundary_properties(row: &Value, kind: &str) -> Value {
    if kind == "managed-pinvoke-import" {
        json!({
            "token": row.get("token").cloned().unwrap_or(Value::Null),
            "member_token": row.get("member_token").cloned().unwrap_or(Value::Null),
            "member_name": row.get("member_name").cloned().unwrap_or(Value::Null),
            "import_name": row.get("import_name").cloned().unwrap_or(Value::Null),
            "import_scope_name": row.get("import_scope_name").cloned().unwrap_or(Value::Null),
            "char_set": row.get("char_set").cloned().unwrap_or(Value::Null),
            "call_convention": row.get("call_convention").cloned().unwrap_or(Value::Null),
            "verification": row.get("verification").cloned().unwrap_or(Value::Null),
        })
    } else {
        json!({
            "token": row.get("token").cloned().unwrap_or(Value::Null),
            "name": row.get("name").cloned().unwrap_or(Value::Null),
            "rva": row.get("rva").cloned().unwrap_or(Value::Null),
            "code_type": row.get("code_type").cloned().unwrap_or(Value::Null),
            "managed_kind": row.get("managed_kind").cloned().unwrap_or(Value::Null),
            "pinvoke_declared": row.get("pinvoke_declared").cloned().unwrap_or(Value::Null),
            "boundary_kind": row.get("boundary_kind").cloned().unwrap_or(Value::Null),
            "body_interpretation": row.get("body_interpretation").cloned().unwrap_or(Value::Null),
        })
    }
}

fn declaring_type_owner(
    row: &Value,
    type_ids: &BTreeMap<String, String>,
    artifact: &str,
) -> String {
    row.get("declaring_type_token")
        .and_then(Value::as_str)
        .and_then(|declaring_type| type_ids.get(declaring_type))
        .cloned()
        .unwrap_or_else(|| artifact.to_owned())
}

fn token_scopes_match(left: Option<&str>, right: Option<&str>) -> bool {
    left.zip(right)
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn source_coverage(state: &str) -> Value {
    match state {
        "complete" => json!({
            "status": "complete",
            "truncated": false,
            "omitted_count": 0,
            "limits": [],
        }),
        "partial" => json!({
            "status": "partial",
            "truncated": false,
            "omitted_count": null,
            "limits": [],
        }),
        "unavailable" => json!({
            "status": "unavailable",
            "truncated": false,
            "omitted_count": null,
            "limits": [],
        }),
        _ => json!({
            "status": "unknown",
            "truncated": false,
            "omitted_count": null,
            "limits": [],
        }),
    }
}

fn result_payload(source: Source<'_>) -> &Value {
    source.result.get("members").unwrap_or(source.result)
}
fn count_kind(graph: &Value, kind: &str) -> usize {
    graph["nodes"]
        .as_array()
        .map(|rows| rows.iter().filter(|row| row["kind"] == kind).count())
        .unwrap_or(0)
}
fn digest(value: &Value) -> Result<String, String> {
    canonical_json::digest(value).map_err(|error| error.to_string())
}
fn basename(path: &str) -> String {
    path.rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("artifact.pe")
        .to_owned()
}

fn graph_artifact_path(path: &str) -> String {
    let name = basename(path);
    let sanitized = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!(
        "managed/{}",
        if sanitized.is_empty() {
            "artifact.pe"
        } else {
            &sanitized
        }
    )
}

#[cfg(test)]
mod tests {
    use super::project;
    use serde_json::json;

    #[test]
    fn projects_missing_and_cyclic_references_without_reinterpreting_tokens() {
        let input = json!({"managed_members":{"evidence_id":"ev_members","operation":"inspect_managed_members","normalized_result":{"artifact":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","path":"/tmp/a.dll"},"types":[{"token":"0x02000001","name":"A","declaring_type_token":"0x02000002"},{"token":"0x02000002","name":"B","declaring_type_token":"0x02000001"}],"methods":[],"fields":[],"references":[{"token":"0x23000001","name":"Shared","issue":null},{"token":"0x23000002","name":"Shared","issue":"unresolved assembly identity"}],"module_references":[{"token":"0x1a000001","name":"native-a","issue":null}]}}});
        let output = project(&input).expect("graph projection");
        assert_eq!(output["summary"]["types"], 2);
        assert_eq!(
            output["source_evidence"]["managed_members_evidence_id"],
            "ev_members"
        );
        assert_eq!(output["summary"]["assemblies"], 2);
        assert_eq!(output["summary"]["modules"], 1);
        let references = output["graph"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|node| node["kind"] == "managed-assembly")
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 2);
        assert_ne!(references[0]["node_id"], references[1]["node_id"]);
    }

    #[test]
    fn rejects_unresolved_artifact_identity_mismatch() {
        let input = json!({"managed_members":{"evidence_id":"ev_members","operation":"inspect_managed_members","normalized_result":{"artifact":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}},"managed_native_boundaries":{"evidence_id":"ev_boundaries","operation":"inspect_managed_native_boundaries","normalized_result":{"artifact":{"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}});
        assert!(project(&input).is_err());
    }

    #[test]
    fn carries_partial_source_coverage_into_graph_result() {
        let input = json!({
            "managed_members": {
                "evidence_id": "ev_members",
                "operation": "inspect_managed_members",
                "normalized_result": {
                    "artifact": {"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    "coverage": {"state":"partial"},
                    "types": [], "methods": [], "fields": []
                }
            }
        });
        let output = project(&input).expect("graph projection");
        assert_eq!(output["coverage"]["status"], "partial");
        assert_eq!(output["graph"]["coverage"]["status"], "partial");
    }
}
