//! `projectRuntimeCaptures` (`javascriptRuntimeReconciliationRuntime.ts`).
use super::captures::Capture;
use super::{Defect, jag, str_of};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocationKind {
    File,
    Url,
    Unresolved,
}

pub struct Entity {
    pub kind: &'static str,
    pub section: &'static str,
    pub node: Value,
    /// Index into the sorted captures.
    pub capture: usize,
    pub runtime_key: String,
    pub location: (LocationKind, String),
    pub frame_key: Option<String>,
    pub source_sha256: Option<String>,
    pub static_kind: &'static str,
}

impl Entity {
    pub fn node_id(&self) -> &str {
        str_of(&self.node["node_id"])
    }
}

pub struct RuntimeProjection {
    pub entities: Vec<Entity>,
    pub edges: Vec<Value>,
    /// `targetNodeByEvidenceId` in capture order.
    pub target_nodes: Vec<(String, String)>,
}

impl RuntimeProjection {
    pub fn target_node(&self, evidence_id: &str) -> Option<&str> {
        self.target_nodes
            .iter()
            .rev()
            .find(|(id, _)| id == evidence_id)
            .map(|(_, node)| node.as_str())
    }
}

pub fn project_runtime_captures(captures: &[Capture]) -> Result<RuntimeProjection, Defect> {
    let mut entities = Vec::new();
    for (index, capture) in captures.iter().enumerate() {
        entities.push(target_entity(capture, index)?);
        for frame in &capture.inspection.frames {
            entities.push(frame_entity(capture, index, frame)?);
        }
        for script in &capture.inspection.scripts {
            entities.push(script_entity(capture, index, script)?);
        }
        for worker in &capture.inspection.workers {
            entities.push(worker_entity(capture, index, worker)?);
        }
    }
    let mut edges = Vec::new();
    for capture in captures {
        edges.extend(runtime_edges(capture, captures, &entities)?);
    }
    // Every entity is retained, so every edge endpoint is retained.
    let target_nodes = entities
        .iter()
        .filter(|entity| entity.kind == "target")
        .map(|entity| {
            (
                captures[entity.capture].evidence_id().to_owned(),
                entity.node_id().to_owned(),
            )
        })
        .collect();
    Ok(RuntimeProjection {
        entities,
        edges,
        target_nodes,
    })
}

fn located(entity: &Value, unresolved: bool) -> (LocationKind, String) {
    if unresolved && entity.get("unresolved_location").is_some() {
        return (
            LocationKind::Unresolved,
            str_of(&entity["unresolved_location"]["reported_url"]).to_owned(),
        );
    }
    if entity.get("url").is_some() {
        return (LocationKind::Url, str_of(&entity["url"]).to_owned());
    }
    (LocationKind::File, str_of(&entity["file_path"]).to_owned())
}

struct EntityInput<'a> {
    kind: &'static str,
    node_kind: &'a str,
    runtime_key: String,
    target_key: String,
    frame_key: Option<String>,
    script_key: Option<String>,
    location: (LocationKind, String),
    static_kind: &'static str,
    source_sha256: Option<String>,
    label: String,
    properties: Map<String, Value>,
    section: &'static str,
}

fn target_entity(capture: &Capture, index: usize) -> Result<Entity, Defect> {
    let target = &capture.inspection.target;
    let location = located(target, true);
    let mut properties = Map::new();
    properties.insert("runtime_type".into(), target["type"].clone());
    if location.0 == LocationKind::Unresolved {
        properties.insert("reported_url".into(), json!(location.1));
        properties.insert("location_kind".into(), json!("unresolved"));
        properties.insert(
            "location_reason".into(),
            json!("unverifiable-file-location"),
        );
    } else {
        properties.insert("location".into(), json!(location.1));
    }
    properties.insert("attached".into(), target["attached"].clone());
    runtime_entity(
        capture,
        index,
        EntityInput {
            kind: "target",
            node_kind: "target",
            runtime_key: capture.target_id().to_owned(),
            target_key: capture.target_id().to_owned(),
            frame_key: None,
            script_key: None,
            location,
            static_kind: "renderer",
            source_sha256: None,
            label: str_of(&target["title"]).to_owned(),
            properties,
            section: "target",
        },
    )
}

fn frame_entity(capture: &Capture, index: usize, frame: &Value) -> Result<Entity, Defect> {
    let location = located(frame, false);
    let frame_id = str_of(&frame["frame_id"]).to_owned();
    let mut properties = Map::new();
    properties.insert("parent_frame_id".into(), frame["parent_frame_id"].clone());
    properties.insert("location".into(), json!(location.1));
    runtime_entity(
        capture,
        index,
        EntityInput {
            kind: "frame",
            node_kind: "frame",
            runtime_key: frame_id.clone(),
            target_key: capture.target_id().to_owned(),
            frame_key: Some(frame_id),
            script_key: None,
            label: location.1.clone(),
            location,
            static_kind: "renderer",
            source_sha256: None,
            properties,
            section: "frames",
        },
    )
}

fn script_entity(capture: &Capture, index: usize, script: &Value) -> Result<Entity, Defect> {
    let location = located(script, true);
    let key = str_of(&script["script_key"]).to_owned();
    let source = (script["source"]["included"] == true)
        .then(|| str_of(&script["source"]["artifact"]["sha256"]).to_owned());
    let mut properties = Map::new();
    if location.0 == LocationKind::Unresolved {
        properties.insert("location_kind".into(), json!("unresolved"));
        properties.insert(
            "reported_url".into(),
            script["unresolved_location"]["reported_url"].clone(),
        );
        properties.insert(
            "location_reason".into(),
            script["unresolved_location"]["reason"].clone(),
        );
    } else {
        properties.insert("location".into(), json!(location.1));
    }
    for field in ["cdp_hash", "length", "is_module", "language"] {
        properties.insert(
            field.into(),
            script.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    properties.insert("source_sha256".into(), json!(source));
    if let Some(url) = script.get("source_map_url") {
        properties.insert("source_map_url".into(), url.clone());
    }
    runtime_entity(
        capture,
        index,
        EntityInput {
            kind: "script",
            node_kind: "runtime-script-instance",
            runtime_key: key.clone(),
            target_key: capture.target_id().to_owned(),
            frame_key: script["frame_id"].as_str().map(str::to_owned),
            script_key: Some(key),
            label: location.1.clone(),
            location,
            static_kind: "javascript",
            source_sha256: source,
            properties,
            section: "scripts",
        },
    )
}

fn worker_entity(capture: &Capture, index: usize, worker: &Value) -> Result<Entity, Defect> {
    let location = located(worker, false);
    let service = str_of(&worker["type"]).contains("service");
    let target_id = str_of(&worker["target_id"]).to_owned();
    let mut properties = Map::new();
    properties.insert("runtime_type".into(), worker["type"].clone());
    properties.insert("location".into(), json!(location.1));
    properties.insert(
        "attached".into(),
        worker.get("attached").cloned().unwrap_or(Value::Null),
    );
    properties.insert(
        "opener_target_id".into(),
        worker["opener_target_id"].clone(),
    );
    properties.insert("parent_frame_id".into(), worker["parent_frame_id"].clone());
    runtime_entity(
        capture,
        index,
        EntityInput {
            kind: "worker",
            node_kind: if service { "service-worker" } else { "worker" },
            runtime_key: target_id.clone(),
            target_key: target_id,
            frame_key: worker["parent_frame_id"].as_str().map(str::to_owned),
            script_key: None,
            label: location.1.clone(),
            location,
            static_kind: if service { "service-worker" } else { "worker" },
            source_sha256: None,
            properties,
            section: "workers",
        },
    )
}

fn extractor(capture: &Capture) -> Value {
    let provider = &capture.evidence["provider"];
    let version = provider["version"]
        .as_str()
        .unwrap_or(if capture.kind == "browser" { "2" } else { "1" });
    json!({
        "name": provider["id"],
        "version": version,
        "operation": capture.evidence["operation"],
        "executable_sha256": null,
    })
}

fn section_count(capture: &Capture, section: &str) -> usize {
    match section {
        "frames" => capture.inspection.frames.len(),
        "scripts" => capture.inspection.scripts.len(),
        "workers" => capture.inspection.workers.len(),
        _ => 1,
    }
}

/// `runtimeSectionComplete`.
fn section_complete(capture: &Capture, section: &str) -> bool {
    match section {
        "target" => true,
        "scripts" => capture.scripts_complete_within_scope,
        _ => !capture.truncated_section(section) && !capture.unavailable_section(section),
    }
}

/// `runtimeSectionCoverage`.
fn section_coverage(capture: &Capture, section: &str) -> Value {
    if section_complete(capture, section) {
        return json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] });
    }
    let truncated = section != "target" && capture.truncated_section(section);
    let limits = if truncated {
        json!([{
            "name": format!("passive-cdp-{section}-limit"),
            "value": section_count(capture, section),
            "unit": "items",
        }])
    } else {
        json!([])
    };
    json!({ "status": "partial", "truncated": truncated, "omitted_count": null, "limits": limits })
}

fn runtime_location(
    capture: &Capture,
    target_key: &str,
    frame_key: &Option<String>,
    script_key: &Option<String>,
) -> Value {
    json!({
        "available": true,
        "value": {
            "kind": "runtime",
            "capture_sha256": capture.capture_sha256,
            "target_key": target_key,
            "frame_key": frame_key,
            "script_key": script_key,
        },
    })
}

fn runtime_entity(
    capture: &Capture,
    index: usize,
    input: EntityInput<'_>,
) -> Result<Entity, Defect> {
    let artifact = match &input.source_sha256 {
        Some(sha256) => json!({
            "available": true,
            "artifact_id": format!("art_{sha256}"),
            "sha256": sha256,
        }),
        None if input.section == "scripts" => json!({
            "available": false,
            "reason": "not-observed",
            "detail": "Script source bytes were not included in this passive capture.",
        }),
        None => json!({
            "available": false,
            "reason": "not-applicable",
            "detail": "This runtime entity has no standalone artifact bytes.",
        }),
    };
    let mut limitations = vec![json!(
        "The entity was observed only within one bounded passive CDP capture."
    )];
    if !section_complete(capture, input.section) {
        limitations.push(json!(format!(
            "The runtime {} inventory was incomplete within this capture.",
            input.section
        )));
    }
    let evidence = json!({
        "authority": "passive-cdp-runtime",
        "state": "observed",
        "confidence": "exact",
        "artifact": artifact,
        "location": runtime_location(capture, &input.target_key, &input.frame_key, &input.script_key),
        "extractor": extractor(capture),
        "coverage": section_coverage(capture, input.section),
        "limitations": limitations,
        "evidence_ids": [capture.evidence_id()],
    });
    let label = if input.label.is_empty() {
        Value::Null
    } else {
        json!(input.label)
    };
    let node = jag::create_node(
        input.node_kind,
        &json!({
            "strategy": "runtime-instance",
            "stability": "capture-only",
            "capture_sha256": capture.capture_sha256,
            "runtime_key": input.runtime_key,
        }),
        &[json!({
            "label": label,
            "properties": Value::Object(input.properties),
            "evidence": evidence,
        })],
    )?;
    Ok(Entity {
        kind: input.kind,
        section: input.section,
        node,
        capture: index,
        runtime_key: input.runtime_key,
        location: input.location,
        frame_key: input.frame_key,
        source_sha256: input.source_sha256,
        static_kind: input.static_kind,
    })
}

/// `runtimeEdges`.
fn runtime_edges(
    capture: &Capture,
    captures: &[Capture],
    entities: &[Entity],
) -> Result<Vec<Value>, Defect> {
    let local: Vec<&Entity> = entities
        .iter()
        .filter(|entity| captures[entity.capture].evidence_id() == capture.evidence_id())
        .collect();
    let Some(target) = local.iter().position(|entity| entity.kind == "target") else {
        return Ok(Vec::new());
    };
    let mut frames: HashMap<&str, &Entity> = HashMap::new();
    for entity in local.iter().filter(|entity| entity.kind == "frame") {
        frames.insert(entity.runtime_key.as_str(), entity);
    }
    let mut edges = Vec::new();
    for (position, entity) in local.iter().enumerate() {
        if position == target {
            continue;
        }
        let parent = match (&entity.frame_key, entity.kind) {
            (Some(frame), "script" | "worker") => {
                frames.get(frame.as_str()).copied().unwrap_or(local[target])
            }
            _ => local[target],
        };
        let evidence = json!({
            "authority": "passive-cdp-runtime",
            "state": "observed",
            "confidence": "exact",
            "artifact": {
                "available": false,
                "reason": "not-applicable",
                "detail": "The relationship is runtime metadata, not standalone bytes.",
            },
            "location": runtime_location(
                capture,
                capture.target_id(),
                &entity.frame_key,
                &(entity.kind == "script").then(|| entity.runtime_key.clone()),
            ),
            "extractor": extractor(capture),
            "coverage": section_coverage(capture, entity.section),
            "limitations": ["The relationship was observed only within one bounded passive CDP capture."],
            "evidence_ids": [capture.evidence_id()],
        });
        edges.push(jag::create_edge(
            parent.node_id(),
            entity.node_id(),
            if entity.kind == "script" {
                "loads"
            } else {
                "contains"
            },
            json!({ "basis": "passive-cdp-observation" }),
            &evidence,
        )?);
    }
    Ok(edges)
}
