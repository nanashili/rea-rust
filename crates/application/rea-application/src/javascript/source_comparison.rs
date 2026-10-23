//! Deterministic historical JavaScript source to shipped-bundle comparison.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const OPERATION: &str = "compare_source_to_bundle";
const WEIGHTS: [(&str, i64); 7] = [
    ("exact-source-digest", 100),
    ("source-map-original-path", 70),
    ("current-path-exact", 60),
    ("current-path-suffix", 40),
    ("unicode-equivalent-path", 20),
    ("basename-match", 20),
    ("language-extension", 5),
];

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("source-to-bundle input must be an object"))?;
    let reference = object
        .get("reference")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("reference source graph is required"))?;
    let application = object
        .get("application")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("application Evidence is required"))?;
    if reference
        .get("root_sha256")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("reference.root_sha256 is required"));
    }
    if application
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("application Evidence must include evidence_id"));
    }
    let normalized = application
        .get("normalized_result")
        .or_else(|| application.get("result"));
    let root_artifact = normalized
        .map(|value| value.get("graph").unwrap_or(value))
        .and_then(|value| value.get("root_artifact_sha256"))
        .or_else(|| application.get("root_artifact_sha256"));
    if root_artifact
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid(
            "application Evidence must include root_artifact_sha256",
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct Source {
    path: String,
    digest: Option<String>,
    language: Option<String>,
    limitations: Vec<String>,
}
#[derive(Clone)]
struct Node {
    id: String,
    kind: String,
    digests: Vec<String>,
    paths: Vec<PathFact>,
}

#[derive(Clone)]
struct PathFact {
    value: String,
    source_map_original: bool,
    allow_suffix: bool,
}

/// Produce bounded, deterministic source-to-bundle mappings from trusted graph inputs.
pub fn compare(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let reference = &input["reference"];
    let application = &input["application"];
    let graph0 = application
        .get("normalized_result")
        .or_else(|| application.get("result"))
        .unwrap_or(application);
    let graph = graph0.get("graph").unwrap_or(graph0);
    let sources = sources(reference);
    let nodes = nodes(graph);
    let complete =
        reference["inventory_state"] == "complete" && absence_claimable(graph.get("coverage"));
    let mut items = Vec::new();
    let mut mapped = HashSet::new();
    for source in &sources {
        let mut candidates = nodes
            .iter()
            .filter_map(|node| score(source, node))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right["score"].as_i64().cmp(&left["score"].as_i64()).then(
                left["current_node_id"]
                    .as_str()
                    .cmp(&right["current_node_id"].as_str()),
            )
        });
        let (status, confidence, ids, mut limitations) = classify(source, &candidates, complete);
        for candidate in &mut candidates {
            if let Some(object) = candidate.as_object_mut() {
                object.remove("digest_available");
            }
        }
        mapped.extend(ids.iter().cloned());
        limitations.extend(source.limitations.clone());
        limitations.sort();
        limitations.dedup();
        let semantic = json!({"source_path":source.path,"source_sha256":source.digest,"source_language":source.language,"status":status,"confidence":confidence,"current_node_ids":ids,"candidates":candidates,"limitations":limitations});
        let id = rea_core::canonical_json::digest(&json!({"reference_root_sha256":reference["root_sha256"],"application_graph_id":graph["graph_id"],"item":semantic})).map_err(|error| invalid(&error.to_string()))?;
        let mut item = semantic.as_object().cloned().unwrap_or_default();
        item.insert("mapping_id".into(), json!(format!("stbc_item_{id}")));
        items.push(Value::Object(item));
    }
    mark_merged(&mut items);
    let mut summary = BTreeMap::new();
    for status in [
        "unchanged",
        "modified",
        "removed",
        "split",
        "merged",
        "duplicated",
        "unknown",
    ] {
        summary.insert(
            status,
            items.iter().filter(|item| item["status"] == status).count(),
        );
    }
    let root_artifact_sha256 = graph
        .get("root_artifact_sha256")
        .cloned()
        .or_else(|| application.get("root_artifact_sha256").cloned())
        .unwrap_or(Value::Null);
    let result = json!({"reference":{"root_sha256":reference["root_sha256"],"inventory_state":reference.get("inventory_state").cloned().unwrap_or(json!("unknown"))},"application":{"evidence_id":application["evidence_id"],"graph_id":graph["graph_id"],"root_artifact_sha256":root_artifact_sha256},"scoring":{"algorithm":"rea-source-to-bundle-signals","minimum_candidate_score":20,"weights":WEIGHTS.iter().map(|(signal,weight)|json!({"signal":signal,"weight":weight})).collect::<Vec<_>>()},"summary":summary,"items":items,"unmapped_current_node_ids":nodes.iter().map(|node|node.id.clone()).filter(|id|!mapped.contains(id)).collect::<Vec<_>>(),"coverage":{"status":if complete{"complete-within-inputs"}else{"partial"},"reference_inventory_state":reference["inventory_state"],"application_graph_status":graph["coverage"]["status"],"retained_source_files":sources.len(),"retained_application_nodes":nodes.len(),"candidate_evaluations":sources.iter().map(|source|nodes.iter().filter(|node|score(source,node).is_some()).count()).sum::<usize>()},"evidence_links":[application["evidence_id"]],"limitations":limitations(reference,graph)});
    let digest =
        rea_core::canonical_json::digest(&result).map_err(|error| invalid(&error.to_string()))?;
    let mut output = result.as_object().cloned().unwrap_or_default();
    output.insert("comparison_id".into(), json!(format!("stbc_{digest}")));
    Ok(Value::Object(output))
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("source-to-bundle result must be an object"));
    }
    Ok(result)
}

fn sources(reference: &Value) -> Vec<Source> {
    let mut output: Vec<Source> = reference["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let classifications = entry["classifications"].as_array()?;
            if entry["kind"] != "file" || !classifications.iter().any(|value| value == "source") {
                return None;
            }
            Some(Source {
                path: entry["path"].as_str()?.into(),
                digest: entry["sha256"].as_str().map(str::to_owned),
                language: entry["language"].as_str().map(str::to_owned),
                limitations: entry["limitations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            })
        })
        .collect();
    output.sort_by(|a, b| a.path.cmp(&b.path));
    output
}

fn nodes(graph: &Value) -> Vec<Node> {
    let mut output: Vec<Node> = graph["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let kind = entry["kind"].as_str()?;
            if ![
                "artifact",
                "javascript-asset",
                "javascript-module",
                "source-module",
            ]
            .contains(&kind)
            {
                return None;
            }
            let mut digests = Vec::new();
            let mut paths = Vec::new();
            let identity = &entry["identity"];
            let strategy = identity["strategy"].as_str().unwrap_or("");
            if strategy == "content-digest" {
                if let Some(value) = identity["sha256"].as_str() {
                    digests.push(value.into());
                }
            } else if strategy == "source-map-original" {
                if let Some(value) = identity["source_sha256"].as_str() {
                    digests.push(value.into());
                }
            } else if strategy == "canonical-path" {
                if let Some(value) = identity["path"].as_str() {
                    paths.push(PathFact {
                        value: value.into(),
                        source_map_original: false,
                        allow_suffix: true,
                    });
                }
            }
            for observation in entry["observations"].as_array().into_iter().flatten() {
                if strategy == "source-map-original" {
                    if let Some(value) =
                        observation["source_map_reference"]["resolution"]["path"].as_str()
                    {
                        let allow_suffix =
                            observation["source_map_reference"]["resolution"]["kind"] == "suffix";
                        paths.push(PathFact {
                            value: value.into(),
                            source_map_original: true,
                            allow_suffix,
                        });
                    }
                    continue;
                }
                if let Some(value) = observation["properties"]["source_sha256"].as_str() {
                    digests.push(value.into());
                }
                for key in [
                    "path",
                    "source",
                    "original_source",
                    "module_path",
                    "resolved_path",
                    "declared_path",
                ] {
                    if key == "declared_path"
                        && observation["properties"].get("resolved_path").is_some()
                    {
                        continue;
                    }
                    if let Some(value) = observation["properties"][key].as_str() {
                        paths.push(PathFact {
                            value: value.into(),
                            source_map_original: false,
                            allow_suffix: true,
                        });
                    }
                }
            }
            Some(Node {
                id: entry["node_id"].as_str()?.into(),
                kind: kind.into(),
                digests,
                paths,
            })
        })
        .collect();
    output.sort_by(|a, b| a.id.cmp(&b.id));
    output
}

fn score(source: &Source, node: &Node) -> Option<Value> {
    let mut signals = Vec::new();
    if let Some(digest) = &source.digest {
        if node.digests.iter().any(|value| value == digest) {
            signals.push(signal("exact-source-digest", digest, vec![digest.clone()]));
        }
    }
    let source_map_paths = node
        .paths
        .iter()
        .filter(|path| path.source_map_original && path_matches(source, path))
        .map(|path| path.value.clone())
        .collect::<Vec<_>>();
    if !source_map_paths.is_empty() {
        signals.push(signal(
            "source-map-original-path",
            &source.path,
            source_map_paths,
        ));
    }
    let unicode_paths = node
        .paths
        .iter()
        .filter(|path| !path.source_map_original && unicode_path_matches(&source.path, path))
        .map(|path| path.value.clone())
        .collect::<Vec<_>>();
    if !unicode_paths.is_empty() {
        signals.push(signal(
            "unicode-equivalent-path",
            &source.path,
            unicode_paths,
        ));
    }
    let exact = node
        .paths
        .iter()
        .filter(|path| !path.source_map_original && path.value == source.path)
        .map(|path| path.value.clone())
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        signals.push(signal("current-path-exact", &source.path, exact));
    }
    let suffix = node
        .paths
        .iter()
        .filter(|path| {
            !path.source_map_original
                && path.allow_suffix
                && path.value != source.path
                && path
                    .value
                    .ends_with(&format!("/{path}", path = source.path))
        })
        .map(|path| path.value.clone())
        .collect::<Vec<_>>();
    if !suffix.is_empty() {
        signals.push(signal("current-path-suffix", &source.path, suffix));
    }
    let basename = source.path.rsplit('/').next().unwrap_or(&source.path);
    let names = node
        .paths
        .iter()
        .filter(|path| path.value.rsplit('/').next().unwrap_or(&path.value) == basename)
        .map(|path| path.value.clone())
        .collect::<Vec<_>>();
    if !names.is_empty() {
        signals.push(signal("basename-match", basename, names));
    }
    let extension = source
        .path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let extensions = node
        .paths
        .iter()
        .filter(|path| {
            path.value
                .rsplit('.')
                .next()
                .unwrap_or("")
                .eq_ignore_ascii_case(&extension)
                && !extension.is_empty()
        })
        .map(|path| path.value.clone())
        .collect::<Vec<_>>();
    if !extensions.is_empty() {
        signals.push(signal("language-extension", &extension, extensions));
    }
    let total = signals
        .iter()
        .map(|value| value["weight"].as_i64().unwrap_or(0))
        .sum::<i64>();
    if total < 20 {
        return None;
    }
    let confidence = if signals
        .iter()
        .any(|value| value["kind"] == "exact-source-digest")
    {
        "exact"
    } else if signals
        .iter()
        .any(|value| value["kind"] == "source-map-original-path")
        || signals
            .iter()
            .any(|value| value["kind"] == "current-path-exact")
    {
        "high"
    } else if signals
        .iter()
        .any(|value| value["kind"] == "current-path-suffix")
    {
        "medium"
    } else {
        "low"
    };
    Some(
        json!({"current_node_id":node.id,"current_node_kind":node.kind,"score":total,"confidence":confidence,"signals":signals,"digest_available":!node.digests.is_empty()}),
    )
}

fn absence_claimable(coverage: Option<&Value>) -> bool {
    coverage
        .filter(|value| value["status"] == "complete")
        .is_some_and(|value| {
            value["truncated"] != true
                && value
                    .get("omitted_count")
                    .is_none_or(|omitted| omitted == 0)
        })
}

fn path_matches(source: &Source, path: &PathFact) -> bool {
    path.value == source.path
        || (path.allow_suffix
            && path
                .value
                .ends_with(&format!("/{path}", path = source.path)))
}

fn unicode_path_matches(source: &str, path: &PathFact) -> bool {
    if path.value == source || (path.allow_suffix && path.value.ends_with(&format!("/{source}"))) {
        return false;
    }
    let source_nfc = canonical_unicode_path(source);
    let path_nfc = canonical_unicode_path(&path.value);
    path_nfc == source_nfc || (path.allow_suffix && path_nfc.ends_with(&format!("/{source_nfc}")))
}

/// Canonicalize the common decomposed Latin spellings used by filesystem and
/// source-map producers without changing any caller-visible path value.
/// Unsupported combining sequences remain distinct and therefore unresolved.
fn canonical_unicode_path(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        let composed = match (character, chars.peek().copied()) {
            ('e', Some('\u{301}')) => Some('é'),
            ('E', Some('\u{301}')) => Some('É'),
            ('a', Some('\u{301}')) => Some('á'),
            ('A', Some('\u{301}')) => Some('Á'),
            ('i', Some('\u{301}')) => Some('í'),
            ('I', Some('\u{301}')) => Some('Í'),
            ('o', Some('\u{301}')) => Some('ó'),
            ('O', Some('\u{301}')) => Some('Ó'),
            ('u', Some('\u{301}')) => Some('ú'),
            ('U', Some('\u{301}')) => Some('Ú'),
            ('n', Some('\u{303}')) => Some('ñ'),
            ('N', Some('\u{303}')) => Some('Ñ'),
            _ => None,
        };
        if let Some(composed) = composed {
            output.push(composed);
            chars.next();
        } else {
            output.push(character);
        }
    }
    output
}
fn signal(kind: &str, source: &str, mut values: Vec<String>) -> Value {
    values.sort();
    values.dedup();
    json!({"kind":kind,"weight":WEIGHTS.iter().find(|(name,_)|*name==kind).map(|(_,weight)|*weight).unwrap_or(0),"source_value":source,"current_values":values})
}
fn classify(
    source: &Source,
    candidates: &[Value],
    complete: bool,
) -> (&'static str, &'static str, Vec<String>, Vec<String>) {
    let exact = candidates
        .iter()
        .filter(|candidate| {
            candidate["signals"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|signal| signal["kind"] == "exact-source-digest")
        })
        .collect::<Vec<_>>();
    if exact.len() == 1 {
        return("unchanged","exact",vec![exact[0]["current_node_id"].as_str().unwrap_or_default().into()],vec!["Exact byte identity does not establish equivalent load context or runtime behavior.".into()]);
    }
    if exact.len() > 1 {
        return (
            "duplicated",
            "exact",
            exact
                .iter()
                .filter_map(|candidate| candidate["current_node_id"].as_str().map(str::to_owned))
                .collect(),
            vec![
                "The same historical source digest occurs in multiple current graph nodes.".into(),
            ],
        );
    }
    let paths = candidates
        .iter()
        .filter(|candidate| {
            candidate["signals"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|signal| {
                    [
                        "source-map-original-path",
                        "current-path-exact",
                        "current-path-suffix",
                    ]
                    .contains(&signal["kind"].as_str().unwrap_or(""))
                })
        })
        .collect::<Vec<_>>();
    if let Some(top) = paths
        .first()
        .and_then(|candidate| candidate["score"].as_i64())
    {
        let tied = paths
            .iter()
            .filter(|candidate| candidate["score"].as_i64() == Some(top))
            .collect::<Vec<_>>();
        if tied.len() == 1 {
            let candidate = tied[0];
            let comparable = candidate["digest_available"] == true;
            let modified = source.digest.is_some() && comparable;
            let confidence = if modified {
                if candidate["confidence"] == "high" {
                    "high"
                } else {
                    "medium"
                }
            } else {
                "unknown"
            };
            return (
                if modified { "modified" } else { "unknown" },
                confidence,
                vec![
                    candidate["current_node_id"]
                        .as_str()
                        .unwrap_or_default()
                        .into(),
                ],
                vec![if modified {
                    "Location evidence links the source to the current node, but their source digests differ.".into()
                } else {
                    "Location evidence links the source to the current node, but comparable source digests are unavailable.".into()
                }],
            );
        }
        return("split","medium",tied.iter().filter_map(|candidate|candidate["current_node_id"].as_str().map(str::to_owned)).collect(),vec!["Multiple equally scored current nodes retain the historical source path; this is a static split inference, not runtime proof.".into()]);
    }
    if !candidates.is_empty() {
        return (
            "unknown",
            "unknown",
            Vec::new(),
            vec![if candidates.iter().any(|candidate| {
                candidate["signals"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|signal| signal["kind"] == "unicode-equivalent-path")
            }) {
                "Unicode-equivalent paths are inferred candidates only; filesystem paths with distinct Unicode spellings may identify different files, so no mapping was forced.".into()
            } else {
                "Only weak basename or extension signals were available; no mapping was forced."
                    .into()
            }],
        );
    }
    if complete {
        ("removed","high",Vec::new(),vec!["No retained current node matched exact digest or path signals within complete static inventories.".into()])
    } else {
        ("unknown","unknown",Vec::new(),vec!["No candidate was observed, but incomplete input or graph coverage prevents a removal claim.".into()])
    }
}
fn mark_merged(items: &mut [Value]) {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, item) in items.iter().enumerate() {
        if item["status"] == "unchanged"
            && item["current_node_ids"].as_array().map(Vec::len) == Some(1)
        {
            if let Some(id) = item["current_node_ids"][0].as_str() {
                groups.entry(id.into()).or_default().push(index);
            }
        }
    }
    for indexes in groups.values().filter(|indexes| indexes.len() > 1) {
        for index in indexes {
            items[*index]["status"] = json!("merged");
        }
    }
}
fn limitations(reference: &Value, graph: &Value) -> Vec<String> {
    let mut output=vec!["Static digest and location signals do not establish runtime behavior, semantic equivalence, or absence of dynamically generated modules.".into()];
    for value in [reference.get("limitations"), graph.get("limitations")]
        .into_iter()
        .flatten()
        .flat_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_str)
    {
        output.push(value.into());
    }
    if reference["inventory_state"] != "complete" {
        output.push(format!(
            "Historical source inventory is {}; unmatched files remain unknown.",
            reference["inventory_state"].as_str().unwrap_or("unknown")
        ));
    }
    if graph["coverage"]["status"] != "complete" || graph["coverage"]["truncated"] == true {
        output.push(format!(
            "Application graph coverage is {}; unmatched files remain unknown.",
            graph["coverage"]["status"].as_str().unwrap_or("unknown")
        ));
    }
    output.sort();
    output.dedup();
    output
}
fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a historical source graph and authenticated application Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(path: &str, digest: Option<&str>, nodes: Value, state: &str) -> Value {
        json!({"reference":{"root_sha256":"a".repeat(64),"inventory_state":state,"entries":[{"kind":"file","path":path,"classifications":["source"],"language":"typescript","sha256":digest,"limitations":[]}]},"application":{"evidence_id":"ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","normalized_result":{"graph_id":"jag_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","root_artifact_sha256":"b".repeat(64),"nodes":nodes,"coverage":{"status":"complete"},"limitations":[]}}})
    }
    #[test]
    fn matches_exact_digest() {
        let digest = "c".repeat(64);
        let result=compare(&input("src/main.ts",Some(&digest),json!([{"node_id":"jag_node_1","kind":"javascript-module","identity":{"sha256":digest},"observations":[{"properties":{}}]}]),"complete")).unwrap();
        assert_eq!(result["items"][0]["status"], "unchanged");
    }
    #[test]
    fn missing_source_is_removed_when_complete() {
        let result = compare(&input(
            "src/missing.ts",
            Some(&"c".repeat(64)),
            json!([]),
            "complete",
        ))
        .unwrap();
        assert_eq!(result["items"][0]["status"], "removed");
    }
    #[test]
    fn ambiguous_paths_are_split() {
        let nodes = json!([{"node_id":"jag_node_a","kind":"source-module","identity":{"path":"one/src/main.ts"},"observations":[{"properties":{}}]},{"node_id":"jag_node_b","kind":"source-module","identity":{"path":"two/src/main.ts"},"observations":[{"properties":{}}]}]);
        let result = compare(&input("src/main.ts", None, nodes, "complete")).unwrap();
        assert_eq!(result["items"][0]["status"], "split");
    }
}
