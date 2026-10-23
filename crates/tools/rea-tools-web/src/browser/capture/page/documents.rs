//! Document projections of `src/browser/CdpCaptureDocuments.ts`:
//! `captureResources`, `captureDom` (with bounded SVG identity batches) and
//! `captureAccessibility`. Frames reuse `values::capture_frames`.
use super::super::completeness::Completeness;
use super::super::values::{self, Record};
use super::events::records;
use super::snapshot::{self, Attributes, SvgLink, SvgQuery};
use crate::cdp::json_text::{canonical_json, utf16_length};
use crate::cdp::urls;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// `DOM_METADATA_BATCH_SIZE`.
const BATCH: usize = 8;

/// `CapturedResource` (public facts plus the raw URL).
#[derive(Clone)]
pub(super) struct Resource {
    pub raw_url: String,
    pub public: Value,
}

/// `captureResources`.
pub(super) fn capture_resources(
    result: &Value,
    origins: &BTreeSet<String>,
    completeness: &mut Completeness,
) -> Vec<Resource> {
    let Some(root) = values::frame_tree_root(result) else {
        completeness.exclude("resources", "invalid_protocol_value");
        return Vec::new();
    };
    let mut invalid: Vec<Option<u64>> = Vec::new();
    let trees = values::walk_frame_trees(root, &mut |count| invalid.push(count));
    let mut items = Vec::new();
    for tree in trees {
        let Some(entries) = tree.get("resources").and_then(Value::as_array) else {
            invalid.push(None);
            continue;
        };
        for entry in entries {
            let Some(resource) = entry.as_object() else {
                invalid.push(Some(1));
                continue;
            };
            let raw_url = values::string(resource.get("url"));
            let Some(urls::SanitizedUrl {
                url,
                origin: Some(origin),
            }) = values::allowed_sanitized_url(raw_url, origins)
            else {
                completeness.exclude("resources", values::exclusion_reason_for_url(raw_url));
                continue;
            };
            let kind = values::string(resource.get("type")).filter(|kind| !kind.is_empty());
            let mime = values::string(resource.get("mimeType"));
            let (Some(kind), Some(mime)) = (kind, mime) else {
                completeness.exclude("resources", "invalid_protocol_value");
                continue;
            };
            let size = match resource.get("contentSize") {
                None => Ok(Value::Null),
                Some(value) => values::number(Some(value))
                    .filter(|size| *size >= 0.0)
                    .map(values::js_number)
                    .ok_or(()),
            };
            if size.is_err() {
                completeness.exclude("resources", "invalid_protocol_value");
            }
            items.push(Resource {
                raw_url: raw_url.unwrap_or("").to_owned(),
                public: json!({
                    "url": url,
                    "origin": origin,
                    "type": kind,
                    "mime_type": mime,
                    "content_size": size.unwrap_or(Value::Null),
                }),
            });
        }
    }
    for count in invalid {
        completeness.exclude_count("resources", "invalid_protocol_value", count);
    }
    items
}

/// `res_` + sha256 of the canonical public resource.
pub(super) fn resource_key(public: &Value) -> String {
    format!(
        "res_{}",
        hex(&Sha256::digest(canonical_json(public).as_bytes()))
    )
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `stableWebResources`: keyed, deduplicated by key (last wins, first
/// position), sorted by key then URL.
pub(super) fn stable_resources(resources: &[Resource]) -> Vec<Value> {
    let mut keyed: Vec<(String, Value)> = Vec::new();
    let mut positions: BTreeMap<String, usize> = BTreeMap::new();
    for resource in resources {
        let key = resource_key(&resource.public);
        let mut item = resource.public.clone();
        item["resource_key"] = json!(key);
        match positions.get(&key) {
            Some(&position) => keyed[position].1 = item,
            None => {
                positions.insert(key.clone(), keyed.len());
                keyed.push((key, item));
            }
        }
    }
    keyed.sort_by(|left, right| {
        left.0.cmp(&right.0).then_with(|| {
            left.1["url"]
                .as_str()
                .unwrap_or("")
                .cmp(right.1["url"].as_str().unwrap_or(""))
        })
    });
    keyed.into_iter().map(|(_, item)| item).collect()
}

/// `DomCapture`.
pub(super) struct DomCapture {
    pub total: usize,
    pub nodes: Vec<Value>,
    pub urls: Vec<Value>,
    pub agent_hints: Vec<Value>,
    pub excluded_urls: u64,
    pub unresolved_svg_nodes: u64,
}

struct Pending {
    attributes: Attributes,
    base_url: String,
    document_url: String,
    node_index: usize,
    node_name: String,
    link: SvgLink,
    /// `None`: no query needed; `Some(None)`: candidate without a valid ID.
    query: Option<Option<SvgQuery>>,
}

fn exclude_document(completeness: &mut Completeness, reason: &'static str, count: Option<u64>) {
    completeness.exclude_count("dom", reason, count);
    completeness.exclude_count("metadata", reason, count);
}

/// SVG identity lookups for one bounded batch, in query order.
pub(super) type Describe<'a> =
    dyn FnMut(&[SvgQuery]) -> Result<Vec<Option<bool>>, AnalysisError> + 'a;

/// `captureDom`.
pub(super) fn capture_dom(
    result: &Value,
    origins: &BTreeSet<String>,
    completeness: &mut Completeness,
    describe: &mut Describe<'_>,
) -> Result<DomCapture, AnalysisError> {
    let root = result
        .as_object()
        .ok_or_else(|| super::super::connection::foreign(super::OPERATION, "protocol_error"))?;
    let strings: Vec<Option<String>> = root
        .get("strings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut capture = DomCapture {
        total: 0,
        nodes: Vec::new(),
        urls: Vec::new(),
        agent_hints: Vec::new(),
        excluded_urls: 0,
        unresolved_svg_nodes: 0,
    };
    if !root.get("strings").is_some_and(Value::is_array) {
        exclude_document(completeness, "invalid_protocol_value", None);
    }
    // `snapshotDocuments`.
    let documents: Vec<&Record> = match root.get("documents").and_then(Value::as_array) {
        Some(items) if !items.is_empty() => items
            .iter()
            .filter_map(|item| {
                let document = item.as_object();
                if document.is_none() {
                    exclude_document(completeness, "invalid_protocol_value", Some(1));
                }
                document
            })
            .collect(),
        _ => {
            exclude_document(completeness, "invalid_protocol_value", None);
            Vec::new()
        }
    };
    for document in documents {
        let Some(document_url) = document
            .get("documentURL")
            .and_then(|index| snapshot::snapshot_string(&strings, index))
        else {
            exclude_document(completeness, "invalid_protocol_value", Some(1));
            continue;
        };
        if values::allowed_sanitized_url(Some(document_url), origins).is_none() {
            exclude_document(
                completeness,
                values::exclusion_reason_for_url(Some(document_url)),
                Some(1),
            );
            continue;
        }
        let base_value = match document.get("baseURL") {
            None => Some(document_url),
            Some(index) => snapshot::snapshot_value_string(&strings, index),
        };
        let Some(base_value) = base_value else {
            exclude_document(completeness, "invalid_protocol_value", Some(1));
            continue;
        };
        let base_url = if base_value.is_empty() {
            document_url
        } else {
            base_value
        };
        let Some(nodes) = snapshot::document_nodes(document.get("nodes"), &strings) else {
            exclude_document(completeness, "invalid_protocol_value", Some(1));
            continue;
        };
        if nodes.excess_attributes > 0 {
            exclude_document(
                completeness,
                "invalid_protocol_value",
                Some(nodes.excess_attributes as u64),
            );
        }
        let base_index = capture.total;
        let count = nodes.node_types.len();
        capture.total += count;
        let ancestry = snapshot::ancestry(&nodes);
        let mut pending: Vec<Pending> = Vec::new();
        for index in 0..count {
            let Some(row) = snapshot::node_at(&nodes, index) else {
                exclude_document(completeness, "invalid_protocol_value", Some(1));
                continue;
            };
            let node_index = base_index + index;
            let mut names: Vec<&str> = Vec::new();
            for (name, _) in row.attributes {
                if !names.contains(&name.as_str()) {
                    names.push(name);
                }
            }
            let link = snapshot::svg_link(&ancestry, index);
            if link.xml_document.is_none() {
                completeness.exclude("metadata", "invalid_protocol_value");
            }
            let query = (link.xml_document == Some(false)
                && row.node_type == 1
                && names.contains(&"xlink:href")
                && !names.contains(&"href"))
            .then(|| {
                nodes
                    .backend_node_ids
                    .get(index)
                    .copied()
                    .flatten()
                    .map(|backend_node_id| SvgQuery {
                        backend_node_id,
                        node_name: row.node_name.to_owned(),
                    })
            });
            capture.nodes.push(json!({
                "index": node_index,
                "parent_index": if row.parent < 0 { -1 } else { base_index as i64 + row.parent },
                "node_type": row.node_type,
                "node_name": row.node_name,
                "node_value_length": utf16_length(row.node_value),
                "attribute_names": names,
            }));
            pending.push(Pending {
                attributes: row.attributes.clone(),
                base_url: if row.node_name.to_lowercase() == "base" {
                    document_url
                } else {
                    base_url
                }
                .to_owned(),
                document_url: document_url.to_owned(),
                node_index,
                node_name: row.node_name.to_owned(),
                link,
                query,
            });
            if pending.len() == BATCH || index == count - 1 {
                flush(&mut pending, origins, completeness, describe, &mut capture)?;
            }
        }
        if !pending.is_empty() {
            flush(&mut pending, origins, completeness, describe, &mut capture)?;
        }
    }
    Ok(capture)
}

/// `captureDomMetadata`.
fn flush(
    pending: &mut Vec<Pending>,
    origins: &BTreeSet<String>,
    completeness: &mut Completeness,
    describe: &mut Describe<'_>,
    capture: &mut DomCapture,
) -> Result<(), AnalysisError> {
    let queries: Vec<SvgQuery> = pending
        .iter()
        .filter_map(|item| item.query.clone().flatten())
        .collect();
    let kinds = if queries.is_empty() {
        Vec::new()
    } else {
        describe(&queries)?
    };
    let mut cursor = 0;
    for item in pending.drain(..) {
        let mut svg_element = item.link.svg_element;
        if let Some(query) = &item.query {
            let kind = match query {
                None => None,
                Some(_) => {
                    let kind = kinds.get(cursor).copied().flatten();
                    cursor += 1;
                    kind
                }
            };
            svg_element = kind == Some(true);
            if kind.is_none() {
                capture.unresolved_svg_nodes += 1;
                completeness.exclude("metadata", "provider_unavailable");
            }
        }
        let (urls, hints) = dom_metadata(&item, svg_element, origins);
        for url in urls {
            let scope = url["destination_scope"].as_str().unwrap_or("");
            if scope != "approved" {
                capture.excluded_urls += 1;
                completeness.exclude(
                    "metadata",
                    if scope == "outside_policy" {
                        "disallowed_origin"
                    } else {
                        "unsupported_url"
                    },
                );
            }
            capture.urls.push(url);
        }
        capture.agent_hints.extend(hints);
    }
    Ok(())
}

const DOM_URL_ATTRIBUTES: [&str; 5] = ["href", "src", "action", "formaction", "poster"];
const AGENT_RELS: [&str; 4] = ["mcp", "model-context", "ai-plugin", "service-desc"];

fn is_html_space(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\u{c}' | '\r' | ' ')
}

/// `domMetadata`.
fn dom_metadata(
    item: &Pending,
    svg_element: bool,
    origins: &BTreeSet<String>,
) -> (Vec<Value>, Vec<Value>) {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for (name, value) in &item.attributes {
        if !pairs.iter().any(|(existing, _)| existing == name) {
            pairs.push((name, value));
        }
    }
    let get = |name: &str| {
        pairs
            .iter()
            .find(|(existing, _)| *existing == name)
            .map(|(_, value)| *value)
    };
    let tag = item.node_name.to_lowercase();
    let mut urls = Vec::new();
    for attribute in DOM_URL_ATTRIBUTES {
        let value = match get(attribute) {
            Some(value) => Some(value),
            None if attribute == "href" && svg_element => {
                if item.link.xml_document == Some(true) {
                    item.link.xlink_href.as_deref()
                } else {
                    get("xlink:href")
                }
            }
            None => None,
        };
        let Some(value) = value else {
            continue;
        };
        let uses_document =
            (tag == "form" && attribute == "action" && value.chars().all(is_html_space))
                || ((tag == "button" || tag == "input")
                    && attribute == "formaction"
                    && value.is_empty());
        let (url, scope) = dom_destination(
            if uses_document {
                &item.document_url
            } else {
                value
            },
            &item.base_url,
            origins,
        );
        urls.push(json!({
            "node_index": item.node_index,
            "attribute": attribute,
            "url": url,
            "destination_scope": scope,
        }));
    }
    let rel_text = get("rel").unwrap_or("").to_lowercase();
    let rels: Vec<&str> = rel_text
        .split(is_html_space)
        .filter(|value| AGENT_RELS.contains(value))
        .collect();
    let href = urls
        .iter()
        .find(|url| url["attribute"] == "href")
        .and_then(|url| url["url"].as_str().map(str::to_owned));
    let hints = if tag == "link" && !rels.is_empty() {
        rels.into_iter()
            .map(|declaration| {
                json!({
                    "mechanism": "dom_link_rel",
                    "declaration": declaration,
                    "url": href,
                    "trust": "page-declared-untrusted",
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    (urls, hints)
}

fn dom_destination(
    value: &str,
    base: &str,
    origins: &BTreeSet<String>,
) -> (Option<String>, &'static str) {
    let Some(parsed) = urls::parse_with_base(value, base) else {
        return (None, "unsupported");
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return (None, "unsupported");
    }
    if !origins.contains(&urls::origin(&parsed)) {
        return (None, "outside_policy");
    }
    (
        values::allowed_sanitized_url(Some(parsed.as_str()), origins).map(|url| url.url),
        "approved",
    )
}

const STATE_NAMES: [&str; 24] = [
    "atomic",
    "autocomplete",
    "busy",
    "checked",
    "disabled",
    "editable",
    "expanded",
    "focusable",
    "focused",
    "hasPopup",
    "hidden",
    "invalid",
    "level",
    "live",
    "modal",
    "multiline",
    "multiselectable",
    "orientation",
    "pressed",
    "readonly",
    "required",
    "selected",
    "valuemax",
    "valuemin",
];

/// `captureAccessibility`.
pub(super) struct Accessibility {
    pub total: usize,
    pub nodes: Vec<Value>,
    pub text_capture: Value,
    pub excluded_fields: u64,
    pub has_unobserved_children: bool,
}

fn non_empty_string(value: Option<&Value>) -> Option<&str> {
    values::string(value).filter(|text| !text.is_empty())
}

pub(super) fn capture_accessibility(
    results: &[Value],
    include_text: bool,
    unavailable: bool,
    completeness: &mut Completeness,
) -> Accessibility {
    let mut all: Vec<&Record> = Vec::new();
    for result in results {
        let Some(inventory) = result.get("nodes").and_then(Value::as_array) else {
            completeness.exclude_count("accessibility", "invalid_protocol_value", None);
            continue;
        };
        let mut malformed = 0_u64;
        for entry in inventory {
            let Some(node) = entry.as_object() else {
                malformed += 1;
                continue;
            };
            if non_empty_string(node.get("nodeId")).is_none()
                || !node.get("ignored").is_some_and(Value::is_boolean)
            {
                malformed += 1;
                continue;
            }
            if node.contains_key("parentId") && non_empty_string(node.get("parentId")).is_none() {
                malformed += 1;
            }
            if let Some(children) = node.get("childIds") {
                let valid = children
                    .as_array()
                    .is_some_and(|ids| ids.iter().all(|id| non_empty_string(Some(id)).is_some()));
                if !valid {
                    malformed += 1;
                }
            }
            all.push(node);
        }
        if malformed > 0 {
            completeness.exclude_count("accessibility", "invalid_protocol_value", Some(malformed));
        }
    }
    let ids: HashSet<&str> = all
        .iter()
        .filter_map(|node| values::string(node.get("nodeId")))
        .collect();
    let mut excluded = 0_u64;
    let mut retained = 0_usize;
    let mut capture_text = |value: Option<&Value>| -> Option<String> {
        let raw = values::string(values::record(value).and_then(|value| value.get("value")))?;
        if !include_text {
            excluded += 1;
            return None;
        }
        retained += raw.len();
        Some(raw.to_owned())
    };
    let nodes: Vec<Value> = all
        .iter()
        .map(|node| {
            let name = capture_text(node.get("name"));
            let description = capture_text(node.get("description"));
            json!({
                "node_id": values::string(node.get("nodeId")).unwrap_or(""),
                "parent_id": values::string(node.get("parentId")),
                "role": values::string(values::record(node.get("role")).and_then(|role| role.get("value"))),
                "name": name,
                "description": description,
                "ignored": node.get("ignored") == Some(&Value::Bool(true)),
                "states": accessibility_states(node.get("properties")),
            })
        })
        .collect();
    let has_unobserved_children = all.iter().any(|node| {
        node.get("childIds")
            .and_then(Value::as_array)
            .is_some_and(|children| {
                children
                    .iter()
                    .any(|id| id.as_str().is_some_and(|id| !ids.contains(id)))
            })
    });
    let status = if unavailable {
        "unavailable"
    } else if !include_text {
        "not_approved"
    } else {
        "included"
    };
    Accessibility {
        total: all.len(),
        nodes,
        text_capture: json!({ "status": status, "retained_bytes": retained, "excluded_fields": excluded }),
        excluded_fields: excluded,
        has_unobserved_children,
    }
}

fn accessibility_states(value: Option<&Value>) -> Vec<Value> {
    let mut states: BTreeMap<String, Value> = BTreeMap::new();
    for property in records(value) {
        let Some(name) =
            values::string(property.get("name")).filter(|name| STATE_NAMES.contains(name))
        else {
            continue;
        };
        let raw = values::record(property.get("value")).and_then(|value| value.get("value"));
        let state = match raw {
            Some(Value::Bool(flag)) => Some(json!(flag)),
            Some(Value::Number(number)) => number
                .as_f64()
                .filter(|value| value.is_finite())
                .map(values::js_number),
            Some(Value::String(text)) => Some(json!(text)),
            _ => None,
        };
        if let Some(state) = state {
            states.insert(name.to_owned(), state);
        }
    }
    states
        .into_iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect()
}
