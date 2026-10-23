//! DOMSnapshot column decoding and SVG/XLink identity:
//! `src/browser/CdpSnapshotStrings.ts`, `CdpSnapshotNodes.ts` and
//! `CdpCaptureDomSvg.ts`. One boundary owns aligned arrays, string
//! references, parent validity and namespace interpretation.
use super::super::values;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const SVG_NAMESPACE: &str = "http://www.w3.org/2000/svg";
const XLINK_NAMESPACE: &str = "http://www.w3.org/1999/xlink";
const SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

pub(super) type Attributes = Vec<(String, String)>;

fn integer(value: &Value) -> Option<i64> {
    values::number(Some(value))
        .filter(|number| number.fract() == 0.0 && number.abs() <= SAFE_INTEGER)
        .map(|number| number as i64)
}

/// `cdpSnapshotString`.
pub(super) fn snapshot_string<'a>(strings: &'a [Option<String>], index: &Value) -> Option<&'a str> {
    let index = integer(index).filter(|index| *index >= 0)?;
    strings.get(index as usize)?.as_deref()
}

/// `cdpSnapshotValueString`: `-1` is the protocol's empty string.
pub(super) fn snapshot_value_string<'a>(
    strings: &'a [Option<String>],
    index: &Value,
) -> Option<&'a str> {
    if values::number(Some(index)) == Some(-1.0) {
        return Some("");
    }
    snapshot_string(strings, index)
}

/// `SnapshotDocumentNodes`.
pub(super) struct DocumentNodes {
    pub node_types: Vec<Option<i64>>,
    pub node_names: Vec<Option<String>>,
    pub node_values: Vec<Option<String>>,
    pub parents: Vec<Option<i64>>,
    pub attributes: Vec<Option<Attributes>>,
    pub backend_node_ids: Vec<Option<i64>>,
    pub excess_attributes: usize,
}

fn attributes(value: &Value, strings: &[Option<String>]) -> Option<Attributes> {
    let items = value.as_array()?;
    if items.len() % 2 != 0 {
        return None;
    }
    let mut pairs = Vec::with_capacity(items.len() / 2);
    for pair in items.chunks(2) {
        let name = snapshot_string(strings, &pair[0])?;
        let text = snapshot_value_string(strings, &pair[1])?;
        pairs.push((name.to_owned(), text.to_owned()));
    }
    Some(pairs)
}

/// `invalidateParentCycles`.
fn invalidate_parent_cycles(parents: &mut [Option<i64>]) {
    let mut state = vec![0_u8; parents.len()];
    let mut path: Vec<usize> = Vec::new();
    for start in 0..parents.len() {
        if state[start] != 0 {
            continue;
        }
        path.clear();
        let mut cursor = start as i64;
        while cursor >= 0 && state[cursor as usize] == 0 {
            state[cursor as usize] = 1;
            path.push(cursor as usize);
            cursor = parents[cursor as usize].unwrap_or(-1);
        }
        if cursor >= 0 && state[cursor as usize] == 1 {
            if let Some(first) = path.iter().position(|index| *index == cursor as usize) {
                for index in &path[first..] {
                    parents[*index] = None;
                }
            }
        }
        for index in &path {
            state[*index] = 2;
        }
    }
}

/// `snapshotDocumentNodes`.
pub(super) fn document_nodes(
    value: Option<&Value>,
    strings: &[Option<String>],
) -> Option<DocumentNodes> {
    let raw = values::record(value)?;
    let column = |name: &str| raw.get(name).and_then(Value::as_array);
    let (types, names, node_values, parents, attribute_rows) = (
        column("nodeType")?,
        column("nodeName")?,
        column("nodeValue")?,
        column("parentIndex")?,
        column("attributes")?,
    );
    let count = types.len();
    if names.len() != count || node_values.len() != count || parents.len() != count {
        return None;
    }
    let mut parent_facts: Vec<Option<i64>> = parents
        .iter()
        .enumerate()
        .map(|(index, value)| {
            integer(value)
                .filter(|parent| *parent >= -1 && *parent < count as i64 && *parent != index as i64)
        })
        .collect();
    invalidate_parent_cycles(&mut parent_facts);
    let backend: &[Value] = column("backendNodeId").map_or(&[], Vec::as_slice);
    Some(DocumentNodes {
        node_types: types
            .iter()
            .map(|value| integer(value).filter(|kind| *kind >= 0))
            .collect(),
        node_names: names
            .iter()
            .map(|value| snapshot_string(strings, value).map(str::to_owned))
            .collect(),
        node_values: node_values
            .iter()
            .map(|value| snapshot_value_string(strings, value).map(str::to_owned))
            .collect(),
        parents: parent_facts,
        attributes: attribute_rows
            .iter()
            .take(count)
            .map(|value| attributes(value, strings))
            .collect(),
        backend_node_ids: backend
            .iter()
            .take(count)
            .map(|value| integer(value).filter(|id| *id > 0))
            .collect(),
        excess_attributes: attribute_rows.len().saturating_sub(count),
    })
}

/// One admitted DOM row (`snapshotNodeAt`).
pub(super) struct NodeRow<'a> {
    pub node_type: i64,
    pub node_name: &'a str,
    pub node_value: &'a str,
    pub parent: i64,
    pub attributes: &'a Attributes,
}

pub(super) fn node_at(nodes: &DocumentNodes, index: usize) -> Option<NodeRow<'_>> {
    Some(NodeRow {
        node_type: (*nodes.node_types.get(index)?)?,
        node_name: nodes.node_names.get(index)?.as_deref()?,
        node_value: nodes.node_values.get(index)?.as_deref()?,
        parent: (*nodes.parents.get(index)?)?,
        attributes: nodes.attributes.get(index)?.as_ref()?,
    })
}

/// `DomSvgNodeQuery`.
#[derive(Clone)]
pub(super) struct SvgQuery {
    pub backend_node_id: i64,
    pub node_name: String,
}

/// `capturedSvgNodeKind`.
pub(super) fn svg_node_kind(query: &SvgQuery, result: &Value) -> Option<bool> {
    let node = values::record(values::record(Some(result)).and_then(|result| result.get("node")))?;
    let backend = values::number(node.get("backendNodeId"));
    if backend != Some(query.backend_node_id as f64)
        || values::string(node.get("nodeName")) != Some(query.node_name.as_str())
        || values::number(node.get("nodeType")) != Some(1.0)
    {
        return None;
    }
    match node.get("isSVG") {
        None => Some(false),
        Some(Value::Bool(flag)) => Some(*flag),
        Some(_) => None,
    }
}

/// `DomSvgLink`.
#[derive(Clone)]
pub(super) struct SvgLink {
    pub svg_element: bool,
    pub xml_document: Option<bool>,
    pub xlink_href: Option<String>,
}

struct XmlLink {
    svg_element: bool,
    xlink_href: Option<String>,
}

/// `DocumentSvgAncestry`.
pub(super) struct Ancestry {
    xml: Option<bool>,
    links: HashMap<usize, XmlLink>,
}

struct Source<'a> {
    node_type: i64,
    node_name: &'a str,
    attributes: &'a Attributes,
}

fn source(nodes: &DocumentNodes, index: usize) -> Option<Source<'_>> {
    Some(Source {
        node_type: (*nodes.node_types.get(index)?)?,
        node_name: nodes.node_names.get(index)?.as_deref()?,
        attributes: nodes.attributes.get(index)?.as_ref()?,
    })
}

fn xmlns_prefix(name: &str) -> Option<&str> {
    if name == "xmlns" {
        return Some("");
    }
    let prefix = name.strip_prefix("xmlns:")?;
    (!prefix.is_empty() && prefix != "xmlns" && !prefix.contains(':')).then_some(prefix)
}

/// `xmlDocument`.
fn xml_document(nodes: &DocumentNodes) -> Option<bool> {
    let Some(document) = nodes.node_types.iter().position(|kind| *kind == Some(9)) else {
        return Some(false);
    };
    source(nodes, document)?;
    if nodes.parents.get(document).copied().flatten() != Some(-1) {
        return None;
    }
    for index in 0..nodes.node_types.len() {
        if nodes.node_types[index] != Some(1) {
            continue;
        }
        if nodes.parents.get(index).copied().flatten() != Some(document as i64) {
            continue;
        }
        let element = source(nodes, index)?;
        let name = element.node_name;
        if name == "HTML" {
            return Some(false);
        }
        if name == "html" || name.contains(':') {
            return Some(true);
        }
        if element
            .attributes
            .iter()
            .any(|(attribute, _)| xmlns_prefix(attribute).is_some())
        {
            return Some(true);
        }
        return Some(false);
    }
    Some(false)
}

/// `createDocumentSvgAncestry`.
pub(super) fn ancestry(nodes: &DocumentNodes) -> Ancestry {
    let xml = xml_document(nodes);
    Ancestry {
        xml,
        links: if xml == Some(true) {
            resolve_xml_elements(nodes)
        } else {
            HashMap::new()
        },
    }
}

/// `domSvgLink`.
pub(super) fn svg_link(ancestry: &Ancestry, index: usize) -> SvgLink {
    let unknown = SvgLink {
        svg_element: false,
        xml_document: None,
        xlink_href: None,
    };
    match ancestry.xml {
        Some(false) => SvgLink {
            svg_element: false,
            xml_document: Some(false),
            xlink_href: None,
        },
        None => unknown,
        Some(true) => match ancestry.links.get(&index) {
            None => unknown,
            Some(resolved) => SvgLink {
                svg_element: resolved.svg_element,
                xml_document: Some(true),
                xlink_href: resolved.xlink_href.clone(),
            },
        },
    }
}

enum Step {
    Node(usize),
    Restore(Vec<(String, Option<String>)>),
}

/// `resolveXmlElements`.
fn resolve_xml_elements(nodes: &DocumentNodes) -> HashMap<usize, XmlLink> {
    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut pending: Vec<Step> = Vec::new();
    for node in 0..nodes.node_names.len() {
        let Some(parent) = nodes.parents.get(node).copied().flatten() else {
            continue;
        };
        if parent < 0 {
            pending.push(Step::Node(node));
        } else {
            children.entry(parent as usize).or_default().push(node);
        }
    }
    let mut bindings: HashMap<String, String> = HashMap::new();
    let mut resolved = HashMap::new();
    while let Some(step) = pending.pop() {
        let node = match step {
            Step::Restore(restore) => {
                for (prefix, previous) in restore {
                    match previous {
                        None => {
                            bindings.remove(&prefix);
                        }
                        Some(previous) => {
                            bindings.insert(prefix, previous);
                        }
                    }
                }
                continue;
            }
            Step::Node(node) => node,
        };
        let Some(element) = source(nodes, node) else {
            continue;
        };
        let restore = apply_declarations(&mut bindings, element.attributes);
        let svg_element = element.node_type == 1
            && element_namespace(element.node_name, &bindings) == SVG_NAMESPACE;
        resolved.insert(
            node,
            XmlLink {
                svg_element,
                xlink_href: if svg_element {
                    xlink_href_value(element.attributes, &bindings)
                } else {
                    None
                },
            },
        );
        pending.push(Step::Restore(restore));
        for child in children.get(&node).into_iter().flatten() {
            pending.push(Step::Node(*child));
        }
    }
    resolved
}

fn apply_declarations(
    bindings: &mut HashMap<String, String>,
    attributes: &Attributes,
) -> Vec<(String, Option<String>)> {
    let mut restore = Vec::new();
    let mut seen = HashSet::new();
    for (name, value) in attributes {
        let Some(prefix) = xmlns_prefix(name) else {
            continue;
        };
        if !seen.insert(prefix.to_owned()) {
            continue;
        }
        restore.push((prefix.to_owned(), bindings.get(prefix).cloned()));
        if value.is_empty() {
            bindings.remove(prefix);
        } else {
            bindings.insert(prefix.to_owned(), value.clone());
        }
    }
    restore
}

fn element_namespace<'a>(name: &str, bindings: &'a HashMap<String, String>) -> &'a str {
    let Some(colon) = name.find(':') else {
        return bindings.get("").map_or("", String::as_str);
    };
    let (prefix, local) = (&name[..colon], &name[colon + 1..]);
    if prefix.is_empty() || local.is_empty() || local.contains(':') || prefix == "xmlns" {
        return "";
    }
    bindings.get(prefix).map_or("", String::as_str)
}

fn xlink_href_value(attributes: &Attributes, bindings: &HashMap<String, String>) -> Option<String> {
    let mut seen = HashSet::new();
    for (name, value) in attributes {
        if !seen.insert(name.as_str()) {
            continue;
        }
        let Some(colon) = name.find(':').filter(|colon| *colon > 0) else {
            continue;
        };
        let (prefix, local) = (&name[..colon], &name[colon + 1..]);
        if local != "href" || bindings.get(prefix).map(String::as_str) != Some(XLINK_NAMESPACE) {
            continue;
        }
        return Some(value.clone());
    }
    None
}
