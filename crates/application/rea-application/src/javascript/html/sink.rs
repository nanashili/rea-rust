//! Minimal arena DOM for html5ever's tree builder. It keeps element names,
//! attributes, text and template contents, plus the token locations that the
//! locating sink publishes while each token is processed.
use std::borrow::Cow;
use std::cell::{Cell, Ref, RefCell};

use html5ever::interface::{ElemName, ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::tendril::StrTendril;
use html5ever::{Attribute, LocalName, Namespace, QualName, ns};

use super::TokenLocations;

#[derive(Debug)]
pub(crate) struct Element {
    pub(crate) name: QualName,
    /// HTML namespace.
    pub(crate) html: bool,
    pub(crate) local: String,
    pub(crate) attrs: Vec<(String, String)>,
    template_contents: Option<usize>,
    /// MathML `annotation-xml` with an HTML `encoding` (an HTML integration
    /// point), as decided by html5ever when the element was created.
    annotation_xml_integration_point: bool,
    /// Byte span of the start tag token that created the element.
    pub(crate) start_tag: Option<(usize, usize)>,
    /// Byte offset where the token that popped the element starts.
    pub(crate) end: Option<usize>,
    /// Whether a matching end tag was seen even if foreign tree rules did not
    /// pop this element. parse5 applies in-body end-tag matching here.
    pub(crate) explicit_end_tag: bool,
}

#[derive(Debug)]
pub(crate) enum NodeKind {
    Document,
    Fragment,
    Element(Box<Element>),
    Text(String),
    Other,
}

#[derive(Debug)]
pub(crate) struct Node {
    parent: Option<usize>,
    pub(crate) children: Vec<usize>,
    pub(crate) kind: NodeKind,
}

pub(crate) struct Arena<'a> {
    nodes: RefCell<Vec<Node>>,
    /// The element html5ever most recently asked the name of.
    last_named: Cell<Option<usize>>,
    locations: &'a TokenLocations,
}

/// An owned element name; html5ever may mutate the sink while holding one.
#[derive(Debug)]
pub(crate) struct OwnedName(QualName);

impl ElemName for OwnedName {
    fn ns(&self) -> &Namespace {
        &self.0.ns
    }
    fn local_name(&self) -> &LocalName {
        &self.0.local
    }
}

impl<'a> Arena<'a> {
    pub(crate) fn new(locations: &'a TokenLocations) -> Self {
        Self {
            nodes: RefCell::new(vec![Node {
                parent: None,
                children: Vec::new(),
                kind: NodeKind::Document,
            }]),
            last_named: Cell::new(None),
            locations,
        }
    }

    /// The element html5ever most recently asked the name of.
    pub(crate) fn last_named(&self) -> Option<usize> {
        self.last_named.get()
    }

    /// A MathML text integration point or an HTML integration point.
    pub(crate) fn is_integration_point(&self, id: usize) -> bool {
        let nodes = self.nodes.borrow();
        let NodeKind::Element(element) = &nodes[id].kind else {
            return false;
        };
        if element.name.ns == ns!(mathml) {
            matches!(element.local.as_str(), "mi" | "mo" | "mn" | "ms" | "mtext")
                || element.annotation_xml_integration_point
        } else if element.name.ns == ns!(svg) {
            matches!(element.local.as_str(), "foreignObject" | "desc" | "title")
        } else {
            false
        }
    }

    pub(crate) fn nodes(&self) -> Ref<'_, Vec<Node>> {
        self.nodes.borrow()
    }

    /// Whether a node is nested in SVG content that has not crossed an HTML
    /// integration point. This supplements html5ever's namespace assignment
    /// where parse5 applies its in-body end-tag matching to foreign nodes.
    pub(crate) fn is_in_foreign_svg(&self, id: usize) -> bool {
        let nodes = self.nodes.borrow();
        let mut current = nodes[id].parent;
        while let Some(parent) = current {
            let NodeKind::Element(element) = &nodes[parent].kind else {
                current = nodes[parent].parent;
                continue;
            };
            if element.html && matches!(element.local.as_str(), "desc" | "title") {
                return false;
            }
            if element.name.ns == ns!(svg) {
                return match element.local.as_str() {
                    "foreignObject" => false,
                    "desc" | "title" => {
                        element.explicit_end_tag && Self::has_svg_script_ancestor(&nodes, current)
                    }
                    _ => true,
                };
            }
            current = nodes[parent].parent;
        }
        false
    }

    fn has_svg_script_ancestor(nodes: &[Node], mut current: Option<usize>) -> bool {
        while let Some(parent) = current {
            if let NodeKind::Element(element) = &nodes[parent].kind
                && element.name.ns == ns!(svg)
                && element.local == "script"
            {
                return true;
            }
            current = nodes[parent].parent;
        }
        false
    }

    pub(crate) fn note_explicit_end_tag(&self, local: &str) {
        let mut nodes = self.nodes.borrow_mut();
        for node in nodes.iter_mut().rev() {
            let NodeKind::Element(element) = &mut node.kind else {
                continue;
            };
            if element.name.ns == ns!(svg) && element.local == local && element.end.is_none() {
                element.explicit_end_tag = true;
                break;
            }
        }
    }

    fn push(&self, kind: NodeKind) -> usize {
        let mut nodes = self.nodes.borrow_mut();
        nodes.push(Node {
            parent: None,
            children: Vec::new(),
            kind,
        });
        nodes.len() - 1
    }

    fn detach(nodes: &mut [Node], child: usize) {
        if let Some(parent) = nodes[child].parent.take() {
            nodes[parent].children.retain(|&existing| existing != child);
        }
    }

    /// Insert `child` into `parent` at `index`, merging adjacent text.
    fn insert(&self, parent: usize, index: usize, child: NodeOrText<usize>) {
        let mut nodes = self.nodes.borrow_mut();
        match child {
            NodeOrText::AppendText(text) => {
                if let Some(&previous) = index
                    .checked_sub(1)
                    .and_then(|before| nodes[parent].children.get(before))
                    && let NodeKind::Text(existing) = &mut nodes[previous].kind
                {
                    existing.push_str(&text);
                    return;
                }
                nodes.push(Node {
                    parent: Some(parent),
                    children: Vec::new(),
                    kind: NodeKind::Text(text.to_string()),
                });
                let id = nodes.len() - 1;
                nodes[parent].children.insert(index, id);
            }
            NodeOrText::AppendNode(id) => {
                Self::detach(&mut nodes, id);
                let index = index.min(nodes[parent].children.len());
                nodes[id].parent = Some(parent);
                nodes[parent].children.insert(index, id);
            }
        }
    }
}

impl TreeSink for Arena<'_> {
    type Handle = usize;
    type Output = Self;
    type ElemName<'b>
        = OwnedName
    where
        Self: 'b;

    fn finish(self) -> Self {
        self
    }

    fn parse_error(&self, _message: Cow<'static, str>) {}

    fn get_document(&self) -> usize {
        0
    }

    fn elem_name<'b>(&'b self, target: &'b usize) -> OwnedName {
        self.last_named.set(Some(*target));
        match &self.nodes.borrow()[*target].kind {
            NodeKind::Element(element) => OwnedName(element.name.clone()),
            _ => OwnedName(QualName::new(None, ns!(), LocalName::from(""))),
        }
    }

    fn create_element(&self, name: QualName, attrs: Vec<Attribute>, flags: ElementFlags) -> usize {
        let template_contents = flags.template.then(|| self.push(NodeKind::Fragment));
        let html = name.ns == ns!(html);
        let local = name.local.to_string();
        self.push(NodeKind::Element(Box::new(Element {
            html,
            local,
            attrs: attrs
                .into_iter()
                .map(|attribute| {
                    (
                        attribute.name.local.to_string(),
                        attribute.value.to_string(),
                    )
                })
                .collect(),
            template_contents,
            annotation_xml_integration_point: flags.mathml_annotation_xml_integration_point,
            start_tag: self.locations.start_tag.get(),
            end: None,
            explicit_end_tag: false,
            name,
        })))
    }

    fn create_comment(&self, _text: StrTendril) -> usize {
        self.push(NodeKind::Other)
    }

    fn create_pi(&self, _target: StrTendril, _data: StrTendril) -> usize {
        self.push(NodeKind::Other)
    }

    fn append(&self, parent: &usize, child: NodeOrText<usize>) {
        let index = self.nodes.borrow()[*parent].children.len();
        self.insert(*parent, index, child);
    }

    fn append_based_on_parent_node(
        &self,
        element: &usize,
        prev_element: &usize,
        child: NodeOrText<usize>,
    ) {
        if self.nodes.borrow()[*element].parent.is_some() {
            self.append_before_sibling(element, child);
        } else {
            self.append(prev_element, child);
        }
    }

    fn append_doctype_to_document(
        &self,
        _name: StrTendril,
        _public_id: StrTendril,
        _system_id: StrTendril,
    ) {
        let id = self.push(NodeKind::Other);
        self.append(&0, NodeOrText::AppendNode(id));
    }

    fn pop(&self, node: &usize) {
        let token_start = self.locations.token_start.get();
        if let NodeKind::Element(element) = &mut self.nodes.borrow_mut()[*node].kind
            && element.end.is_none()
        {
            element.end = Some(token_start);
        }
    }

    fn get_template_contents(&self, target: &usize) -> usize {
        match &self.nodes.borrow()[*target].kind {
            NodeKind::Element(element) => element.template_contents.unwrap_or(*target),
            _ => *target,
        }
    }

    fn is_mathml_annotation_xml_integration_point(&self, handle: &usize) -> bool {
        matches!(&self.nodes.borrow()[*handle].kind, NodeKind::Element(element) if element.annotation_xml_integration_point)
    }

    fn same_node(&self, x: &usize, y: &usize) -> bool {
        x == y
    }

    fn set_quirks_mode(&self, _mode: QuirksMode) {}

    fn append_before_sibling(&self, sibling: &usize, new_node: NodeOrText<usize>) {
        let (parent, index) = {
            let nodes = self.nodes.borrow();
            let Some(parent) = nodes[*sibling].parent else {
                return;
            };
            let index = nodes[parent]
                .children
                .iter()
                .position(|&child| child == *sibling)
                .unwrap_or_default();
            (parent, index)
        };
        // Detaching a node that precedes the sibling in the same parent
        // shifts the insertion index.
        let index = match &new_node {
            NodeOrText::AppendNode(id) => {
                let nodes = self.nodes.borrow();
                match nodes[*id].parent {
                    Some(existing) if existing == parent => {
                        let position = nodes[parent]
                            .children
                            .iter()
                            .position(|&child| child == *id);
                        if position.is_some_and(|position| position < index) {
                            index - 1
                        } else {
                            index
                        }
                    }
                    _ => index,
                }
            }
            NodeOrText::AppendText(_) => index,
        };
        self.insert(parent, index, new_node);
    }

    fn add_attrs_if_missing(&self, target: &usize, attrs: Vec<Attribute>) {
        if let NodeKind::Element(element) = &mut self.nodes.borrow_mut()[*target].kind {
            for attribute in attrs {
                let name = attribute.name.local.to_string();
                if !element.attrs.iter().any(|(existing, _)| *existing == name) {
                    element.attrs.push((name, attribute.value.to_string()));
                }
            }
        }
    }

    fn remove_from_parent(&self, target: &usize) {
        Self::detach(&mut self.nodes.borrow_mut(), *target);
    }

    fn reparent_children(&self, node: &usize, new_parent: &usize) {
        let mut nodes = self.nodes.borrow_mut();
        let children = std::mem::take(&mut nodes[*node].children);
        for &child in &children {
            nodes[child].parent = Some(*new_parent);
        }
        nodes[*new_parent].children.extend(children);
    }
}
