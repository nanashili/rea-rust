//! Per-analysis AST context: source, Babel positions and node side tables.

use std::collections::{HashMap, HashSet};

use oxc_ast::ast::{Comment, Program};
use oxc_span::Span;

use super::node::{Node, NodeKey};
use crate::javascript::parser::{PositionIndex, SourcePosition, SourceRange};

/// Node-keyed state (`WeakMap<t.Node, T>` in TS). One per analysis, owned by
/// [`AstContext`] users; never shared across analyses.
pub type NodeMap<T> = HashMap<NodeKey, T>;
/// Node-keyed membership (`WeakSet<t.Node>` in TS).
pub type NodeSet = HashSet<NodeKey>;

/// Everything one analysis of one parsed source shares: the program, its
/// text and the single UTF-8 -> Babel UTF-16 position conversion. Anything
/// emitted or keyed by position goes through here.
pub struct AstContext<'a> {
    program: &'a Program<'a>,
    index: PositionIndex<'a>,
}

impl<'a> AstContext<'a> {
    pub fn new(program: &'a Program<'a>) -> Self {
        Self {
            program,
            index: PositionIndex::new(program.source_text),
        }
    }

    pub fn program(&self) -> &'a Program<'a> {
        self.program
    }

    pub fn source(&self) -> &'a str {
        self.program.source_text
    }

    /// Parser-owned comment tokens in source order.
    ///
    /// Consumers must inspect these tokens rather than searching the source
    /// text, because quoted strings, regular expressions, and template
    /// literals may contain comment-looking text.
    pub fn comments(&self) -> impl Iterator<Item = Comment> + '_ {
        self.program.comments.iter().copied()
    }

    /// The Babel `Program` view.
    pub fn root(&self) -> Node<'a> {
        Node::program(self.program)
    }

    /// Children in Babel `VISITOR_KEYS` order.
    pub fn children(&self, node: &Node<'a>) -> Vec<Node<'a>> {
        node.children(self.program.source_text)
    }

    /// Babel `start` (UTF-16 code units).
    pub fn start(&self, node: &Node<'_>) -> u32 {
        self.index.utf16_offset(node.span().start)
    }

    /// Babel `end` (UTF-16 code units).
    pub fn end(&self, node: &Node<'_>) -> u32 {
        self.index.utf16_offset(node.span().end)
    }

    /// Babel `loc` for a node (1-based lines, 0-based UTF-16 columns).
    pub fn range(&self, node: &Node<'_>) -> SourceRange {
        self.index.range(node.span())
    }

    /// Babel position of a UTF-8 byte offset.
    pub fn point_for_offset(&self, byte: u32) -> SourcePosition {
        self.index.position(byte)
    }

    /// `source.slice(node.start, node.end)`; identical to the UTF-16 slice
    /// because node boundaries are character boundaries.
    pub fn slice(&self, span: Span) -> &'a str {
        &self.program.source_text[span.start as usize..span.end as usize]
    }

    /// `source.slice(start, end).slice(0, max_units)` in UTF-16 code units,
    /// and whether it was truncated. A cut through a surrogate pair keeps
    /// the whole character out (Rust strings cannot hold half a pair), which
    /// is one unit shorter than JS would produce.
    pub fn slice_utf16_prefix(&self, span: Span, max_units: usize) -> (&'a str, bool) {
        let text = self.slice(span);
        let mut units = 0usize;
        for (byte, ch) in text.char_indices() {
            units += ch.len_utf16();
            if units > max_units {
                return (&text[..byte], true);
            }
        }
        (text, false)
    }
}
