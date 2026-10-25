//! `JavaScriptSemanticGraphProjection`: source-interval lookups over one file IR.

use std::cmp::Ordering;
use std::collections::HashMap;

use super::json::Json;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Point(i64, i64);

#[derive(Clone, Copy, Debug)]
struct Range {
    start: Point,
    end: Point,
}

#[allow(clippy::cast_possible_truncation)]
fn point(value: &Json) -> Point {
    Point(
        value.at("line").num() as i64,
        value.at("column").num() as i64,
    )
}

fn range(value: &Json) -> Range {
    Range {
        start: point(value.at("start")),
        end: point(value.at("end")),
    }
}

fn contains(outer: Range, inner: Range) -> bool {
    outer.start <= inner.start && outer.end >= inner.end
}

struct Tree {
    entry: usize,
    minimum_start: Point,
    maximum_start: Point,
    minimum_end: Point,
    maximum_end: Point,
    left: Option<Box<Tree>>,
    right: Option<Box<Tree>>,
}

fn build(entries: &[(Range, usize)], start: usize, end: usize) -> Option<Box<Tree>> {
    if start >= end {
        return None;
    }
    let middle = (start + end) / 2;
    let (entry_range, _) = entries[middle];
    let left = build(entries, start, middle);
    let right = build(entries, middle + 1, end);
    let mut minimum_end = entry_range.end;
    let mut maximum_end = entry_range.end;
    for child in [&left, &right].into_iter().flatten() {
        minimum_end = minimum_end.min(child.minimum_end);
        maximum_end = maximum_end.max(child.maximum_end);
    }
    Some(Box::new(Tree {
        entry: middle,
        minimum_start: left
            .as_ref()
            .map_or(entry_range.start, |tree| tree.minimum_start),
        maximum_start: right
            .as_ref()
            .map_or(entry_range.start, |tree| tree.maximum_start),
        minimum_end,
        maximum_end,
        left,
        right,
    }))
}

fn sorted_entries(ranges: impl Iterator<Item = (Range, usize)>) -> Vec<(Range, usize)> {
    let mut entries: Vec<(Range, usize)> = ranges.collect();
    entries.sort_by(|left, right| left.0.start.cmp(&right.0.start).then(left.1.cmp(&right.1)));
    entries
}

/// `createSemanticCallableOwnerLookup`: innermost-by-start retained callable.
pub struct CallableOwnerLookup {
    entries: Vec<(Range, usize)>,
    ids: Vec<String>,
    tree: Option<Box<Tree>>,
}

impl CallableOwnerLookup {
    /// Index one IR's callables.
    pub fn new(ir: &Json) -> Self {
        let callables = ir.at("callables").arr();
        let ids = callables
            .iter()
            .map(|callable| callable.at("callableId").str().to_owned())
            .collect();
        let entries = sorted_entries(
            callables
                .iter()
                .enumerate()
                .map(|(order, callable)| (range(callable.at("location")), order)),
        );
        let tree = build(&entries, 0, entries.len());
        Self { entries, ids, tree }
    }

    /// The owning retained callable node for one location.
    pub fn owner<'n>(&self, location: &Json, nodes: &'n HashMap<String, Json>) -> Option<&'n Json> {
        if location.is_null() || nodes.is_empty() {
            return None;
        }
        let location = range(location);
        let mut pending: Vec<&Tree> = self.tree.as_deref().into_iter().collect();
        let mut best: Option<(Point, usize)> = None;
        let mut result = None;
        while let Some(current) = pending.pop() {
            if current.minimum_start > location.start || current.maximum_end < location.end {
                continue;
            }
            let (candidate, order) = self.entries[current.entry];
            if contains(candidate, location)
                && let Some(node) = nodes.get(&self.ids[order])
            {
                let better = match best {
                    None => true,
                    Some((start, best_order)) => match candidate.start.cmp(&start) {
                        Ordering::Greater => true,
                        Ordering::Less => false,
                        Ordering::Equal => best_order > order,
                    },
                };
                if better {
                    best = Some((candidate.start, order));
                    result = Some(node);
                }
            }
            pending.extend(current.left.as_deref());
            pending.extend(current.right.as_deref());
        }
        result
    }
}

/// `createSemanticNodeRangeLookup`: retained nodes contained in a range, in producer order.
pub struct NodeRangeLookup {
    entries: Vec<(Range, usize)>,
    nodes: Vec<Json>,
    tree: Option<Box<Tree>>,
}

impl NodeRangeLookup {
    /// Index nodes with a source range.
    pub fn new(nodes: &[Json]) -> Self {
        let entries = sorted_entries(nodes.iter().enumerate().filter_map(|(order, node)| {
            let source = node.at("identity").at("source_range");
            (!source.is_null()).then(|| (range(source), order))
        }));
        let tree = build(&entries, 0, entries.len());
        Self {
            entries,
            nodes: nodes.to_vec(),
            tree,
        }
    }

    /// Nodes whose ranges lie within `bounds`.
    pub fn within(&self, bounds: &Json) -> Vec<&Json> {
        let bounds = range(bounds);
        let mut pending: Vec<&Tree> = self.tree.as_deref().into_iter().collect();
        let mut matches: Vec<usize> = Vec::new();
        while let Some(current) = pending.pop() {
            if current.maximum_start < bounds.start || current.minimum_end > bounds.end {
                continue;
            }
            let (entry, order) = self.entries[current.entry];
            if contains(bounds, entry) {
                matches.push(order);
            }
            pending.extend(current.left.as_deref());
            pending.extend(current.right.as_deref());
        }
        matches.sort_unstable();
        matches
            .into_iter()
            .map(|order| &self.nodes[order])
            .collect()
    }
}

/// `rangeKey` for exact-range maps.
pub fn range_key(value: &Json) -> String {
    let point = |point: &Json| {
        format!(
            "{}:{}",
            super::json::js_int(point.at("line").num()),
            super::json::js_int(point.at("column").num())
        )
    };
    format!("{}-{}", point(value.at("start")), point(value.at("end")))
}
