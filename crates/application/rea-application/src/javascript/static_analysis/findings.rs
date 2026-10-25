//! Port of `javascriptStaticAnalysisFindings.ts`. Offsets are Babel UTF-16
//! `start` values, the unit every producer of module ranges and findings
//! uses.

use std::collections::HashSet;

/// Source offsets for one recovered bundle module factory
/// (`JavaScriptModuleRange`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleRange {
    pub start: i64,
    pub end: i64,
    pub key: String,
    pub runtime: String,
    pub require_name: Option<String>,
}

#[derive(Default)]
struct TreeNode {
    left: Option<Box<TreeNode>>,
    right: Option<Box<TreeNode>>,
    /// `(order, index into ranges)` of the earliest range covering the node.
    best: Option<usize>,
}

/// `JavaScriptModuleRangeIndex`: incremental point lookup preserving
/// insertion-order precedence for overlaps.
pub struct ModuleRangeIndex {
    root: TreeNode,
    end: i64,
    ranges: Vec<ModuleRange>,
}

impl ModuleRangeIndex {
    /// An empty index bounded by the analyzed source length (UTF-16 units).
    pub fn new(source_length: usize) -> Self {
        Self {
            root: TreeNode::default(),
            end: (i64::try_from(source_length).unwrap_or(i64::MAX - 1) + 1).max(1),
            ranges: Vec::new(),
        }
    }

    /// Add a module range in discovery order.
    pub fn add(&mut self, range: ModuleRange) {
        let order = self.ranges.len();
        let start = range.start.max(0);
        let end = self.end.min(range.end.saturating_add(1));
        self.ranges.push(range);
        if start < end {
            insert(&mut self.root, 0, self.end, start, end, order);
        }
    }

    /// The first discovered inclusive range containing `offset`.
    pub fn find(&self, offset: Option<i64>) -> Option<&ModuleRange> {
        let offset = offset?;
        if offset < 0 || offset >= self.end {
            return None;
        }
        let mut node = Some(&self.root);
        let (mut low, mut high) = (0_i64, self.end);
        let mut best: Option<usize> = None;
        while let Some(current) = node {
            if let Some(order) = current.best
                && best.is_none_or(|best| order < best)
            {
                best = Some(order);
            }
            if high - low <= 1 {
                break;
            }
            let middle = low + (high - low) / 2;
            if offset < middle {
                node = current.left.as_deref();
                high = middle;
            } else {
                node = current.right.as_deref();
                low = middle;
            }
        }
        best.map(|order| &self.ranges[order])
    }
}

fn insert(node: &mut TreeNode, low: i64, high: i64, query_low: i64, query_high: i64, order: usize) {
    if query_low <= low && high <= query_high {
        if node.best.is_none_or(|best| order < best) {
            node.best = Some(order);
        }
        return;
    }
    let middle = low + (high - low) / 2;
    if query_low < middle {
        let left = node.left.get_or_insert_with(Box::default);
        insert(left, low, middle, query_low, query_high, order);
    }
    if query_high > middle {
        let right = node.right.get_or_insert_with(Box::default);
        insert(right, middle, high, query_low, query_high, order);
    }
}

/// `addFindingOnce`: reserve one deterministic finding key, then add.
pub fn add_finding_once(seen: &mut HashSet<String>, key: String, add: impl FnOnce()) {
    if seen.insert(key) {
        add();
    }
}

/// Static finding retained with its source offset until module attribution
/// (`LocatedJavaScriptFinding`).
#[derive(Clone, Debug)]
pub struct LocatedFinding<V> {
    pub offset: i64,
    pub value: V,
}

/// A finding whose module ownership is attached after traversal.
pub trait ModuleAttributed {
    fn attribute(&mut self, module: Option<&ModuleRange>);
}

/// `finalizeLocatedFindings`.
pub fn finalize_located_findings<V: ModuleAttributed + Clone>(
    values: &[LocatedFinding<V>],
    modules: &ModuleRangeIndex,
) -> Vec<V> {
    values
        .iter()
        .map(|located| {
            let mut value = located.value.clone();
            value.attribute(modules.find(Some(located.offset)));
            value
        })
        .collect()
}

/// `addLocatedFinding`'s key: `${key}\0${String(node.start)}`.
pub fn located_finding_key(key: &str, start: u32) -> String {
    format!("{key}\0{start}")
}
