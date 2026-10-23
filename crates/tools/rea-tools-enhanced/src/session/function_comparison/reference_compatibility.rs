//! Reference-fact compatibility via integer max-flow.
//!
//! Compatibility owner: `functionReferenceCompatibility.ts`.

use crate::js::composite_key;
use std::collections::HashMap;

/// One reference compatibility row; only source/target/kind can be unknown.
#[derive(Clone)]
pub struct ReferenceCompatibilityRow {
    pub direction: &'static str,
    pub source: Option<String>,
    pub target: Option<String>,
    pub kind: Option<String>,
}

#[derive(Clone)]
struct ReferenceGroup {
    direction: &'static str,
    source: Option<String>,
    target: Option<String>,
    kind: Option<String>,
    mask: u8,
    count: i64,
}

struct FlowEdge {
    to: usize,
    reverse: usize,
    remaining: i64,
}

#[derive(Default)]
struct ReferenceFlow {
    edges: Vec<Vec<FlowEdge>>,
}

impl ReferenceFlow {
    fn node(&mut self) -> usize {
        self.edges.push(Vec::new());
        self.edges.len() - 1
    }

    fn connect(&mut self, from: usize, to: usize, capacity: i64) {
        let reverse_index = self.edges[to].len();
        let forward_index = self.edges[from].len();
        self.edges[from].push(FlowEdge {
            to,
            reverse: reverse_index,
            remaining: capacity,
        });
        self.edges[to].push(FlowEdge {
            to: from,
            reverse: forward_index,
            remaining: 0,
        });
    }

    fn covers(&mut self, source: usize, sink: usize, required: i64) -> bool {
        let mut delivered = 0i64;
        while delivered < required {
            let mut levels = vec![-1i64; self.edges.len()];
            let mut queue = vec![source];
            levels[source] = 0;
            let mut index = 0;
            while index < queue.len() {
                let node = queue[index];
                index += 1;
                for edge in &self.edges[node] {
                    if edge.remaining <= 0 || levels[edge.to] != -1 {
                        continue;
                    }
                    levels[edge.to] = levels[node] + 1;
                    queue.push(edge.to);
                }
            }
            if levels[sink] == -1 {
                return false;
            }
            let mut next = vec![0usize; self.edges.len()];
            loop {
                if delivered >= required {
                    break;
                }
                let amount =
                    self.augment(source, sink, required - delivered, &mut levels, &mut next);
                if amount <= 0 {
                    break;
                }
                delivered += amount;
            }
        }
        true
    }

    fn augment(
        &mut self,
        source: usize,
        sink: usize,
        capacity: i64,
        levels: &mut [i64],
        next: &mut [usize],
    ) -> i64 {
        // Iterative DFS mirroring the TypeScript path/stack bookkeeping.
        let mut nodes = vec![source];
        let mut path: Vec<(usize, usize)> = Vec::new(); // (node, edge index within node)
        let mut capacities = vec![capacity];
        while let Some(&node) = nodes.last() {
            if node == sink {
                let amount = *capacities.last().unwrap_or(&0);
                for &(from, edge_index) in &path {
                    let to;
                    let reverse;
                    {
                        let edge = &mut self.edges[from][edge_index];
                        edge.remaining -= amount;
                        to = edge.to;
                        reverse = edge.reverse;
                    }
                    self.edges[to][reverse].remaining += amount;
                }
                return amount;
            }
            // Advance next[node] past unusable edges.
            let mut chosen: Option<usize> = None;
            while next[node] < self.edges[node].len() {
                let edge = &self.edges[node][next[node]];
                if edge.remaining > 0 && levels[edge.to] == levels[node] + 1 {
                    chosen = Some(next[node]);
                    break;
                }
                next[node] += 1;
            }
            match chosen {
                None => {
                    levels[node] = -1;
                    nodes.pop();
                    path.pop();
                    capacities.pop();
                }
                Some(edge_index) => {
                    let (to, remaining) = {
                        let edge = &self.edges[node][edge_index];
                        (edge.to, edge.remaining)
                    };
                    path.push((node, edge_index));
                    nodes.push(to);
                    let current = *capacities.last().unwrap_or(&0);
                    capacities.push(current.min(remaining));
                }
            }
        }
        0
    }
}

fn group_key(row: &ReferenceCompatibilityRow) -> String {
    composite_key_opt(&[
        Some(row.direction),
        row.source.as_deref(),
        row.target.as_deref(),
        row.kind.as_deref(),
    ])
}

/// `JSON.stringify` of a tuple of strings/nulls.
fn composite_key_opt(parts: &[Option<&str>]) -> String {
    let values: Vec<serde_json::Value> = parts
        .iter()
        .map(|part| match part {
            Some(text) => serde_json::Value::String((*text).to_owned()),
            None => serde_json::Value::Null,
        })
        .collect();
    serde_json::to_string(&values).unwrap_or_default()
}

fn group_rows(rows: &[ReferenceCompatibilityRow]) -> Vec<(String, ReferenceGroup)> {
    // Preserve insertion order like a JS Map.
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, ReferenceGroup> = HashMap::new();
    for row in rows {
        let key = group_key(row);
        if let Some(previous) = groups.get_mut(&key) {
            previous.count += 1;
        } else {
            let mask = (if row.source.is_none() { 0 } else { 1 })
                | (if row.target.is_none() { 0 } else { 2 })
                | (if row.kind.is_none() { 0 } else { 4 });
            order.push(key.clone());
            groups.insert(
                key,
                ReferenceGroup {
                    direction: row.direction,
                    source: row.source.clone(),
                    target: row.target.clone(),
                    kind: row.kind.clone(),
                    mask,
                    count: 1,
                },
            );
        }
    }
    order
        .into_iter()
        .map(|key| (key.clone(), groups.remove(&key).unwrap()))
        .collect()
}

/// `referenceFactsCompatible`.
pub fn reference_facts_compatible(
    left: &[ReferenceCompatibilityRow],
    right: &[ReferenceCompatibilityRow],
) -> bool {
    if left.len() != right.len() {
        return false;
    }
    if left.is_empty() {
        return true;
    }
    let mut left_groups = group_rows(left);
    let mut right_groups = group_rows(right);

    // Exact multiset equality shortcut.
    if left_groups.len() == right_groups.len() {
        let right_counts: HashMap<&str, i64> = right_groups
            .iter()
            .map(|(key, group)| (key.as_str(), group.count))
            .collect();
        if left_groups
            .iter()
            .all(|(key, group)| right_counts.get(key.as_str()) == Some(&group.count))
        {
            return true;
        }
    }

    // All rows fully known and multisets differ.
    if left_groups
        .iter()
        .chain(right_groups.iter())
        .all(|(_, group)| group.mask == 7)
    {
        return false;
    }

    // Cancel identical complete (mask == 7) rows.
    let mut required: i64 = left.len() as i64;
    // Build lookup for right groups by key index.
    for i in 0..left_groups.len() {
        if left_groups[i].1.mask != 7 {
            continue;
        }
        let key = left_groups[i].0.clone();
        if let Some(j) = right_groups
            .iter()
            .position(|(right_key, _)| *right_key == key)
        {
            let cancelled = left_groups[i].1.count.min(right_groups[j].1.count);
            left_groups[i].1.count -= cancelled;
            right_groups[j].1.count -= cancelled;
            required -= cancelled;
        }
    }
    left_groups.retain(|(_, group)| group.count != 0);
    right_groups.retain(|(_, group)| group.count != 0);

    let left_masks: Vec<u8> = {
        let mut set = Vec::new();
        for (_, group) in &left_groups {
            if !set.contains(&group.mask) {
                set.push(group.mask);
            }
        }
        set
    };
    let right_masks: Vec<u8> = {
        let mut set = Vec::new();
        for (_, group) in &right_groups {
            if !set.contains(&group.mask) {
                set.push(group.mask);
            }
        }
        set
    };

    let mut flow = ReferenceFlow::default();
    let source = flow.node();
    let sink = flow.node();
    let mut buckets: HashMap<String, usize> = HashMap::new();

    let bucket_node = |flow: &mut ReferenceFlow,
                       buckets: &mut HashMap<String, usize>,
                       group: &ReferenceGroup,
                       left_mask: u8,
                       right_mask: u8|
     -> usize {
        let intersection = left_mask & right_mask;
        let key = composite_key(&[
            group.direction,
            &left_mask.to_string(),
            &right_mask.to_string(),
            &bucket_component(intersection & 1, &group.source),
            &bucket_component(intersection & 2, &group.target),
            &bucket_component(intersection & 4, &group.kind),
        ]);
        if let Some(existing) = buckets.get(&key) {
            return *existing;
        }
        let node = flow.node();
        buckets.insert(key, node);
        node
    };

    for (_, group) in &left_groups {
        let node = flow.node();
        flow.connect(source, node, group.count);
        for &mask in &right_masks {
            let bucket = bucket_node(&mut flow, &mut buckets, group, group.mask, mask);
            flow.connect(node, bucket, group.count);
        }
    }
    for (_, group) in &right_groups {
        let node = flow.node();
        flow.connect(node, sink, group.count);
        for &mask in &left_masks {
            let bucket = bucket_node(&mut flow, &mut buckets, group, mask, group.mask);
            flow.connect(bucket, node, group.count);
        }
    }

    flow.covers(source, sink, required)
}

/// Encode one bucket key component: the fact value when present, else null.
fn bucket_component(present: u8, value: &Option<String>) -> String {
    // Encoded as a JSON fragment within the composite tuple string to match
    // `JSON.stringify([... , present ? value : null, ...])`.
    match (present != 0, value) {
        (true, Some(text)) => text.clone(),
        _ => "\0null".to_owned(),
    }
}
