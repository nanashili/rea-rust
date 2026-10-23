//! Line diff matching the `diff` npm package `diffLines` used by
//! `functionComparisonDimensions.ts`.
//!
//! Compatibility owner: `node_modules/diff` `LineDiff`/`Diff` (`diff/line.js`,
//! `diff/base.js`). The tokenizer splits on `\n`/`\r\n`, merges each newline
//! separator into its preceding content token, drops the trailing empty token,
//! then `removeEmpty` filters empty tokens. The diff is Myers' algorithm with
//! the library's diagonal-pruning optimization and `maxEditLength` abort.
//!
//! Timeout: the original passes `timeout: 100` (wall-clock milliseconds). A
//! deterministic port cannot reproduce a wall-clock abort and the original's
//! result on a timed-out diff is itself nondeterministic, so only the
//! deterministic `maxEditLength` bound is enforced here. See the port report.

/// One diff component: a run of common/added/removed tokens.
#[derive(Clone, Copy)]
struct Component {
    count: usize,
    added: bool,
    removed: bool,
}

/// Summed line delta over the produced change components.
pub struct TextDelta {
    pub added_lines: u64,
    pub removed_lines: u64,
    pub hunks: u64,
}

/// `tokenize` without `stripTrailingCr`/`newlineIsToken`.
fn tokenize(value: &str) -> Vec<&str> {
    // Split keeping separators: emulate value.split(/(\n|\r\n)/). JavaScript's
    // regex is greedy and tries `\n` first in the alternation, but with a
    // capture group the split alternates content and separator tokens. Because
    // `\r\n` contains `\n`, JS matches `\n` first only when not preceded by
    // `\r`; the `(\n|\r\n)` group as written matches `\n` greedily so `\r\n`
    // is split as content ending in `\r` then `\n`. Reproduce that precisely.
    let bytes = value.as_bytes();
    let mut pieces: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            // content piece before the newline
            pieces.push(&value[start..index]);
            // separator piece
            pieces.push(&value[index..index + 1]);
            index += 1;
            start = index;
        } else {
            index += 1;
        }
    }
    // trailing content piece
    pieces.push(&value[start..]);

    // Ignore the final empty token that occurs if the string ends with newline.
    if pieces.last().is_some_and(|piece| piece.is_empty()) {
        pieces.pop();
    }

    // Merge separators (odd indices) into the preceding content token.
    let mut lines: Vec<&str> = Vec::new();
    for (i, piece) in pieces.iter().enumerate() {
        if i % 2 == 1 {
            // separator: extend the previous content token's slice
            if let Some(previous) = lines.last_mut() {
                // piece immediately follows previous in the same &str
                let prev_start = previous.as_ptr() as usize - value.as_ptr() as usize;
                let new_end = prev_start + previous.len() + piece.len();
                *previous = &value[prev_start..new_end];
            } else {
                lines.push(piece);
            }
        } else {
            lines.push(piece);
        }
    }
    lines
}

/// `removeEmpty`.
fn remove_empty<'a>(tokens: Vec<&'a str>) -> Vec<&'a str> {
    tokens
        .into_iter()
        .filter(|token| !token.is_empty())
        .collect()
}

#[derive(Clone)]
struct PathNode {
    old_pos: i64,
    last: Option<Box<Comp>>,
}

#[derive(Clone)]
struct Comp {
    count: usize,
    added: bool,
    removed: bool,
    previous: Option<Box<Comp>>,
}

fn add_to_path(path: &PathNode, added: bool, removed: bool, old_pos_inc: i64) -> PathNode {
    if let Some(last) = &path.last
        && last.added == added
        && last.removed == removed
    {
        return PathNode {
            old_pos: path.old_pos + old_pos_inc,
            last: Some(Box::new(Comp {
                count: last.count + 1,
                added,
                removed,
                previous: last.previous.clone(),
            })),
        };
    }
    PathNode {
        old_pos: path.old_pos + old_pos_inc,
        last: Some(Box::new(Comp {
            count: 1,
            added,
            removed,
            previous: path.last.clone(),
        })),
    }
}

fn extract_common(
    base: &mut PathNode,
    new_tokens: &[&str],
    old_tokens: &[&str],
    diagonal: i64,
) -> i64 {
    let new_len = new_tokens.len() as i64;
    let old_len = old_tokens.len() as i64;
    let mut old_pos = base.old_pos;
    let mut new_pos = old_pos - diagonal;
    let mut common_count = 0usize;
    while new_pos + 1 < new_len
        && old_pos + 1 < old_len
        && old_tokens[(old_pos + 1) as usize] == new_tokens[(new_pos + 1) as usize]
    {
        new_pos += 1;
        old_pos += 1;
        common_count += 1;
    }
    if common_count > 0 {
        base.last = Some(Box::new(Comp {
            count: common_count,
            added: false,
            removed: false,
            previous: base.last.take(),
        }));
    }
    base.old_pos = old_pos;
    new_pos
}

fn build_values(mut last: Option<Box<Comp>>) -> Vec<Component> {
    let mut components = Vec::new();
    while let Some(node) = last {
        components.push(Component {
            count: node.count,
            added: node.added,
            removed: node.removed,
        });
        last = node.previous;
    }
    components.reverse();
    components
}

/// `diffLines(old, new, { maxEditLength })` reduced to a [`TextDelta`].
///
/// Returns `None` when the bounded edit distance is exceeded (the original's
/// `undefined`).
pub fn diff_lines_delta(old_str: &str, new_str: &str, max_edit_length: usize) -> Option<TextDelta> {
    let old_tokens = remove_empty(tokenize(old_str));
    let new_tokens = remove_empty(tokenize(new_str));
    let components = diff(&old_tokens, &new_tokens, max_edit_length)?;
    let mut delta = TextDelta {
        added_lines: 0,
        removed_lines: 0,
        hunks: 0,
    };
    for component in components {
        if component.added {
            delta.added_lines += component.count as u64;
        }
        if component.removed {
            delta.removed_lines += component.count as u64;
        }
        if component.added || component.removed {
            delta.hunks += 1;
        }
    }
    Some(delta)
}

fn diff(
    old_tokens: &[&str],
    new_tokens: &[&str],
    max_edit_length: usize,
) -> Option<Vec<Component>> {
    let new_len = new_tokens.len() as i64;
    let old_len = old_tokens.len() as i64;
    let mut edit_length: i64 = 1;
    let mut max_edit = new_len + old_len;
    max_edit = max_edit.min(max_edit_length as i64);

    // best_path indexed by diagonal, offset so index 0 => diagonal -(old+new).
    let offset = (old_len + new_len) as usize + 2;
    let mut best_path: Vec<Option<PathNode>> = vec![None; offset * 2 + 2];
    let idx = |diagonal: i64| -> usize { (diagonal + offset as i64) as usize };

    best_path[idx(0)] = Some(PathNode {
        old_pos: -1,
        last: None,
    });
    let seed = best_path[idx(0)].as_mut().unwrap();
    let mut new_pos = extract_common(seed, new_tokens, old_tokens, 0);
    if best_path[idx(0)].as_ref().unwrap().old_pos + 1 >= old_len && new_pos + 1 >= new_len {
        let last = best_path[idx(0)].as_ref().unwrap().last.clone();
        return Some(build_values(last));
    }

    let mut min_diagonal = i64::MIN;
    let mut max_diagonal = i64::MAX;

    while edit_length <= max_edit {
        let lower = min_diagonal.max(-edit_length);
        let upper = max_diagonal.min(edit_length);
        let mut diagonal = lower;
        while diagonal <= upper {
            let remove_path = if diagonal - 1 >= -(old_len + new_len) {
                best_path[idx(diagonal - 1)].take()
            } else {
                None
            };
            let add_path = best_path
                .get(idx(diagonal + 1))
                .and_then(|slot| slot.clone());

            let can_add = if let Some(add) = &add_path {
                let add_new_pos = add.old_pos - diagonal;
                add_new_pos >= 0 && add_new_pos < new_len
            } else {
                false
            };
            let can_remove = remove_path
                .as_ref()
                .is_some_and(|remove| remove.old_pos + 1 < old_len);

            if !can_add && !can_remove {
                best_path[idx(diagonal)] = None;
                diagonal += 2;
                continue;
            }

            let mut base_path = if !can_remove
                || (can_add
                    && remove_path
                        .as_ref()
                        .map(|remove| remove.old_pos)
                        .unwrap_or(i64::MIN)
                        < add_path.as_ref().map(|add| add.old_pos).unwrap_or(i64::MIN))
            {
                add_to_path(add_path.as_ref().unwrap(), true, false, 0)
            } else {
                add_to_path(remove_path.as_ref().unwrap(), false, true, 1)
            };

            new_pos = extract_common(&mut base_path, new_tokens, old_tokens, diagonal);

            if base_path.old_pos + 1 >= old_len && new_pos + 1 >= new_len {
                return Some(build_values(base_path.last.clone()));
            }
            if base_path.old_pos + 1 >= old_len {
                max_diagonal = max_diagonal.min(diagonal - 1);
            }
            if new_pos + 1 >= new_len {
                min_diagonal = min_diagonal.max(diagonal + 1);
            }
            best_path[idx(diagonal)] = Some(base_path);
            diagonal += 2;
        }
        edit_length += 1;
    }
    None
}
