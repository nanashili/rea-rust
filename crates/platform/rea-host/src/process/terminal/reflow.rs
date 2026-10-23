//! Soft-wrap reflow on column resize, ported from xterm.js
//! `common/buffer/BufferReflow.ts` and the copy loop of
//! `Buffer._reflowSmaller`. Lines holding the cursor are not reflowed
//! (xterm's default `reflowCursorLine: false`).

use super::attr::Cell;
use super::circular::CircularList;
use super::line::BufferLine;

/// `copyCellsFrom` between two entries of one wrapped group (possibly the same).
fn copy_between(
    lines: &mut [BufferLine],
    dest: usize,
    src: usize,
    src_col: usize,
    dest_col: usize,
    length: usize,
    reverse: bool,
) {
    if dest == src {
        lines[dest].copy_cells_within(src_col, dest_col, length, reverse);
    } else if dest < src {
        let (head, tail) = lines.split_at_mut(src);
        head[dest].copy_cells_from(&tail[0], src_col, dest_col, length, reverse);
    } else {
        let (head, tail) = lines.split_at_mut(dest);
        tail[0].copy_cells_from(&head[src], src_col, dest_col, length, reverse);
    }
}

pub fn wrapped_trimmed_length(lines: &[BufferLine], index: usize, cols: usize) -> usize {
    if index == lines.len() - 1 {
        return lines[index].trimmed_length();
    }
    let ends_in_null = !lines[index].has_content(cols - 1) && lines[index].width(cols - 1) == 1;
    let next_starts_wide = lines[index + 1].width(0) == 2;
    if ends_in_null && next_starts_wide {
        return cols - 1;
    }
    cols
}

/// `reflowLargerGetLinesToRemove`: pull wrapped content up into wider rows
/// (mutating `lines`) and return `[index, count, ...]` of emptied rows.
pub fn larger_lines_to_remove(
    lines: &mut CircularList,
    old_cols: usize,
    new_cols: usize,
    cursor_absolute_y: isize,
    null: &Cell,
) -> Vec<usize> {
    let mut to_remove = Vec::new();
    let mut y = 0usize;
    while y + 1 < lines.len() {
        let mut i = y + 1;
        if !lines.get(i).is_some_and(|line| line.is_wrapped) {
            y += 1;
            continue;
        }
        while i < lines.len() && lines.get(i).is_some_and(|line| line.is_wrapped) {
            i += 1;
        }
        let group_len = i - y;
        if cursor_absolute_y >= y as isize && cursor_absolute_y < i as isize {
            y += group_len;
            continue;
        }
        let mut wrapped: Vec<BufferLine> =
            (y..i).map(|index| lines.take(index).unwrap_or_default()).collect();
        let mut dest_index = 0usize;
        let mut dest_col = wrapped_trimmed_length(&wrapped, dest_index, old_cols);
        let mut src_index = 1usize;
        let mut src_col = 0usize;
        while src_index < wrapped.len() {
            let src_trimmed = wrapped_trimmed_length(&wrapped, src_index, old_cols);
            let src_remaining = src_trimmed.saturating_sub(src_col);
            let dest_remaining = new_cols.saturating_sub(dest_col);
            let cells = src_remaining.min(dest_remaining);
            copy_between(&mut wrapped, dest_index, src_index, src_col, dest_col, cells, false);
            dest_col += cells;
            if dest_col == new_cols {
                dest_index += 1;
                dest_col = 0;
            }
            src_col += cells;
            if src_col == src_trimmed {
                src_index += 1;
                src_col = 0;
            }
            if dest_col == 0 && dest_index != 0 && wrapped[dest_index - 1].width(new_cols - 1) == 2 {
                copy_between(&mut wrapped, dest_index, dest_index - 1, new_cols - 1, dest_col, 1, false);
                dest_col += 1;
                wrapped[dest_index - 1].set_cell(new_cols - 1, null);
            }
        }
        wrapped[dest_index].replace_cells(dest_col, new_cols, null, false);
        let mut count = 0;
        for index in (1..wrapped.len()).rev() {
            if index > dest_index || wrapped[index].trimmed_length() == 0 {
                count += 1;
            } else {
                break;
            }
        }
        if count > 0 {
            to_remove.push(y + wrapped.len() - count);
            to_remove.push(count);
        }
        for (offset, line) in wrapped.into_iter().enumerate() {
            lines.set(y + offset, Some(line));
        }
        y += group_len;
    }
    to_remove
}

/// `reflowLargerCreateNewLayout`: surviving line indices and removed count.
pub fn larger_new_layout(length: usize, to_remove: &[usize]) -> (Vec<usize>, usize) {
    let mut layout = Vec::new();
    let mut next = 0;
    let mut removed = 0;
    let mut i = 0;
    while i < length {
        if to_remove.get(next) == Some(&i) {
            let count = to_remove[next + 1];
            i += count;
            removed += count;
            next += 2;
        } else {
            layout.push(i);
            i += 1;
        }
    }
    (layout, removed)
}

pub fn larger_apply_layout(lines: &mut CircularList, layout: &[usize]) {
    let moved: Vec<Option<BufferLine>> = layout.iter().map(|&index| lines.take(index)).collect();
    for (index, line) in moved.into_iter().enumerate() {
        lines.set(index, line);
    }
    lines.set_len(layout.len());
}

/// `reflowSmallerGetNewLineLengths`.
pub fn smaller_new_line_lengths(wrapped: &[BufferLine], old_cols: usize, new_cols: usize) -> Vec<usize> {
    let needed: usize = (0..wrapped.len())
        .map(|index| wrapped_trimmed_length(wrapped, index, old_cols))
        .sum();
    let mut lengths = Vec::new();
    let mut src_col = 0usize;
    let mut src_line = 0usize;
    let mut available = 0usize;
    while available < needed {
        if needed - available < new_cols {
            lengths.push(needed - available);
            break;
        }
        src_col += new_cols;
        let old_trimmed = wrapped_trimmed_length(wrapped, src_line, old_cols);
        if src_col > old_trimmed {
            src_col -= old_trimmed;
            src_line += 1;
        }
        let ends_wide = src_col > 0
            && wrapped.get(src_line).is_some_and(|line| line.width(src_col - 1) == 2);
        if ends_wide {
            src_col -= 1;
        }
        let length = if ends_wide { new_cols - 1 } else { new_cols };
        lengths.push(length);
        available += length;
    }
    lengths
}

/// The reverse copy loop of `_reflowSmaller` over one wrapped group whose
/// last `added` entries are freshly inserted blank wrapped lines.
pub fn smaller_copy(
    wrapped: &mut [BufferLine],
    dest_lengths: &[usize],
    last_line_length: usize,
    old_cols: usize,
    added: usize,
) {
    let length_at = |index: isize| -> Option<usize> {
        usize::try_from(index).ok().and_then(|index| dest_lengths.get(index).copied())
    };
    let mut dest_index = dest_lengths.len() as isize - 1;
    let Some(mut dest_col) = length_at(dest_index) else {
        return;
    };
    if dest_col == 0 {
        dest_index -= 1;
        let Some(col) = length_at(dest_index) else {
            return;
        };
        dest_col = col;
    }
    let mut src_index = wrapped.len() as isize - added as isize - 1;
    let mut src_col = last_line_length;
    while src_index >= 0 {
        let cells = src_col.min(dest_col);
        let Ok(dest) = usize::try_from(dest_index) else {
            break;
        };
        if dest >= wrapped.len() {
            break;
        }
        copy_between(
            wrapped,
            dest,
            src_index as usize,
            src_col - cells,
            dest_col - cells,
            cells,
            true,
        );
        dest_col -= cells;
        if dest_col == 0 {
            dest_index -= 1;
            dest_col = length_at(dest_index).unwrap_or(0);
        }
        src_col -= cells;
        if src_col == 0 {
            src_index -= 1;
            let index = src_index.max(0) as usize;
            src_col = wrapped_trimmed_length(wrapped, index, old_cols);
        }
    }
}
