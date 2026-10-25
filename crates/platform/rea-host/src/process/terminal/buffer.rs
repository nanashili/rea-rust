//! One screen buffer (normal or alternate), ported from xterm.js
//! `common/buffer/Buffer.ts`: viewport/scrollback ring, cursor, scroll region,
//! tab stops, saved cursor, and resize with reflow.

use std::collections::BTreeSet;

use super::attr::{Attr, Cell};
use super::circular::CircularList;
use super::line::BufferLine;
use super::reflow;

/// Saved cursor state (DECSC): position, colors and charset.
#[derive(Clone, Copy, Debug, Default)]
pub struct SavedCursor {
    pub x: isize,
    pub y: isize,
    pub fg: u32,
    pub bg: u32,
    pub charset: Option<u8>,
}

#[derive(Debug)]
pub struct Buffer {
    pub lines: CircularList,
    pub ydisp: isize,
    pub ybase: isize,
    pub y: isize,
    pub x: isize,
    pub scroll_top: isize,
    pub scroll_bottom: isize,
    pub tabs: BTreeSet<isize>,
    pub saved: SavedCursor,
    has_scrollback: bool,
    scrollback: usize,
    cols: usize,
    rows: usize,
}

const TAB_STOP_WIDTH: isize = 8;

impl Buffer {
    pub fn new(has_scrollback: bool, scrollback: usize, cols: usize, rows: usize) -> Self {
        let mut buffer = Self {
            lines: CircularList::new(buffer_length(has_scrollback, scrollback, rows)),
            ydisp: 0,
            ybase: 0,
            y: 0,
            x: 0,
            scroll_top: 0,
            scroll_bottom: rows as isize - 1,
            tabs: BTreeSet::new(),
            saved: SavedCursor::default(),
            has_scrollback,
            scrollback,
            cols,
            rows,
        };
        buffer.setup_tab_stops(None);
        buffer
    }

    pub fn blank_line(&self, cols: usize, attr: &Attr, is_wrapped: bool) -> BufferLine {
        BufferLine::new(cols, &Cell::null(*attr), is_wrapped)
    }

    pub fn line(&self, index: isize) -> Option<&BufferLine> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.lines.get(index))
    }

    pub fn line_mut(&mut self, index: isize) -> Option<&mut BufferLine> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.lines.get_mut(index))
    }

    pub fn fill_viewport_rows(&mut self, attr: &Attr) {
        if self.lines.is_empty() {
            for _ in 0..self.rows {
                let line = self.blank_line(self.cols, attr, false);
                self.lines.push(line);
            }
        }
    }

    pub fn clear(&mut self) {
        self.ydisp = 0;
        self.ybase = 0;
        self.y = 0;
        self.x = 0;
        self.lines = CircularList::new(buffer_length(
            self.has_scrollback,
            self.scrollback,
            self.rows,
        ));
        self.scroll_top = 0;
        self.scroll_bottom = self.rows as isize - 1;
        self.setup_tab_stops(None);
    }

    pub fn setup_tab_stops(&mut self, from: Option<isize>) {
        let mut i = match from {
            Some(i) => {
                if self.tabs.contains(&i) {
                    i
                } else {
                    self.prev_stop(i)
                }
            }
            None => {
                self.tabs.clear();
                0
            }
        };
        while i < self.cols as isize {
            self.tabs.insert(i);
            i += TAB_STOP_WIDTH;
        }
    }

    pub fn prev_stop(&self, x: isize) -> isize {
        let mut x = x;
        loop {
            x -= 1;
            if self.tabs.contains(&x) || x <= 0 {
                break;
            }
        }
        self.clamp_stop(x)
    }

    pub fn next_stop(&self, x: isize) -> isize {
        let mut x = x;
        loop {
            x += 1;
            if self.tabs.contains(&x) || x >= self.cols as isize {
                break;
            }
        }
        self.clamp_stop(x)
    }

    fn clamp_stop(&self, x: isize) -> isize {
        let cols = self.cols as isize;
        if x >= cols {
            cols - 1
        } else if x < 0 {
            0
        } else {
            x
        }
    }

    pub fn resize(&mut self, new_cols: usize, new_rows: usize) {
        let null = Cell::null(Attr::default());
        let new_max = buffer_length(self.has_scrollback, self.scrollback, new_rows);
        if new_max > self.lines.max_length() {
            self.lines.set_max_length(new_max);
        }
        if !self.lines.is_empty() {
            if self.cols < new_cols {
                for index in 0..self.lines.len() {
                    if let Some(line) = self.lines.get_mut(index) {
                        line.resize(new_cols, &null);
                    }
                }
            }
            let mut add_to_y = 0;
            if self.rows < new_rows {
                for _ in self.rows..new_rows {
                    if (self.lines.len() as isize) < new_rows as isize + self.ybase {
                        if self.ybase > 0
                            && self.lines.len() as isize <= self.ybase + self.y + add_to_y + 1
                        {
                            self.ybase -= 1;
                            add_to_y += 1;
                            if self.ydisp > 0 {
                                self.ydisp -= 1;
                            }
                        } else {
                            self.lines.push(BufferLine::new(new_cols, &null, false));
                        }
                    }
                }
            } else {
                for _ in (new_rows + 1..=self.rows).rev() {
                    if self.lines.len() as isize > new_rows as isize + self.ybase {
                        if self.lines.len() as isize > self.ybase + self.y + 1 {
                            self.lines.pop();
                        } else {
                            self.ybase += 1;
                            self.ydisp += 1;
                        }
                    }
                }
            }
            if new_max < self.lines.max_length() {
                let trim = self.lines.len() as isize - new_max as isize;
                if trim > 0 {
                    self.lines.trim_start(trim as usize);
                    self.ybase = (self.ybase - trim).max(0);
                    self.ydisp = (self.ydisp - trim).max(0);
                    self.saved.y = (self.saved.y - trim).max(0);
                }
                self.lines.set_max_length(new_max);
            }
            self.x = self.x.min(new_cols as isize - 1);
            self.y = self.y.min(new_rows as isize - 1);
            if add_to_y != 0 {
                self.y += add_to_y;
            }
            self.saved.x = self.saved.x.min(new_cols as isize - 1);
            self.scroll_top = 0;
        }
        self.scroll_bottom = new_rows as isize - 1;
        if self.has_scrollback {
            self.reflow(new_cols, new_rows);
            if self.cols > new_cols {
                for index in 0..self.lines.len() {
                    if let Some(line) = self.lines.get_mut(index) {
                        line.resize(new_cols, &null);
                    }
                }
            }
        }
        self.cols = new_cols;
        self.rows = new_rows;
    }

    fn reflow(&mut self, new_cols: usize, new_rows: usize) {
        if self.cols == new_cols {
            return;
        }
        if new_cols > self.cols {
            self.reflow_larger(new_cols, new_rows);
        } else {
            self.reflow_smaller(new_cols, new_rows);
        }
    }

    fn reflow_larger(&mut self, new_cols: usize, new_rows: usize) {
        let null = Cell::null(Attr::default());
        let to_remove = reflow::larger_lines_to_remove(
            &mut self.lines,
            self.cols,
            new_cols,
            self.ybase + self.y,
            &null,
        );
        if !to_remove.is_empty() {
            let (layout, removed) = reflow::larger_new_layout(self.lines.len(), &to_remove);
            reflow::larger_apply_layout(&mut self.lines, &layout);
            self.reflow_larger_adjust_viewport(new_cols, new_rows, removed);
        }
    }

    fn reflow_larger_adjust_viewport(&mut self, new_cols: usize, new_rows: usize, removed: usize) {
        let null = Cell::null(Attr::default());
        for _ in 0..removed {
            if self.ybase == 0 {
                if self.y > 0 {
                    self.y -= 1;
                }
                if self.lines.len() < new_rows {
                    self.lines.push(BufferLine::new(new_cols, &null, false));
                }
            } else {
                if self.ydisp == self.ybase {
                    self.ydisp -= 1;
                }
                self.ybase -= 1;
            }
        }
        self.saved.y = (self.saved.y - removed as isize).max(0);
    }

    fn reflow_smaller(&mut self, new_cols: usize, new_rows: usize) {
        let null = Cell::null(Attr::default());
        let old_cols = self.cols;
        // (insert position, new lines) in descending position order.
        let mut to_insert: Vec<(usize, Vec<BufferLine>)> = Vec::new();
        let mut count_to_insert = 0usize;
        let mut y = self.lines.len() as isize - 1;
        while y >= 0 {
            let Some(next) = self.lines.get(y as usize) else {
                y -= 1;
                continue;
            };
            if !next.is_wrapped && next.trimmed_length() <= new_cols {
                y -= 1;
                continue;
            }
            let last = y as usize;
            while self
                .lines
                .get(y as usize)
                .is_some_and(|line| line.is_wrapped)
                && y > 0
            {
                y -= 1;
            }
            let first = y as usize;
            let group_len = last - first + 1;
            let absolute_y = self.ybase + self.y;
            if absolute_y >= first as isize && absolute_y < (first + group_len) as isize {
                y -= 1;
                continue;
            }
            let mut wrapped: Vec<BufferLine> = (first..=last)
                .map(|index| self.lines.take(index).unwrap_or_default())
                .collect();
            let last_line_length = wrapped[wrapped.len() - 1].trimmed_length();
            let dest_lengths = reflow::smaller_new_line_lengths(&wrapped, old_cols, new_cols);
            let lines_to_add = dest_lengths.len() as isize - wrapped.len() as isize;
            let trimmed_lines = if self.ybase == 0 && self.y != self.lines.len() as isize - 1 {
                (self.y - self.lines.max_length() as isize + lines_to_add).max(0)
            } else {
                (self.lines.len() as isize - self.lines.max_length() as isize + lines_to_add).max(0)
            };
            let added = lines_to_add.max(0) as usize;
            for _ in 0..added {
                wrapped.push(BufferLine::new(new_cols, &null, true));
            }
            reflow::smaller_copy(
                &mut wrapped,
                &dest_lengths,
                last_line_length,
                old_cols,
                added,
            );
            for (index, line) in wrapped.iter_mut().enumerate() {
                if let Some(&length) = dest_lengths.get(index)
                    && length < new_cols
                {
                    line.set_cell(length, &null);
                }
            }
            let new_lines = wrapped.split_off(group_len);
            for (offset, line) in wrapped.into_iter().enumerate() {
                self.lines.set(first + offset, Some(line));
            }
            if !new_lines.is_empty() {
                to_insert.push((first + group_len + count_to_insert, new_lines));
                count_to_insert += added;
            }
            let mut adjustments = lines_to_add - trimmed_lines;
            while adjustments > 0 {
                adjustments -= 1;
                if self.ybase == 0 {
                    if self.y < new_rows as isize - 1 {
                        self.y += 1;
                        self.lines.pop();
                    } else {
                        self.ybase += 1;
                        self.ydisp += 1;
                    }
                } else {
                    let limit = self
                        .lines
                        .max_length()
                        .min(self.lines.len() + count_to_insert)
                        as isize
                        - new_rows as isize;
                    if self.ybase < limit {
                        if self.ybase == self.ydisp {
                            self.ydisp += 1;
                        }
                        self.ybase += 1;
                    }
                }
            }
            self.saved.y = (self.saved.y + lines_to_add).min(self.ybase + new_rows as isize - 1);
            y -= 1;
        }
        if !to_insert.is_empty() {
            let original_length = self.lines.len();
            let mut original: Vec<Option<BufferLine>> = (0..original_length)
                .map(|index| self.lines.take(index))
                .collect();
            let mut original_index = original_length as isize - 1;
            let mut inserts = to_insert.into_iter();
            let mut next = inserts.next();
            let max = self.lines.max_length();
            self.lines
                .set_len(max.min(original_length + count_to_insert));
            let mut inserted = 0usize;
            let mut i = (max as isize - 1).min((original_length + count_to_insert) as isize - 1);
            while i >= 0 {
                let insert_here = next
                    .as_ref()
                    .is_some_and(|(start, _)| *start as isize > original_index + inserted as isize);
                if insert_here {
                    let (_, new_lines) = next.take().unwrap_or_default();
                    inserted += new_lines.len();
                    for line in new_lines.into_iter().rev() {
                        self.lines.set(i as usize, Some(line));
                        i -= 1;
                    }
                    i += 1;
                    next = inserts.next();
                } else {
                    let line = usize::try_from(original_index)
                        .ok()
                        .and_then(|index| original.get_mut(index))
                        .and_then(Option::take);
                    self.lines.set(i as usize, line);
                    original_index -= 1;
                }
                i -= 1;
            }
        }
    }
}

fn buffer_length(has_scrollback: bool, scrollback: usize, rows: usize) -> usize {
    if has_scrollback {
        (rows + scrollback).min(4_294_967_295)
    } else {
        rows
    }
}
