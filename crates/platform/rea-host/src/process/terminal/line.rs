//! One buffer row, ported from xterm.js `common/buffer/BufferLine.ts`.
//!
//! Cells are three words (content, fg, bg) with side maps for combined text
//! and extended attributes, exactly like xterm. Out-of-range reads return 0
//! and out-of-range word writes are dropped, matching typed-array semantics
//! that xterm's callers rely on.

use std::collections::BTreeMap;

use super::attr::{
    Attr, BG_HAS_EXTENDED, BG_PROTECTED, CODEPOINT_MASK, Cell, ExtendedAttrs,
    HAS_CONTENT_MASK, IS_COMBINED_MASK, WIDTH_MASK, WIDTH_SHIFT, char_string,
};

const CONTENT: usize = 0;
const FG: usize = 1;
const BG: usize = 2;
const CELL_SIZE: usize = 3;

#[derive(Clone, Debug, Default)]
pub struct BufferLine {
    data: Vec<u32>,
    combined: BTreeMap<usize, String>,
    extended: BTreeMap<usize, ExtendedAttrs>,
    pub is_wrapped: bool,
}

impl BufferLine {
    pub fn new(cols: usize, fill: &Cell, is_wrapped: bool) -> Self {
        let mut line = Self {
            data: vec![0; cols * CELL_SIZE],
            combined: BTreeMap::new(),
            extended: BTreeMap::new(),
            is_wrapped,
        };
        for index in 0..cols {
            line.set_cell(index, fill);
        }
        line
    }

    pub fn len(&self) -> usize {
        self.data.len() / CELL_SIZE
    }


    fn word(&self, index: usize, slot: usize) -> u32 {
        self.data.get(index * CELL_SIZE + slot).copied().unwrap_or(0)
    }

    fn put(&mut self, index: usize, slot: usize, value: u32) {
        if let Some(word) = self.data.get_mut(index * CELL_SIZE + slot) {
            *word = value;
        }
    }

    pub fn width(&self, index: usize) -> u32 {
        self.word(index, CONTENT) >> WIDTH_SHIFT
    }

    pub fn has_width(&self, index: usize) -> bool {
        self.word(index, CONTENT) & WIDTH_MASK != 0
    }

    pub fn fg(&self, index: usize) -> u32 {
        self.word(index, FG)
    }

    pub fn bg(&self, index: usize) -> u32 {
        self.word(index, BG)
    }

    pub fn has_content(&self, index: usize) -> bool {
        self.word(index, CONTENT) & HAS_CONTENT_MASK != 0
    }

    fn is_protected(&self, index: usize) -> bool {
        self.word(index, BG) & BG_PROTECTED != 0
    }

    /// xterm `getString`: the text stored in one cell.
    pub fn string_at(&self, index: usize) -> String {
        let content = self.word(index, CONTENT);
        if content & IS_COMBINED_MASK != 0 {
            return self.combined.get(&index).cloned().unwrap_or_default();
        }
        char_string(content & CODEPOINT_MASK)
    }

    /// xterm `loadCell` into a reusable cell. Like xterm, `extended` and
    /// `combined` keep their previous values unless the flags select them.
    pub fn load_cell(&self, index: usize, cell: &mut Cell) {
        cell.content = self.word(index, CONTENT);
        cell.attr.fg = self.word(index, FG);
        cell.attr.bg = self.word(index, BG);
        if cell.content & IS_COMBINED_MASK != 0 {
            cell.combined = self.combined.get(&index).cloned().unwrap_or_default();
        }
        if cell.attr.bg & BG_HAS_EXTENDED != 0 {
            cell.attr.extended = self.extended.get(&index).copied().unwrap_or_default();
        }
    }

    pub fn set_cell(&mut self, index: usize, cell: &Cell) {
        if cell.content & IS_COMBINED_MASK != 0 {
            self.combined.insert(index, cell.combined.clone());
        }
        if cell.attr.bg & BG_HAS_EXTENDED != 0 {
            self.extended.insert(index, cell.attr.extended);
        }
        self.put(index, CONTENT, cell.content);
        self.put(index, FG, cell.attr.fg);
        self.put(index, BG, cell.attr.bg);
    }

    pub fn set_cell_from_codepoint(&mut self, index: usize, code: u32, width: u32, attr: &Attr) {
        if attr.bg & BG_HAS_EXTENDED != 0 {
            self.extended.insert(index, attr.extended);
        }
        self.put(index, CONTENT, code | (width << WIDTH_SHIFT));
        self.put(index, FG, attr.fg);
        self.put(index, BG, attr.bg);
    }

    pub fn add_codepoint_to_cell(&mut self, index: usize, code: u32, width: u32) {
        let mut content = self.word(index, CONTENT);
        if content & IS_COMBINED_MASK != 0 {
            self.combined
                .entry(index)
                .or_default()
                .push_str(&char_string(code));
        } else if content & CODEPOINT_MASK != 0 {
            let text = char_string(content & CODEPOINT_MASK) + &char_string(code);
            self.combined.insert(index, text);
            content &= !CODEPOINT_MASK;
            content |= IS_COMBINED_MASK;
        } else {
            content = code | (1 << WIDTH_SHIFT);
        }
        if width != 0 {
            content &= !WIDTH_MASK;
            content |= width << WIDTH_SHIFT;
        }
        self.put(index, CONTENT, content);
    }

    fn cell(&self, index: usize) -> Cell {
        let mut cell = Cell::default();
        self.load_cell(index, &mut cell);
        cell
    }

    pub fn insert_cells(&mut self, pos: usize, n: usize, fill: &Cell) {
        let length = self.len();
        if length == 0 {
            return;
        }
        let pos = pos % length;
        if pos != 0 && self.width(pos - 1) == 2 {
            self.set_cell_from_codepoint(pos - 1, 0, 1, &fill.attr);
        }
        if n < length - pos {
            // xterm reuses one CellData across loads, so stale combined text
            // and extended attributes carry over between copied cells.
            let mut cell = Cell::default();
            for i in (0..length - pos - n).rev() {
                self.load_cell(pos + i, &mut cell);
                self.set_cell(pos + n + i, &cell);
            }
            for i in 0..n {
                self.set_cell(pos + i, fill);
            }
        } else {
            for i in pos..length {
                self.set_cell(i, fill);
            }
        }
        if self.width(length - 1) == 2 {
            self.set_cell_from_codepoint(length - 1, 0, 1, &fill.attr);
        }
    }

    pub fn delete_cells(&mut self, pos: usize, n: usize, fill: &Cell) {
        let length = self.len();
        if length == 0 {
            return;
        }
        let pos = pos % length;
        if n < length - pos {
            let mut cell = Cell::default();
            for i in 0..length - pos - n {
                self.load_cell(pos + n + i, &mut cell);
                self.set_cell(pos + i, &cell);
            }
            for i in length - n..length {
                self.set_cell(i, fill);
            }
        } else {
            for i in pos..length {
                self.set_cell(i, fill);
            }
        }
        if pos != 0 && self.width(pos - 1) == 2 {
            self.set_cell_from_codepoint(pos - 1, 0, 1, &fill.attr);
        }
        if self.width(pos) == 0 && !self.has_content(pos) {
            self.set_cell_from_codepoint(pos, 0, 1, &fill.attr);
        }
    }

    pub fn replace_cells(&mut self, start: usize, end: usize, fill: &Cell, respect_protect: bool) {
        let length = self.len();
        let mut start = start;
        if respect_protect {
            if start != 0 && self.width(start - 1) == 2 && !self.is_protected(start - 1) {
                self.set_cell_from_codepoint(start - 1, 0, 1, &fill.attr);
            }
            if end < length && end != 0 && self.width(end - 1) == 2 && !self.is_protected(end) {
                self.set_cell_from_codepoint(end, 0, 1, &fill.attr);
            }
            while start < end && start < length {
                if !self.is_protected(start) {
                    self.set_cell(start, fill);
                }
                start += 1;
            }
            return;
        }
        if start != 0 && self.width(start - 1) == 2 {
            self.set_cell_from_codepoint(start - 1, 0, 1, &fill.attr);
        }
        if end < length && end != 0 && self.width(end - 1) == 2 {
            self.set_cell_from_codepoint(end, 0, 1, &fill.attr);
        }
        while start < end && start < length {
            self.set_cell(start, fill);
            start += 1;
        }
    }

    pub fn resize(&mut self, cols: usize, fill: &Cell) {
        let length = self.len();
        if cols == length {
            return;
        }
        if cols > length {
            self.data.resize(cols * CELL_SIZE, 0);
            for index in length..cols {
                self.set_cell(index, fill);
            }
        } else {
            self.data.truncate(cols * CELL_SIZE);
            self.combined.retain(|key, _| *key < cols);
            self.extended.retain(|key, _| *key < cols);
        }
    }

    pub fn fill(&mut self, fill: &Cell, respect_protect: bool) {
        if respect_protect {
            for index in 0..self.len() {
                if !self.is_protected(index) {
                    self.set_cell(index, fill);
                }
            }
            return;
        }
        self.combined.clear();
        self.extended.clear();
        for index in 0..self.len() {
            self.set_cell(index, fill);
        }
    }

    /// xterm `copyFrom`: replace this line with a copy of `line`.
    pub fn copy_from(&mut self, line: &Self) {
        self.clone_from(line);
    }

    pub fn trimmed_length(&self) -> usize {
        for index in (0..self.len()).rev() {
            let content = self.word(index, CONTENT);
            if content & HAS_CONTENT_MASK != 0 {
                return index + (content >> WIDTH_SHIFT) as usize;
            }
        }
        0
    }


    /// xterm `copyCellsFrom` with a distinct source line.
    pub fn copy_cells_from(
        &mut self,
        src: &Self,
        src_col: usize,
        dest_col: usize,
        length: usize,
        reverse: bool,
    ) {
        let order: Box<dyn Iterator<Item = usize>> = if reverse {
            Box::new((0..length).rev())
        } else {
            Box::new(0..length)
        };
        for cell in order {
            for slot in 0..CELL_SIZE {
                self.put(dest_col + cell, slot, src.word(src_col + cell, slot));
            }
            if src.word(src_col + cell, BG) & BG_HAS_EXTENDED != 0 {
                self.copy_extended(dest_col + cell, src.extended.get(&(src_col + cell)).copied());
            }
        }
        for (key, text) in &src.combined {
            if *key >= src_col {
                self.combined.insert(key - src_col + dest_col, text.clone());
            }
        }
    }

    /// xterm `copyCellsFrom` where source and destination are this line.
    /// Reads observe earlier writes, exactly like the aliased JS call.
    pub fn copy_cells_within(&mut self, src_col: usize, dest_col: usize, length: usize, reverse: bool) {
        let order: Box<dyn Iterator<Item = usize>> = if reverse {
            Box::new((0..length).rev())
        } else {
            Box::new(0..length)
        };
        for cell in order {
            for slot in 0..CELL_SIZE {
                let value = self.word(src_col + cell, slot);
                self.put(dest_col + cell, slot, value);
            }
            if self.word(src_col + cell, BG) & BG_HAS_EXTENDED != 0 {
                let value = self.extended.get(&(src_col + cell)).copied();
                self.copy_extended(dest_col + cell, value);
            }
        }
        let keys: Vec<usize> = self.combined.keys().copied().collect();
        for key in keys {
            if key >= src_col {
                let text = self.combined.get(&key).cloned();
                match text {
                    Some(text) => {
                        self.combined.insert(key - src_col + dest_col, text);
                    }
                    None => {
                        self.combined.remove(&(key - src_col + dest_col));
                    }
                }
            }
        }
    }

    fn copy_extended(&mut self, index: usize, value: Option<ExtendedAttrs>) {
        match value {
            Some(value) => {
                self.extended.insert(index, value);
            }
            None => {
                self.extended.remove(&index);
            }
        }
    }

    /// xterm `translateToString(trimRight, startCol, endCol)`.
    pub fn translate_to_string(&self, trim_right: bool, start: usize, end: Option<usize>) -> String {
        let mut end = end.unwrap_or(self.len());
        if trim_right {
            end = end.min(self.trimmed_length());
        }
        let mut result = String::new();
        let mut column = start;
        while column < end {
            let content = self.word(column, CONTENT);
            let code = content & CODEPOINT_MASK;
            if content & IS_COMBINED_MASK != 0 {
                result.push_str(self.combined.get(&column).map_or("", String::as_str));
            } else if code != 0 {
                result.push_str(&char_string(code));
            } else {
                result.push(' ');
            }
            column += ((content >> WIDTH_SHIFT) as usize).max(1);
        }
        result
    }

    /// Public `getCell(x)` view used by the serializer.
    pub fn api_cell(&self, index: usize) -> Option<Cell> {
        (index < self.len()).then(|| self.cell(index))
    }
}
