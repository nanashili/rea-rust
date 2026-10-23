//! Terminal core: xterm.js `InputHandler` actions over `BufferService`,
//! `BufferSet`, `CoreService`, `CharsetService` and mouse-mode state, with
//! headless xterm 6.0.0 default options (scrollback from the caller,
//! `tabStopWidth` 8, `convertEol` false, no window options, not Windows).
//!
//! Responses xterm emits on its input channel (DA, DSR, DECRQM, DECRQSS,
//! window reports) and events with no screen effect (bell, title, colors)
//! are not modeled: a headless observer never feeds them back to the child.

use super::attr::{
    Attr, BG_DIM, BG_ITALIC, BG_OVERLINE, BG_PROTECTED, CM_MASK, CM_P16, CM_P256, CM_RGB, Cell,
    FG_BLINK, FG_BOLD, FG_INVERSE, FG_INVISIBLE, FG_STRIKETHROUGH, FG_UNDERLINE, PCOLOR_MASK,
    RGB_MASK, UNDERLINE_DOUBLE, UNDERLINE_NONE, UNDERLINE_SINGLE, WIDTH_SHIFT,
};
use super::buffer::Buffer;
use super::charsets;
use super::line::BufferLine;
use super::params::Params;
use super::parser::Perform;
use super::serialize::SerializedModes;
use super::unicode;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MouseProtocol {
    #[default]
    None,
    X10,
    Vt200,
    Drag,
    Any,
}

#[derive(Clone, Copy, Debug)]
struct DecModes {
    application_cursor_keys: bool,
    application_keypad: bool,
    bracketed_paste: bool,
    origin: bool,
    reverse_wraparound: bool,
    send_focus: bool,
    wraparound: bool,
}

impl Default for DecModes {
    fn default() -> Self {
        Self {
            application_cursor_keys: false,
            application_keypad: false,
            bracketed_paste: false,
            origin: false,
            reverse_wraparound: false,
            send_focus: false,
            wraparound: true,
        }
    }
}

/// `CharsetService`: G0..G3 designations and the active charset flag.
#[derive(Clone, Copy, Debug, Default)]
struct Charsets {
    charset: Option<u8>,
    glevel: usize,
    designated: [Option<u8>; 4],
}

impl Charsets {
    fn set_glevel(&mut self, level: usize) {
        self.glevel = level;
        self.charset = self.designated.get(level).copied().flatten();
    }
    fn set_gcharset(&mut self, level: usize, charset: Option<u8>) {
        if let Some(slot) = self.designated.get_mut(level) {
            *slot = charset;
        }
        if self.glevel == level {
            self.charset = charset;
        }
    }
}

/// Upper bound on code points one REP (`CSI b`) prints.
const MAX_REPEAT_CODES: usize = 1 << 20;

/// Where the row a wrapping `print` left went after the buffer scrolled.
enum OldRow {
    Index(isize),
    Detached(Box<BufferLine>),
}

pub struct Core {
    pub cols: usize,
    pub rows: usize,
    scrollback: usize,
    pub normal: Buffer,
    pub alt: Buffer,
    pub alt_active: bool,
    cached_blank: Option<BufferLine>,
    pub cur_attr: Attr,
    erase_attr: Attr,
    charsets: Charsets,
    insert_mode: bool,
    convert_eol: bool,
    dec: DecModes,
    mouse: MouseProtocol,
    join_state: u32,
}

impl Core {
    pub fn new(cols: usize, rows: usize, scrollback: usize) -> Self {
        let cols = cols.max(2);
        let rows = rows.max(1);
        let (normal, alt) = new_buffers(cols, rows, scrollback);
        Self {
            cols,
            rows,
            scrollback,
            normal,
            alt,
            alt_active: false,
            cached_blank: None,
            cur_attr: Attr::default(),
            erase_attr: Attr::default(),
            charsets: Charsets::default(),
            insert_mode: false,
            convert_eol: false,
            dec: DecModes::default(),
            mouse: MouseProtocol::None,
            join_state: 0,
        }
    }

    pub fn buffer(&self) -> &Buffer {
        if self.alt_active { &self.alt } else { &self.normal }
    }

    fn buf(&mut self) -> &mut Buffer {
        if self.alt_active {
            &mut self.alt
        } else {
            &mut self.normal
        }
    }

    pub fn modes(&self) -> SerializedModes {
        SerializedModes {
            application_cursor_keys: self.dec.application_cursor_keys,
            application_keypad: self.dec.application_keypad,
            bracketed_paste: self.dec.bracketed_paste,
            insert: self.insert_mode,
            origin: self.dec.origin,
            reverse_wraparound: self.dec.reverse_wraparound,
            send_focus: self.dec.send_focus,
            wraparound: self.dec.wraparound,
            mouse_tracking: match self.mouse {
                MouseProtocol::None => None,
                MouseProtocol::X10 => Some(9),
                MouseProtocol::Vt200 => Some(1000),
                MouseProtocol::Drag => Some(1002),
                MouseProtocol::Any => Some(1003),
            },
        }
    }

    /// Headless `Terminal.resize` (same-size no-op, minimum 2x1).
    pub fn resize(&mut self, cols: usize, rows: usize) {
        if cols == self.cols && rows == self.rows {
            return;
        }
        let cols = cols.max(2);
        let rows = rows.max(1);
        self.cols = cols;
        self.rows = rows;
        self.normal.resize(cols, rows);
        self.alt.resize(cols, rows);
        self.normal.setup_tab_stops(Some(cols as isize));
        self.alt.setup_tab_stops(Some(cols as isize));
    }

    /// `Terminal.reset` (RIS): new buffers, default attributes and modes.
    fn full_reset(&mut self) {
        self.join_state = 0;
        self.cur_attr = Attr::default();
        self.erase_attr = Attr::default();
        let (normal, alt) = new_buffers(self.cols, self.rows, self.scrollback);
        self.normal = normal;
        self.alt = alt;
        self.alt_active = false;
        self.charsets = Charsets::default();
        self.insert_mode = false;
        self.dec = DecModes::default();
        self.mouse = MouseProtocol::None;
    }

    fn erase_attr(&mut self) -> Attr {
        self.erase_attr.bg &= !(CM_MASK | 0xFF_FFFF);
        self.erase_attr.bg |= self.cur_attr.bg & !0xFC00_0000;
        self.erase_attr
    }

    fn row_index(&self) -> isize {
        let buffer = self.buffer();
        buffer.ybase + buffer.y
    }

    /// `BufferService.scroll`; returns where the old bottom row of the scroll
    /// region now lives, or `None` if the scroll dropped it.
    fn scroll(&mut self, erase: Attr, is_wrapped: bool) -> Option<isize> {
        let cols = self.cols;
        let reuse = self.cached_blank.as_ref().is_some_and(|line| {
            line.len() == cols && line.fg(0) == erase.fg && line.bg(0) == erase.bg
        });
        if !reuse {
            self.cached_blank = Some(BufferLine::new(cols, &Cell::null(erase), is_wrapped));
        }
        let mut new_line = self.cached_blank.clone().unwrap_or_default();
        new_line.is_wrapped = is_wrapped;
        if let Some(cached) = self.cached_blank.as_mut() {
            cached.is_wrapped = is_wrapped;
        }
        let buffer = self.buf();
        let top_row = buffer.ybase + buffer.scroll_top;
        let bottom_row = buffer.ybase + buffer.scroll_bottom;
        let moved;
        if buffer.scroll_top == 0 {
            let will_trim = buffer.lines.is_full();
            if bottom_row == buffer.lines.len() as isize - 1 {
                if will_trim {
                    if let Some(line) = buffer.lines.recycle() {
                        line.copy_from(&new_line);
                    }
                    moved = Some((bottom_row - 1).max(0));
                } else {
                    buffer.lines.push(new_line);
                    moved = Some(bottom_row);
                }
            } else {
                let trimmed = (buffer.lines.len() + 1).saturating_sub(buffer.lines.max_length());
                buffer.lines.splice((bottom_row + 1) as usize, 0, vec![new_line]);
                moved = Some(bottom_row - trimmed as isize);
            }
            if !will_trim {
                buffer.ybase += 1;
                buffer.ydisp += 1;
            }
        } else {
            let height = bottom_row - top_row + 1;
            buffer.lines.shift_elements((top_row + 1) as usize, height - 1, -1);
            buffer.lines.set(bottom_row as usize, Some(new_line));
            moved = (height > 1).then_some(bottom_row - 1);
        }
        buffer.ydisp = buffer.ybase;
        moved
    }

    fn print_codes(&mut self, data: &[u32]) {
        let cols = self.cols as isize;
        let wraparound = self.dec.wraparound;
        let insert = self.insert_mode;
        let cur = self.cur_attr;
        let mut row = self.row_index();
        {
            let x = self.buffer().x;
            if let Some(line) = self.buf().line_mut(row)
                && x != 0
                && !data.is_empty()
                && line.width((x - 1) as usize) == 2
            {
                line.set_cell_from_codepoint((x - 1) as usize, 0, 1, &cur);
            }
        }
        let mut preceding = self.join_state;
        for &original in data {
            let mut code = original;
            if code < 127
                && let Some(flag) = self.charsets.charset
                && let Some(mapped) = charsets::map(flag, code)
            {
                code = mapped;
            }
            let info = unicode::char_properties(code, preceding);
            let mut width = unicode::extract_width(info) as isize;
            let should_join = unicode::extract_should_join(info);
            let old_width = if should_join {
                unicode::extract_width(preceding) as isize
            } else {
                0
            };
            preceding = info;
            if self.buffer().x + width - old_width > cols {
                if wraparound {
                    let old_index = row;
                    let mut old_col = self.buffer().x - old_width;
                    let detached = self.buffer().line(old_index).cloned();
                    self.buf().x = old_width;
                    self.buf().y += 1;
                    let old_row;
                    if self.buffer().y == self.buffer().scroll_bottom + 1 {
                        self.buf().y -= 1;
                        let erase = self.erase_attr();
                        old_row = match self.scroll(erase, true) {
                            Some(index) => OldRow::Index(index),
                            None => OldRow::Detached(Box::new(detached.unwrap_or_default())),
                        };
                    } else {
                        if self.buffer().y >= self.rows as isize {
                            self.buf().y = self.rows as isize - 1;
                        }
                        let index = self.row_index();
                        if let Some(line) = self.buf().line_mut(index) {
                            line.is_wrapped = true;
                        }
                        old_row = OldRow::Index(old_index);
                    }
                    row = self.row_index();
                    let old_cols = self.cols;
                    match old_row {
                        OldRow::Index(index) => {
                            let buffer = self.buf();
                            if old_width > 0 {
                                copy_rows(buffer, index, row, old_col.max(0) as usize, old_width as usize);
                            }
                            if let Some(line) = buffer.line_mut(index) {
                                while old_col < old_cols as isize {
                                    if old_col >= 0 {
                                        line.set_cell_from_codepoint(old_col as usize, 0, 1, &cur);
                                    }
                                    old_col += 1;
                                }
                            }
                        }
                        OldRow::Detached(source) => {
                            if old_width > 0
                                && let Some(line) = self.buf().line_mut(row)
                            {
                                line.copy_cells_from(&source, old_col.max(0) as usize, 0, old_width as usize, false);
                            }
                        }
                    }
                } else {
                    self.buf().x = cols - 1;
                    if width == 2 {
                        continue;
                    }
                }
            }
            let x = self.buffer().x;
            if should_join && x != 0 {
                let buffer = self.buf();
                if let Some(line) = buffer.line_mut(row) {
                    let offset = if line.width((x - 1) as usize) != 0 { 1 } else { 2 };
                    if x - offset >= 0 {
                        line.add_codepoint_to_cell((x - offset) as usize, code, width as u32);
                    }
                    let mut x = x;
                    for _ in 0..(width - old_width).max(0) {
                        line.set_cell_from_codepoint(x as usize, 0, 0, &cur);
                        x += 1;
                    }
                    buffer.x = x;
                }
                continue;
            }
            let buffer = self.buf();
            let Some(line) = buffer.line_mut(row) else {
                continue;
            };
            if insert {
                line.insert_cells(x as usize, (width - old_width).max(0) as usize, &Cell::null(cur));
                if line.width(cols as usize - 1) == 2 {
                    line.set_cell_from_codepoint(cols as usize - 1, 0, 1, &cur);
                }
            }
            let mut x = x;
            line.set_cell_from_codepoint(x as usize, code, width as u32, &cur);
            x += 1;
            if width > 0 {
                width -= 1;
                while width > 0 {
                    line.set_cell_from_codepoint(x as usize, 0, 0, &cur);
                    x += 1;
                    width -= 1;
                }
            }
            buffer.x = x;
        }
        self.join_state = preceding;
        let x = self.buffer().x;
        if x < cols
            && !data.is_empty()
            && let Some(line) = self.buf().line_mut(row)
            && line.width(x as usize) == 0
            && !line.has_content(x as usize)
        {
            line.set_cell_from_codepoint(x as usize, 0, 1, &cur);
        }
    }

    fn line_feed(&mut self) {
        if self.convert_eol {
            self.buf().x = 0;
        }
        self.buf().y += 1;
        let rows = self.rows as isize;
        if self.buffer().y == self.buffer().scroll_bottom + 1 {
            self.buf().y -= 1;
            let erase = self.erase_attr();
            self.scroll(erase, false);
        } else if self.buffer().y >= rows {
            self.buf().y = rows - 1;
        } else {
            let index = self.row_index();
            if let Some(line) = self.buf().line_mut(index) {
                line.is_wrapped = false;
            }
        }
        if self.buffer().x >= self.cols as isize {
            self.buf().x -= 1;
        }
    }

    fn restrict_cursor(&mut self, max_col: Option<isize>) {
        let max_col = max_col.unwrap_or(self.cols as isize - 1);
        let origin = self.dec.origin;
        let rows = self.rows as isize;
        let buffer = self.buf();
        buffer.x = max_col.min(buffer.x.max(0));
        buffer.y = if origin {
            buffer.scroll_bottom.min(buffer.y.max(buffer.scroll_top))
        } else {
            (rows - 1).min(buffer.y.max(0))
        };
    }

    fn set_cursor(&mut self, x: isize, y: isize) {
        let origin = self.dec.origin;
        let buffer = self.buf();
        buffer.x = x;
        buffer.y = if origin { buffer.scroll_top + y } else { y };
        self.restrict_cursor(None);
    }

    fn move_cursor(&mut self, x: isize, y: isize) {
        self.restrict_cursor(None);
        let (bx, by) = (self.buffer().x, self.buffer().y);
        self.set_cursor(bx + x, by + y);
    }

    fn backspace(&mut self) {
        if !self.dec.reverse_wraparound {
            self.restrict_cursor(None);
            if self.buffer().x > 0 {
                self.buf().x -= 1;
            }
            return;
        }
        self.restrict_cursor(Some(self.cols as isize));
        if self.buffer().x > 0 {
            self.buf().x -= 1;
        } else {
            let index = self.row_index();
            let cols = self.cols as isize;
            let buffer = self.buf();
            let wrapped = buffer.line(index).is_some_and(|line| line.is_wrapped);
            if buffer.x == 0 && buffer.y > buffer.scroll_top && buffer.y <= buffer.scroll_bottom && wrapped {
                if let Some(line) = buffer.line_mut(index) {
                    line.is_wrapped = false;
                }
                buffer.y -= 1;
                buffer.x = cols - 1;
                let index = buffer.ybase + buffer.y;
                let x = buffer.x;
                if buffer
                    .line(index)
                    .is_some_and(|line| line.has_width(x as usize) && !line.has_content(x as usize))
                {
                    buffer.x -= 1;
                }
            }
        }
        self.restrict_cursor(None);
    }

    fn tab(&mut self) {
        if self.buffer().x >= self.cols as isize {
            return;
        }
        let next = self.buffer().next_stop(self.buffer().x);
        self.buf().x = next;
    }

    fn erase_in_buffer_line(&mut self, y: isize, start: usize, end: usize, clear_wrap: bool, protect: bool) {
        let fill = Cell::null(self.erase_attr());
        let buffer = self.buf();
        let index = buffer.ybase + y;
        if let Some(line) = buffer.line_mut(index) {
            line.replace_cells(start, end, &fill, protect);
            if clear_wrap {
                line.is_wrapped = false;
            }
        }
    }

    fn reset_buffer_line(&mut self, y: isize, protect: bool) {
        let fill = Cell::null(self.erase_attr());
        let buffer = self.buf();
        let index = buffer.ybase + y;
        if let Some(line) = buffer.line_mut(index) {
            line.fill(&fill, protect);
            line.is_wrapped = false;
        }
    }

    fn erase_in_display(&mut self, params: &Params, protect: bool) {
        self.restrict_cursor(Some(self.cols as isize));
        let cols = self.cols;
        let rows = self.rows as isize;
        match params.get(0) {
            0 => {
                let (x, y) = (self.buffer().x, self.buffer().y);
                self.erase_in_buffer_line(y, x as usize, cols, x == 0, protect);
                for j in y + 1..rows {
                    self.reset_buffer_line(j, protect);
                }
            }
            1 => {
                let (x, y) = (self.buffer().x, self.buffer().y);
                self.erase_in_buffer_line(y, 0, (x + 1) as usize, true, protect);
                if x + 1 >= cols as isize {
                    // xterm indexes `lines` with the viewport row here.
                    if let Some(line) = self.buf().line_mut(y + 1) {
                        line.is_wrapped = false;
                    }
                }
                for j in (0..y).rev() {
                    self.reset_buffer_line(j, protect);
                }
            }
            2 => {
                for j in (0..rows).rev() {
                    self.reset_buffer_line(j, protect);
                }
            }
            3 => {
                let buffer = self.buf();
                let scrollback = buffer.lines.len() as isize - rows;
                if scrollback > 0 {
                    buffer.lines.trim_start(scrollback as usize);
                    buffer.ybase = (buffer.ybase - scrollback).max(0);
                    buffer.ydisp = (buffer.ydisp - scrollback).max(0);
                }
            }
            _ => {}
        }
    }

    fn erase_in_line(&mut self, params: &Params, protect: bool) {
        self.restrict_cursor(Some(self.cols as isize));
        let (x, y) = (self.buffer().x, self.buffer().y);
        let cols = self.cols;
        match params.get(0) {
            0 => self.erase_in_buffer_line(y, x as usize, cols, x == 0, protect),
            1 => self.erase_in_buffer_line(y, 0, (x + 1) as usize, false, protect),
            2 => self.erase_in_buffer_line(y, 0, cols, true, protect),
            _ => {}
        }
    }

    fn insert_lines(&mut self, params: &Params) {
        self.restrict_cursor(None);
        let count = param_or_one(params);
        let rows = self.rows as isize;
        let erase = self.erase_attr();
        let cols = self.cols;
        let buffer = self.buf();
        if buffer.y > buffer.scroll_bottom || buffer.y < buffer.scroll_top {
            return;
        }
        let row = buffer.ybase + buffer.y;
        let offset = rows - 1 - buffer.scroll_bottom;
        let bottom_absolute = rows - 1 + buffer.ybase - offset + 1;
        // Iterations past the region height only replace blanks with blanks.
        for _ in 0..count.min(rows as i64) {
            buffer.lines.splice((bottom_absolute - 1) as usize, 1, Vec::new());
            let blank = buffer.blank_line(cols, &erase, false);
            buffer.lines.splice(row as usize, 0, vec![blank]);
        }
        buffer.x = 0;
    }

    fn delete_lines(&mut self, params: &Params) {
        self.restrict_cursor(None);
        let count = param_or_one(params);
        let rows = self.rows as isize;
        let erase = self.erase_attr();
        let cols = self.cols;
        let buffer = self.buf();
        if buffer.y > buffer.scroll_bottom || buffer.y < buffer.scroll_top {
            return;
        }
        let row = buffer.ybase + buffer.y;
        let j = rows - 1 + buffer.ybase - (rows - 1 - buffer.scroll_bottom);
        for _ in 0..count.min(rows as i64) {
            buffer.lines.splice(row as usize, 1, Vec::new());
            let blank = buffer.blank_line(cols, &erase, false);
            buffer.lines.splice(j as usize, 0, vec![blank]);
        }
        buffer.x = 0;
    }

    fn edit_current_line(&mut self, edit: impl FnOnce(&mut BufferLine, usize, &Cell)) {
        self.restrict_cursor(None);
        let fill = Cell::null(self.erase_attr());
        let index = self.row_index();
        let buffer = self.buf();
        let x = buffer.x as usize;
        if let Some(line) = buffer.line_mut(index) {
            edit(line, x, &fill);
        }
    }

    fn scroll_up(&mut self, params: &Params) {
        let count = param_or_one(params).min(self.rows as i64);
        let erase = self.erase_attr();
        let cols = self.cols;
        let buffer = self.buf();
        for _ in 0..count {
            buffer.lines.splice((buffer.ybase + buffer.scroll_top) as usize, 1, Vec::new());
            let blank = buffer.blank_line(cols, &erase, false);
            buffer.lines.splice((buffer.ybase + buffer.scroll_bottom) as usize, 0, vec![blank]);
        }
    }

    fn scroll_down(&mut self, params: &Params) {
        let count = param_or_one(params).min(self.rows as i64);
        let cols = self.cols;
        let buffer = self.buf();
        for _ in 0..count {
            buffer.lines.splice((buffer.ybase + buffer.scroll_bottom) as usize, 1, Vec::new());
            let blank = buffer.blank_line(cols, &Attr::default(), false);
            buffer.lines.splice((buffer.ybase + buffer.scroll_top) as usize, 0, vec![blank]);
        }
    }

    /// SL/SR/DECIC/DECDC: edit every row of the scroll region.
    fn edit_region(&mut self, params: &Params, edit: impl Fn(&mut BufferLine, usize, usize, &Cell)) {
        let fill = Cell::null(self.erase_attr());
        let count = param_or_one(params) as usize;
        let buffer = self.buf();
        if buffer.y > buffer.scroll_bottom || buffer.y < buffer.scroll_top {
            return;
        }
        let x = buffer.x.max(0) as usize;
        for y in buffer.scroll_top..=buffer.scroll_bottom {
            let index = buffer.ybase + y;
            if let Some(line) = buffer.line_mut(index) {
                edit(line, x, count, &fill);
                line.is_wrapped = false;
            }
        }
    }

    fn repeat_preceding(&mut self, params: &Params) {
        let join = self.join_state;
        if join == 0 {
            return;
        }
        // xterm allocates `text.length * count` code points at once; counts
        // that large exhaust the oracle, so they are bounded here.
        let count = (param_or_one(params) as usize).min(MAX_REPEAT_CODES);
        let width = unicode::extract_width(join) as isize;
        let index = self.row_index();
        let x = self.buffer().x - width;
        let text = self
            .buffer()
            .line(index)
            .map(|line| if x >= 0 { line.string_at(x as usize) } else { String::new() })
            .unwrap_or_default();
        let codes: Vec<u32> = text.chars().map(u32::from).collect();
        let total = (codes.len() * count).min(MAX_REPEAT_CODES);
        let data: Vec<u32> = codes.iter().copied().cycle().take(total).collect();
        self.print_codes(&data);
    }

    fn set_mode_private(&mut self, params: &Params, on: bool) {
        for i in 0..params.length {
            match params.get(i) {
                1 => self.dec.application_cursor_keys = on,
                2 if on => {
                    for level in 0..4 {
                        self.charsets.set_gcharset(level, None);
                    }
                }
                6 => {
                    self.dec.origin = on;
                    self.set_cursor(0, 0);
                }
                7 => self.dec.wraparound = on,
                45 => self.dec.reverse_wraparound = on,
                66 => self.dec.application_keypad = on,
                9 => self.mouse = if on { MouseProtocol::X10 } else { MouseProtocol::None },
                1000 => self.mouse = if on { MouseProtocol::Vt200 } else { MouseProtocol::None },
                1002 => self.mouse = if on { MouseProtocol::Drag } else { MouseProtocol::None },
                1003 => self.mouse = if on { MouseProtocol::Any } else { MouseProtocol::None },
                1004 => self.dec.send_focus = on,
                1048 => {
                    if on {
                        self.save_cursor();
                    } else {
                        self.restore_cursor();
                    }
                }
                1049 | 47 | 1047 => {
                    let mode = params.get(i);
                    if on {
                        if mode == 1049 {
                            self.save_cursor();
                        }
                        let erase = self.erase_attr();
                        self.activate_alt(&erase);
                    } else {
                        self.activate_normal();
                        if mode == 1049 {
                            self.restore_cursor();
                        }
                    }
                }
                2004 => self.dec.bracketed_paste = on,
                _ => {}
            }
        }
    }

    fn activate_alt(&mut self, fill: &Attr) {
        if self.alt_active {
            return;
        }
        self.alt.fill_viewport_rows(fill);
        self.alt.x = self.normal.x;
        self.alt.y = self.normal.y;
        self.alt_active = true;
    }

    fn activate_normal(&mut self) {
        if !self.alt_active {
            return;
        }
        self.normal.x = self.alt.x;
        self.normal.y = self.alt.y;
        self.alt.clear();
        self.alt_active = false;
    }

    fn char_attributes(&mut self, params: &Params) {
        if params.length == 1 && params.get(0) == 0 {
            sgr0(&mut self.cur_attr);
            return;
        }
        let mut i = 0;
        while i < params.length {
            let p = params.get(i);
            let attr = &mut self.cur_attr;
            match p {
                30..=37 => {
                    attr.fg &= !(CM_MASK | PCOLOR_MASK);
                    attr.fg |= CM_P16 | (p - 30) as u32;
                }
                40..=47 => {
                    attr.bg &= !(CM_MASK | PCOLOR_MASK);
                    attr.bg |= CM_P16 | (p - 40) as u32;
                }
                90..=97 => {
                    attr.fg &= !(CM_MASK | PCOLOR_MASK);
                    attr.fg |= CM_P16 | (p - 90) as u32 | 8;
                }
                100..=107 => {
                    attr.bg &= !(CM_MASK | PCOLOR_MASK);
                    attr.bg |= CM_P16 | (p - 100) as u32 | 8;
                }
                0 => sgr0(attr),
                1 => attr.fg |= FG_BOLD,
                3 => attr.bg |= BG_ITALIC,
                4 => {
                    attr.fg |= FG_UNDERLINE;
                    let style = if params.has_sub_params(i) {
                        params.sub_params(i)[0]
                    } else {
                        UNDERLINE_SINGLE as i32
                    };
                    process_underline(style, attr);
                }
                5 => attr.fg |= FG_BLINK,
                7 => attr.fg |= FG_INVERSE,
                8 => attr.fg |= FG_INVISIBLE,
                9 => attr.fg |= FG_STRIKETHROUGH,
                2 => attr.bg |= BG_DIM,
                21 => process_underline(UNDERLINE_DOUBLE as i32, attr),
                22 => {
                    attr.fg &= !FG_BOLD;
                    attr.bg &= !BG_DIM;
                }
                23 => attr.bg &= !BG_ITALIC,
                24 => {
                    attr.fg &= !FG_UNDERLINE;
                    process_underline(UNDERLINE_NONE as i32, attr);
                }
                25 => attr.fg &= !FG_BLINK,
                27 => attr.fg &= !FG_INVERSE,
                28 => attr.fg &= !FG_INVISIBLE,
                29 => attr.fg &= !FG_STRIKETHROUGH,
                39 => attr.fg &= !(CM_MASK | RGB_MASK),
                49 => attr.bg &= !(CM_MASK | RGB_MASK),
                38 | 48 | 58 => i += extract_color(params, i, attr),
                53 => attr.bg |= BG_OVERLINE,
                55 => attr.bg &= !BG_OVERLINE,
                59 => {
                    attr.extended.set_underline_color(u32::MAX);
                    attr.update_extended();
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn soft_reset(&mut self) {
        let rows = self.rows as isize;
        self.cur_attr = Attr::default();
        self.insert_mode = false;
        self.dec = DecModes::default();
        self.charsets = Charsets::default();
        let ybase = self.buffer().ybase;
        let buffer = self.buf();
        buffer.scroll_top = 0;
        buffer.scroll_bottom = rows - 1;
        buffer.saved.x = 0;
        buffer.saved.y = ybase;
        buffer.saved.fg = 0;
        buffer.saved.bg = 0;
        buffer.saved.charset = None;
    }

    fn set_scroll_region(&mut self, params: &Params) {
        let rows = self.rows as isize;
        let top = isize::try_from(param_or_one(params)).unwrap_or(isize::MAX);
        let mut bottom = rows;
        if params.length >= 2 {
            let value = params.get(1) as isize;
            if value <= rows && value != 0 {
                bottom = value;
            }
        }
        if bottom > top {
            let buffer = self.buf();
            buffer.scroll_top = top - 1;
            buffer.scroll_bottom = bottom - 1;
            self.set_cursor(0, 0);
        }
    }

    fn save_cursor(&mut self) {
        let (fg, bg) = (self.cur_attr.fg, self.cur_attr.bg);
        let charset = self.charsets.charset;
        let buffer = self.buf();
        buffer.saved.x = buffer.x;
        buffer.saved.y = buffer.ybase + buffer.y;
        buffer.saved.fg = fg;
        buffer.saved.bg = bg;
        buffer.saved.charset = charset;
    }

    fn restore_cursor(&mut self) {
        let buffer = self.buf();
        buffer.x = buffer.saved.x;
        buffer.y = (buffer.saved.y - buffer.ybase).max(0);
        let saved = buffer.saved;
        self.cur_attr.fg = saved.fg;
        self.cur_attr.bg = saved.bg;
        self.charsets.charset = saved.charset;
        self.restrict_cursor(None);
    }

    fn index(&mut self) {
        self.restrict_cursor(None);
        self.buf().y += 1;
        if self.buffer().y == self.buffer().scroll_bottom + 1 {
            self.buf().y -= 1;
            let erase = self.erase_attr();
            self.scroll(erase, false);
        } else if self.buffer().y >= self.rows as isize {
            self.buf().y = self.rows as isize - 1;
        }
        self.restrict_cursor(None);
    }

    fn reverse_index(&mut self) {
        self.restrict_cursor(None);
        let erase = self.erase_attr();
        let cols = self.cols;
        let buffer = self.buf();
        if buffer.y == buffer.scroll_top {
            let height = buffer.scroll_bottom - buffer.scroll_top;
            let start = buffer.ybase + buffer.y;
            buffer.lines.shift_elements(start as usize, height, 1);
            let blank = buffer.blank_line(cols, &erase, false);
            buffer.lines.set(start as usize, Some(blank));
        } else {
            buffer.y -= 1;
            self.restrict_cursor(None);
        }
    }

    fn select_charset(&mut self, collect: u32, flag: u8) {
        let level = match collect {
            0x28 => 0,
            0x29 | 0x2d => 1,
            0x2a | 0x2e => 2,
            0x2b => 3,
            _ => return,
        };
        let charset = (flag != b'B').then_some(flag);
        self.charsets.set_gcharset(level, charset);
    }

    fn screen_alignment_pattern(&mut self) {
        let cell = Cell {
            content: (1 << WIDTH_SHIFT) | u32::from(b'E'),
            attr: Attr {
                fg: self.cur_attr.fg,
                bg: self.cur_attr.bg,
                extended: Default::default(),
            },
            combined: String::new(),
        };
        self.set_cursor(0, 0);
        let rows = self.rows as isize;
        let buffer = self.buf();
        for offset in 0..rows {
            let index = buffer.ybase + buffer.y + offset;
            if let Some(line) = buffer.line_mut(index) {
                line.fill(&cell, false);
                line.is_wrapped = false;
            }
        }
        self.set_cursor(0, 0);
    }

    fn set_hyperlink(&mut self, data: &str) {
        let Some(split) = data.find(';') else {
            return;
        };
        let params = data[..split].trim_matches(js_whitespace);
        let uri = &data[split + 1..];
        if !uri.is_empty() {
            // Link ids only distinguish "linked" from "not linked" in every
            // observed field (they force the dashed underline style).
            self.cur_attr.extended.url_id = 1;
            self.cur_attr.update_extended();
        } else if params.is_empty() {
            self.cur_attr.extended.url_id = 0;
            self.cur_attr.update_extended();
        }
    }
}

/// JavaScript `String.prototype.trim` whitespace (WhiteSpace + LineTerminator).
fn js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{A}' | '\u{B}' | '\u{C}' | '\u{D}' | ' ' | '\u{A0}' | '\u{1680}'
            | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}'
            | '\u{3000}' | '\u{FEFF}'
    )
}

fn new_buffers(cols: usize, rows: usize, scrollback: usize) -> (Buffer, Buffer) {
    let mut normal = Buffer::new(true, scrollback, cols, rows);
    normal.fill_viewport_rows(&Attr::default());
    let alt = Buffer::new(false, scrollback, cols, rows);
    (normal, alt)
}

/// `print`'s copy of a wide/joined cell from the row it wrapped off.
fn copy_rows(buffer: &mut Buffer, src: isize, dest: isize, src_col: usize, length: usize) {
    if src == dest {
        if let Some(line) = buffer.line_mut(dest) {
            line.copy_cells_within(src_col, 0, length, false);
        }
        return;
    }
    let Some(source) = buffer.line(src).cloned() else {
        return;
    };
    if let Some(line) = buffer.line_mut(dest) {
        line.copy_cells_from(&source, src_col, 0, length, false);
    }
}

fn param_or_one(params: &Params) -> i64 {
    match params.get(0) {
        0 => 1,
        value => i64::from(value),
    }
}

fn sgr0(attr: &mut Attr) {
    attr.fg = 0;
    attr.bg = 0;
    attr.extended.set_underline_style(UNDERLINE_NONE);
    let color = attr.extended.underline_color() & !(CM_MASK | RGB_MASK);
    attr.extended.set_underline_color(color);
    attr.update_extended();
}

fn process_underline(style: i32, attr: &mut Attr) {
    let style = if style == -1 || style > 5 { 1 } else { style as u32 };
    attr.extended.set_underline_style(style);
    attr.fg |= FG_UNDERLINE;
    if style == 0 {
        attr.fg &= !FG_UNDERLINE;
    }
    attr.update_extended();
}

fn update_attr_color(color: u32, mode: i64, c1: i64, c2: i64, c3: i64) -> u32 {
    let mut color = color;
    if mode == 2 {
        color |= CM_RGB;
        color &= !RGB_MASK;
        color |= (((c1 & 255) as u32) << 16) | (((c2 & 255) as u32) << 8) | (c3 & 255) as u32;
    } else if mode == 5 {
        color &= !(CM_MASK | PCOLOR_MASK);
        color |= CM_P256 | (c1 & 0xff) as u32;
    }
    color
}

/// xterm `_extractColor`: returns how many params the color consumed.
fn extract_color(params: &Params, pos: usize, attr: &mut Attr) -> usize {
    let mut accu: [i64; 6] = [0, 0, -1, 0, 0, 0];
    let mut space = 0usize;
    let mut advance = 0usize;
    loop {
        accu[advance + space] = i64::from(params.get(pos + advance));
        if params.has_sub_params(pos + advance) {
            let sub = params.sub_params(pos + advance);
            let mut i = 0;
            loop {
                if accu[1] == 5 {
                    space = 1;
                }
                if let Some(slot) = accu.get_mut(advance + i + 1 + space) {
                    *slot = i64::from(sub[i]);
                }
                i += 1;
                if !(i < sub.len() && i + advance + 1 + space < accu.len()) {
                    break;
                }
            }
            break;
        }
        if (accu[1] == 5 && advance + space >= 2) || (accu[1] == 2 && advance + space >= 5) {
            break;
        }
        if accu[1] != 0 {
            space = 1;
        }
        advance += 1;
        if !(advance + pos < params.length && advance + space < accu.len()) {
            break;
        }
    }
    for value in accu.iter_mut().skip(2) {
        if *value == -1 {
            *value = 0;
        }
    }
    match accu[0] {
        38 => attr.fg = update_attr_color(attr.fg, accu[1], accu[3], accu[4], accu[5]),
        48 => attr.bg = update_attr_color(attr.bg, accu[1], accu[3], accu[4], accu[5]),
        58 => {
            let color = update_attr_color(attr.extended.underline_color(), accu[1], accu[3], accu[4], accu[5]);
            attr.extended.set_underline_color(color);
        }
        _ => {}
    }
    advance
}

impl Perform for Core {
    fn print(&mut self, data: &[u32]) {
        self.print_codes(data);
    }

    fn execute(&mut self, code: u32) {
        match code {
            0x0a..=0x0c => self.line_feed(),
            0x0d => self.buf().x = 0,
            0x08 => self.backspace(),
            0x09 => self.tab(),
            0x0e => self.charsets.set_glevel(1),
            0x0f => self.charsets.set_glevel(0),
            0x84 => self.index(),
            0x85 => {
                self.buf().x = 0;
                self.index();
            }
            0x88 => {
                let buffer = self.buf();
                let x = buffer.x;
                buffer.tabs.insert(x);
            }
            _ => {}
        }
    }

    fn csi_dispatch(&mut self, ident: u32, params: &Params) {
        let p0 = params.get(0) as isize;
        let n = if p0 == 0 { 1 } else { p0 };
        match ident {
            0x40 => self.edit_current_line(|line, x, fill| {
                line.insert_cells(x, n as usize, fill);
            }),
            0x2040 => self.edit_region(params, |line, _, count, fill| line.delete_cells(0, count, fill)),
            0x41 => {
                let diff = self.buffer().y - self.buffer().scroll_top;
                self.move_cursor(0, if diff >= 0 { -diff.min(n) } else { -n });
            }
            0x2041 => self.edit_region(params, |line, _, count, fill| line.insert_cells(0, count, fill)),
            0x42 => {
                let diff = self.buffer().scroll_bottom - self.buffer().y;
                self.move_cursor(0, if diff >= 0 { diff.min(n) } else { n });
            }
            0x43 | 0x61 => self.move_cursor(n, 0),
            0x44 => self.move_cursor(-n, 0),
            0x45 => {
                self.csi_dispatch(0x42, params);
                self.buf().x = 0;
            }
            0x46 => {
                self.csi_dispatch(0x41, params);
                self.buf().x = 0;
            }
            0x47 | 0x60 => {
                let y = self.buffer().y;
                self.set_cursor(n - 1, y);
            }
            0x48 | 0x66 => {
                let x = if params.length >= 2 {
                    let p1 = params.get(1) as isize;
                    (if p1 == 0 { 1 } else { p1 }) - 1
                } else {
                    0
                };
                self.set_cursor(x, n - 1);
            }
            0x49 => {
                if self.buffer().x < self.cols as isize {
                    for _ in 0..n.min(self.cols as isize + 1) {
                        let next = self.buffer().next_stop(self.buffer().x);
                        self.buf().x = next;
                    }
                }
            }
            0x4a => self.erase_in_display(params, false),
            0x3f4a => self.erase_in_display(params, true),
            0x4b => self.erase_in_line(params, false),
            0x3f4b => self.erase_in_line(params, true),
            0x4c => self.insert_lines(params),
            0x4d => self.delete_lines(params),
            0x50 => self.edit_current_line(|line, x, fill| {
                line.delete_cells(x, n as usize, fill);
            }),
            0x53 => self.scroll_up(params),
            0x54 => self.scroll_down(params),
            0x58 => self.edit_current_line(|line, x, fill| {
                line.replace_cells(x, x + n as usize, fill, false);
            }),
            0x5a => {
                if self.buffer().x < self.cols as isize {
                    for _ in 0..n.min(self.cols as isize + 1) {
                        let prev = self.buffer().prev_stop(self.buffer().x);
                        self.buf().x = prev;
                    }
                }
            }
            0x62 => self.repeat_preceding(params),
            0x64 => {
                let x = self.buffer().x;
                self.set_cursor(x, n - 1);
            }
            0x65 => self.move_cursor(0, n),
            0x67 => match p0 {
                0 => {
                    let buffer = self.buf();
                    let x = buffer.x;
                    buffer.tabs.remove(&x);
                }
                3 => self.buf().tabs.clear(),
                _ => {}
            },
            0x68 | 0x6c => {
                let on = ident == 0x68;
                for i in 0..params.length {
                    match params.get(i) {
                        4 => self.insert_mode = on,
                        20 => self.convert_eol = on,
                        _ => {}
                    }
                }
            }
            0x3f68 => self.set_mode_private(params, true),
            0x3f6c => self.set_mode_private(params, false),
            0x6d => self.char_attributes(params),
            0x2170 => self.soft_reset(),
            0x72 => self.set_scroll_region(params),
            0x73 => self.save_cursor(),
            0x75 => self.restore_cursor(),
            0x277d => self.edit_region(params, |line, x, count, fill| line.insert_cells(x, count, fill)),
            0x277e => self.edit_region(params, |line, x, count, fill| line.delete_cells(x, count, fill)),
            0x2271 => match p0 {
                1 => self.cur_attr.bg |= BG_PROTECTED,
                0 | 2 => self.cur_attr.bg &= !BG_PROTECTED,
                _ => {}
            },
            _ => {}
        }
    }

    fn esc_dispatch(&mut self, ident: u32) {
        let collect = ident >> 8;
        let flag = (ident & 0xff) as u8;
        if collect == 0 {
            match flag {
                b'7' => self.save_cursor(),
                b'8' => self.restore_cursor(),
                b'D' => self.index(),
                b'E' => {
                    self.buf().x = 0;
                    self.index();
                }
                b'H' => {
                    let buffer = self.buf();
                    let x = buffer.x;
                    buffer.tabs.insert(x);
                }
                b'M' => self.reverse_index(),
                b'=' => self.dec.application_keypad = true,
                b'>' => self.dec.application_keypad = false,
                b'c' => self.full_reset(),
                b'n' | b'}' => self.charsets.set_glevel(2),
                b'o' | b'|' => self.charsets.set_glevel(3),
                b'~' => self.charsets.set_glevel(1),
                _ => {}
            }
            return;
        }
        if collect == 0x25 && (flag == b'@' || flag == b'G') {
            self.charsets.set_glevel(0);
            self.charsets.set_gcharset(0, None);
            return;
        }
        if collect == 0x23 && flag == b'8' {
            self.screen_alignment_pattern();
            return;
        }
        if matches!(collect, 0x28..=0x2f) && collect != 0x2c && charsets::CHARSET_FLAGS.contains(&flag) {
            self.select_charset(collect, flag);
        }
    }

    fn osc_dispatch(&mut self, id: i64, data: Option<&str>) {
        if id == 8
            && let Some(data) = data
        {
            self.set_hyperlink(data);
        }
    }

    fn clear_join_state(&mut self) {
        self.join_state = 0;
    }
}
