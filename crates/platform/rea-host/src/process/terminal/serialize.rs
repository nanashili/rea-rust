//! Buffer replay serialization, ported from `@xterm/addon-serialize`
//! (`SerializeAddon.serialize()` with default options: full normal buffer,
//! alternate screen when active, then terminal modes).

use std::fmt::Write as _;

use super::attr::{Attr, Cell};
use super::buffer::Buffer;

/// Terminal modes `SerializeAddon._serializeModes` replays.
#[derive(Clone, Copy, Debug, Default)]
pub struct SerializedModes {
    pub application_cursor_keys: bool,
    pub application_keypad: bool,
    pub bracketed_paste: bool,
    pub insert: bool,
    pub origin: bool,
    pub reverse_wraparound: bool,
    pub send_focus: bool,
    pub wraparound: bool,
    /// `?9h`/`?1000h`/`?1002h`/`?1003h` parameter, if mouse tracking is on.
    pub mouse_tracking: Option<u16>,
}

pub struct SerializeInput<'a> {
    pub normal: &'a Buffer,
    pub alternate: Option<&'a Buffer>,
    pub rows: usize,
    pub cols: usize,
    pub cur_attr: &'a Attr,
    pub modes: SerializedModes,
}

pub fn serialize(input: &SerializeInput<'_>) -> String {
    let mut content = serialize_buffer(input.normal, input);
    if let Some(alternate) = input.alternate {
        content.push_str("\x1b[?1049h\x1b[H");
        content.push_str(&serialize_buffer(alternate, input));
    }
    let modes = input.modes;
    for (on, sequence) in [
        (modes.application_cursor_keys, "\x1b[?1h"),
        (modes.application_keypad, "\x1b[?66h"),
        (modes.bracketed_paste, "\x1b[?2004h"),
        (modes.insert, "\x1b[4h"),
        (modes.origin, "\x1b[?6h"),
        (modes.reverse_wraparound, "\x1b[?45h"),
        (modes.send_focus, "\x1b[?1004h"),
        (!modes.wraparound, "\x1b[?7l"),
    ] {
        if on {
            content.push_str(sequence);
        }
    }
    if let Some(mode) = modes.mouse_tracking {
        let _ = write!(content, "\x1b[?{mode}h");
    }
    content
}

fn equal_fg(a: &Attr, b: &Attr) -> bool {
    a.fg_color_mode() == b.fg_color_mode() && a.fg_color() == b.fg_color()
}

fn equal_bg(a: &Attr, b: &Attr) -> bool {
    a.bg_color_mode() == b.bg_color_mode() && a.bg_color() == b.bg_color()
}

fn equal_flags(a: &Attr, b: &Attr) -> bool {
    a.is_inverse() == b.is_inverse()
        && a.is_bold() == b.is_bold()
        && a.is_underline() == b.is_underline()
        && a.is_overline() == b.is_overline()
        && a.is_blink() == b.is_blink()
        && a.is_invisible() == b.is_invisible()
        && a.is_italic() == b.is_italic()
        && a.is_dim() == b.is_dim()
        && a.is_strikethrough() == b.is_strikethrough()
}

fn diff_style(cell: &Attr, old: &Attr) -> Vec<i64> {
    let mut sgr = Vec::new();
    let fg_changed = !equal_fg(cell, old);
    let bg_changed = !equal_bg(cell, old);
    let flags_changed = !equal_flags(cell, old);
    if !(fg_changed || bg_changed || flags_changed) {
        return sgr;
    }
    if cell.is_attribute_default() {
        if !old.is_attribute_default() {
            sgr.push(0);
        }
        return sgr;
    }
    if fg_changed {
        let color = cell.fg_color();
        if cell.is_fg_rgb() {
            sgr.extend([38, 2, (color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF]);
        } else if cell.is_fg_palette() {
            if color >= 16 {
                sgr.extend([38, 5, color]);
            } else {
                sgr.push(if color & 8 != 0 { 90 + (color & 7) } else { 30 + (color & 7) });
            }
        } else {
            sgr.push(39);
        }
    }
    if bg_changed {
        let color = cell.bg_color();
        if cell.is_bg_rgb() {
            sgr.extend([48, 2, (color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF]);
        } else if cell.is_bg_palette() {
            if color >= 16 {
                sgr.extend([48, 5, color]);
            } else {
                sgr.push(if color & 8 != 0 { 100 + (color & 7) } else { 40 + (color & 7) });
            }
        } else {
            sgr.push(49);
        }
    }
    if flags_changed {
        let toggles: [(u32, u32, i64, i64); 9] = [
            (cell.is_inverse(), old.is_inverse(), 7, 27),
            (cell.is_bold(), old.is_bold(), 1, 22),
            (cell.is_underline(), old.is_underline(), 4, 24),
            (cell.is_overline(), old.is_overline(), 53, 55),
            (cell.is_blink(), old.is_blink(), 5, 25),
            (cell.is_invisible(), old.is_invisible(), 8, 28),
            (cell.is_italic(), old.is_italic(), 3, 23),
            (cell.is_dim(), old.is_dim(), 2, 22),
            (cell.is_strikethrough(), old.is_strikethrough(), 9, 29),
        ];
        for (new, previous, on, off) in toggles {
            if new != previous {
                sgr.push(if new != 0 { on } else { off });
            }
        }
    }
    sgr
}

fn sgr_string(sgr: &[i64]) -> String {
    let joined: Vec<String> = sgr.iter().map(i64::to_string).collect();
    format!("\x1b[{}m", joined.join(";"))
}

/// `StringSerializeHandler` state over one buffer.
struct Handler<'a> {
    buffer: &'a Buffer,
    rows: usize,
    all_rows: Vec<String>,
    separators: Vec<String>,
    current_row: String,
    null_cell_count: usize,
    cursor_style: Cell,
    cursor_style_row: usize,
    cursor_style_col: usize,
    background: Cell,
    first_row: usize,
    last_cursor_row: isize,
    last_cursor_col: isize,
    last_content_row: isize,
    last_content_col: isize,
}

fn serialize_buffer(buffer: &Buffer, input: &SerializeInput<'_>) -> String {
    let max_rows = buffer.lines.len();
    let mut handler = Handler {
        buffer,
        rows: input.rows,
        all_rows: Vec::new(),
        separators: Vec::new(),
        current_row: String::new(),
        null_cell_count: 0,
        cursor_style: Cell::default(),
        cursor_style_row: 0,
        cursor_style_col: 0,
        background: Cell::default(),
        first_row: 0,
        last_cursor_row: 0,
        last_cursor_col: 0,
        last_content_row: 0,
        last_content_col: 0,
    };
    if max_rows == 0 {
        // Range end row is -1: no row runs and no `_rowEnd` fires.
        return handler.finish(input);
    }
    let end_row = max_rows - 1;
    for row in 0..=end_row {
        if let Some(line) = buffer.lines.get(row) {
            let end_col = if row == end_row { input.cols } else { line.len() };
            for col in 0..end_col {
                if let Some(cell) = line.api_cell(col) {
                    handler.next_cell(&cell, row, col);
                }
            }
        }
        handler.row_end(row, row == end_row);
    }
    handler.finish(input)
}

impl Handler<'_> {
    fn line_cell(&self, row: usize, col: usize) -> Option<Cell> {
        self.buffer.lines.get(row).and_then(|line| line.api_cell(col))
    }

    fn row_end(&mut self, row: usize, is_last: bool) {
        if self.null_cell_count > 0 && !equal_bg(&self.cursor_style.attr, &self.background.attr) {
            let _ = write!(self.current_row, "\x1b[{}X", self.null_cell_count);
        }
        let mut separator = String::new();
        if !is_last {
            if row - self.first_row >= self.rows
                && let Some(cell) = self.line_cell(self.cursor_style_row, self.cursor_style_col)
            {
                self.background = cell;
            }
            let current = self.buffer.lines.get(row);
            let next = self.buffer.lines.get(row + 1);
            if let (Some(current), Some(next)) = (current, next) {
                if !next.is_wrapped {
                    separator.push_str("\r\n");
                    self.last_cursor_row = row as isize + 1;
                    self.last_cursor_col = 0;
                } else {
                    let length = current.len();
                    let last = current.api_cell(length - 1).unwrap_or_default();
                    let second = current.api_cell(length - 2).unwrap_or_default();
                    let first_next = next.api_cell(0).unwrap_or_default();
                    let next_wide = first_next.width() > 1;
                    let mut valid = false;
                    let condition = if !first_next.chars().is_empty() && next_wide {
                        self.null_cell_count <= 1
                    } else {
                        self.null_cell_count == 0
                    };
                    if condition {
                        if (!last.chars().is_empty() || last.width() == 0)
                            && equal_bg(&last.attr, &first_next.attr)
                        {
                            valid = true;
                        }
                        if next_wide
                            && (!second.chars().is_empty() || second.width() == 0)
                            && equal_bg(&last.attr, &first_next.attr)
                            && equal_bg(&second.attr, &first_next.attr)
                        {
                            valid = true;
                        }
                    }
                    if !valid {
                        separator = "-".repeat(self.null_cell_count + 1);
                        separator.push_str("\x1b[1D\x1b[1X");
                        if self.null_cell_count > 0 {
                            let kept = length as isize - self.null_cell_count as isize;
                            let _ = write!(
                                separator,
                                "\x1b[A\x1b[{kept}C\x1b[{}X\x1b[{kept}D\x1b[B",
                                self.null_cell_count
                            );
                        }
                        self.last_content_row = row as isize + 1;
                        self.last_content_col = 0;
                        self.last_cursor_row = row as isize + 1;
                        self.last_cursor_col = 0;
                    }
                }
            }
        }
        self.all_rows.push(std::mem::take(&mut self.current_row));
        self.separators.push(separator);
        self.null_cell_count = 0;
    }

    fn next_cell(&mut self, cell: &Cell, row: usize, col: usize) {
        if cell.width() == 0 {
            return;
        }
        let chars = cell.chars();
        let is_empty = chars.is_empty();
        let sgr = diff_style(&cell.attr, &self.cursor_style.attr);
        let style_changed = if is_empty {
            !equal_bg(&self.cursor_style.attr, &cell.attr)
        } else {
            !sgr.is_empty()
        };
        if style_changed {
            if self.null_cell_count > 0 {
                if !equal_bg(&self.cursor_style.attr, &self.background.attr) {
                    let _ = write!(self.current_row, "\x1b[{}X", self.null_cell_count);
                }
                let _ = write!(self.current_row, "\x1b[{}C", self.null_cell_count);
                self.null_cell_count = 0;
            }
            self.last_content_row = row as isize;
            self.last_cursor_row = row as isize;
            self.last_content_col = col as isize;
            self.last_cursor_col = col as isize;
            self.current_row.push_str(&sgr_string(&sgr));
            if let Some(loaded) = self.line_cell(row, col) {
                self.cursor_style = loaded;
                self.cursor_style_row = row;
                self.cursor_style_col = col;
            }
        }
        if is_empty {
            self.null_cell_count += cell.width() as usize;
        } else {
            if self.null_cell_count > 0 {
                if !equal_bg(&self.cursor_style.attr, &self.background.attr) {
                    let _ = write!(self.current_row, "\x1b[{}X", self.null_cell_count);
                }
                let _ = write!(self.current_row, "\x1b[{}C", self.null_cell_count);
                self.null_cell_count = 0;
            }
            self.current_row.push_str(&chars);
            self.last_content_row = row as isize;
            self.last_cursor_row = row as isize;
            self.last_content_col = (col + cell.width() as usize) as isize;
            self.last_cursor_col = self.last_content_col;
        }
    }

    fn finish(&mut self, input: &SerializeInput<'_>) -> String {
        let mut row_end = self.all_rows.len() as isize;
        if self.buffer.lines.len() as isize - self.first_row as isize <= self.rows as isize {
            row_end = self.last_content_row + 1 - self.first_row as isize;
            self.last_cursor_col = self.last_content_col;
            self.last_cursor_row = self.last_content_row;
        }
        let mut content = String::new();
        let row_end = row_end.max(0) as usize;
        for i in 0..row_end {
            if let Some(row) = self.all_rows.get(i) {
                content.push_str(row);
            }
            if i + 1 < row_end
                && let Some(separator) = self.separators.get(i)
            {
                content.push_str(separator);
            }
        }
        let real_row = self.buffer.ybase + self.buffer.y;
        let real_col = self.buffer.x;
        if real_row != self.last_cursor_row || real_col != self.last_cursor_col {
            let down = real_row - self.last_cursor_row;
            if down > 0 {
                let _ = write!(content, "\x1b[{down}B");
            } else if down < 0 {
                let _ = write!(content, "\x1b[{}A", -down);
            }
            let right = real_col - self.last_cursor_col;
            if right > 0 {
                let _ = write!(content, "\x1b[{right}C");
            } else if right < 0 {
                let _ = write!(content, "\x1b[{}D", -right);
            }
        }
        let sgr = diff_style(input.cur_attr, &self.cursor_style.attr);
        if !sgr.is_empty() {
            content.push_str(&sgr_string(&sgr));
        }
        content
    }
}
