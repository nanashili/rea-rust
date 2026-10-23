//! Module semantics the differential corpus (`.cache/rust-migration/
//! terminal-diff`, xterm.js oracle) cannot pin as compactly. Expected values
//! were taken from `@xterm/headless` 6.0.0 + `@xterm/addon-serialize`.

use super::*;

fn screen(columns: u16, rows: u16) -> TerminalScreen {
    TerminalScreen::new(TerminalSize::new(columns, rows).unwrap(), 100)
}

fn trimmed(snapshot: &ScreenSnapshot) -> Vec<&str> {
    snapshot.lines.iter().map(|line| line.trim_end_matches(' ')).collect()
}

#[test]
fn renders_padded_viewport_cursor_and_serialized_state() {
    let mut terminal = screen(10, 3);
    terminal.write(b"ab\r\n\x1b[31;1mcd");
    let snapshot = terminal.snapshot();
    assert_eq!(snapshot.lines, vec!["ab        ", "cd        ", "          "]);
    assert_eq!((snapshot.cursor_x, snapshot.cursor_y), (2, 1));
    assert_eq!(snapshot.active_buffer, ActiveBuffer::Normal);
    assert_eq!(snapshot.serialized_state, "ab\r\n\x1b[31;1mcd");
}

#[test]
fn carries_split_utf8_and_escape_sequences_across_chunks() {
    let mut terminal = screen(10, 2);
    terminal.write(b"\x1b[3");
    terminal.write(b"1m\xc3");
    terminal.write(b"\xa9");
    assert_eq!(trimmed(&terminal.snapshot())[0], "é");
}

#[test]
fn uses_xterm_unicode_6_widths_for_emoji_and_cjk() {
    let mut terminal = screen(10, 2);
    terminal.write("😀中".as_bytes());
    // U+1F600 is one cell under xterm's default Unicode 6 table; CJK is two.
    assert_eq!(terminal.snapshot().cursor_x, 3);
}

#[test]
fn reports_pending_wrap_cursor_at_the_margin() {
    let mut terminal = screen(4, 2);
    terminal.write(b"abcd");
    let snapshot = terminal.snapshot();
    assert_eq!((snapshot.cursor_x, snapshot.cursor_y), (4, 0));
}

#[test]
fn reflows_soft_wrapped_lines_when_columns_grow() {
    let mut terminal = screen(4, 3);
    terminal.write(b"abcdefgh\r\n");
    terminal.resize(TerminalSize::new(8, 3).unwrap());
    assert_eq!(trimmed(&terminal.snapshot())[0], "abcdefgh");
}

#[test]
fn serializes_alternate_screen_after_the_normal_buffer() {
    let mut terminal = screen(5, 2);
    terminal.write(b"1\r\n2\r\n3");
    assert_eq!(trimmed(&terminal.snapshot())[0], "2");
    terminal.write(b"\x1b[?1049h\x1b[Halt");
    let snapshot = terminal.snapshot();
    assert_eq!(snapshot.active_buffer, ActiveBuffer::Alternate);
    assert!(snapshot.serialized_state.contains("\x1b[?1049h\x1b[Halt"));
}

#[test]
fn resize_changes_reported_dimensions() {
    let mut terminal = screen(5, 2);
    terminal.resize(TerminalSize::new(8, 4).unwrap());
    let snapshot = terminal.snapshot();
    assert_eq!((snapshot.columns, snapshot.rows, snapshot.lines.len()), (8, 4, 4));
    assert!(TerminalSize::new(0, 4).is_none());
}
