//! Pure GDB/MI parsing helpers.
//!
//! Compatibility owner: `src/gdb/GdbSessionManager.ts` (`gdbMiGroupsListSpan`,
//! `gdbThreadGroupPids`, `gdbThreadGroupCount`, `miStringField`, `miQuote`,
//! `commandMayChangeInferiorOutput`). These are faithful byte/char-for-char
//! ports over `&str` (the TS operates on UTF-16 code units; GDB MI records are
//! ASCII-structured, and the only data compared is structural punctuation and
//! decimal PIDs, so operating over `char`s preserves behavior).
#![allow(dead_code)]

/// Bound parser memory when a capped MI record contains extreme nesting.
const MAX_GDB_MI_NESTED_VALUE_FRAMES: usize = 256;

const RECENT_RECORD_TRUNCATION_MARKER: &str = "[recent record truncated]";
const MAX_RECENT_MI_LINE_BYTES: usize = 64 * 1024;

/// Retain a UTF-8 prefix of a long MI record with the truncation marker.
pub(super) fn truncate_utf8_record_prefix(line: &str) -> String {
    let budget = MAX_RECENT_MI_LINE_BYTES - RECENT_RECORD_TRUNCATION_MARKER.len();
    let mut prefix = String::new();
    let mut retained = 0usize;
    for ch in line.chars() {
        let bytes = ch.len_utf8();
        if retained + bytes > budget {
            break;
        }
        prefix.push(ch);
        retained += bytes;
    }
    prefix.push_str(RECENT_RECORD_TRUNCATION_MARKER);
    prefix
}

/// Quote a command for `-interpreter-exec console` (`miQuote`).
pub(super) fn mi_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\r' => quoted.push_str("\\r"),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

#[derive(Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

fn is_name_character(ch: Option<char>) -> bool {
    match ch {
        None => false,
        Some(ch) => {
            !matches!(ch, '=' | ',' | '{' | '}' | '[' | ']' | '"')
                && !ch.is_whitespace()
                && (ch as u32) >= 0x20
        }
    }
}

/// Iterate the chars as a Vec for index-based lookahead like the TS code.
struct Chars {
    chars: Vec<char>,
}

impl Chars {
    fn new(value: &str) -> Self {
        Self {
            chars: value.chars().collect(),
        }
    }
    fn get(&self, index: usize) -> Option<char> {
        self.chars.get(index).copied()
    }
    fn len(&self) -> usize {
        self.chars.len()
    }
    fn slice(&self, start: usize, end: usize) -> String {
        self.chars[start..end].iter().collect()
    }
    fn starts_with_at(&self, needle: &str, index: usize) -> bool {
        let needle: Vec<char> = needle.chars().collect();
        if index + needle.len() > self.chars.len() {
            return false;
        }
        self.chars[index..index + needle.len()] == needle[..]
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    First,
    AfterComma,
    AfterItem,
}

#[derive(Clone, Copy, PartialEq)]
enum ListItems {
    Result,
    Value,
}

struct Frame {
    kind_is_list: bool,
    close: char,
    group_inventory: bool,
    group_start: Option<usize>,
    group_tuple: bool,
    phase: Phase,
    list_items: Option<ListItems>,
    group_id_seen: bool,
}

/// Parse a complete MI result record and retain the unique top-level groups
/// list span (`gdbMiGroupsListSpan`).
fn gdb_mi_groups_list_span(mi: &str) -> Option<Span> {
    let chars = Chars::new(mi);
    // prefix = /^(?:\d+)?\^done/
    let mut cursor = 0usize;
    while matches!(chars.get(cursor), Some(c) if c.is_ascii_digit()) {
        cursor += 1;
    }
    if !chars.starts_with_at("^done", cursor) {
        return None;
    }
    cursor += "^done".len();

    let read_name = |start: usize| -> usize {
        if !is_name_character(chars.get(start)) {
            return start;
        }
        let mut c = start;
        while is_name_character(chars.get(c)) {
            c += 1;
        }
        c
    };

    let read_string = |start: usize| -> Option<usize> {
        let mut c = start + 1;
        while c < chars.len() {
            let ch = chars.get(c);
            if ch == Some('"') {
                return Some(c + 1);
            }
            if ch == Some('\\') {
                c += 1;
                let escaped = chars.get(c)?;
                if escaped == 'x' {
                    let start_hex = c + 1;
                    c = start_hex;
                    while matches!(chars.get(c), Some(h) if h.is_ascii_hexdigit()) {
                        c += 1;
                    }
                    if c == start_hex {
                        return None;
                    }
                    c -= 1;
                } else if ('0'..='7').contains(&escaped) {
                    let mut digits = 1;
                    while digits < 3
                        && matches!(chars.get(c + 1), Some(d) if ('0'..='7').contains(&d))
                    {
                        c += 1;
                        digits += 1;
                    }
                } else if !matches!(
                    escaped,
                    'a' | 'b' | 'f' | 'n' | 'r' | 't' | 'v' | '\\' | '\'' | '"' | '?'
                ) {
                    return None;
                }
            } else if (chars.get(c).map(|c| c as u32).unwrap_or(0)) < 0x20 {
                return None;
            }
            c += 1;
        }
        None
    };

    let mut stack: Vec<Frame> = Vec::new();
    let mut group_span: Option<Span> = None;
    let mut group_seen = false;
    let mut value_start: isize = -1;
    let mut pending_group_list = false;

    // begin_value / complete_value need to mutate cursor + stack, so we inline
    // them as macros via closures over indices is awkward in Rust; implement a
    // manual loop mirroring the TS control flow.
    macro_rules! complete_value {
        () => {{
            if let Some(parent) = stack.last_mut() {
                parent.phase = Phase::AfterItem;
            }
        }};
    }

    // Returns false on malformed value.
    macro_rules! begin_value {
        () => {{
            let ch = chars.get(cursor);
            if pending_group_list && ch != Some('[') {
                false
            } else if ch == Some('"') {
                match read_string(cursor) {
                    None => false,
                    Some(end) => {
                        cursor = end;
                        complete_value!();
                        true
                    }
                }
            } else if ch == Some('[') || ch == Some('{') {
                let kind_is_list = ch == Some('[');
                let group_inventory = pending_group_list;
                if group_inventory && !kind_is_list {
                    false
                } else if stack.len() >= MAX_GDB_MI_NESTED_VALUE_FRAMES {
                    false
                } else {
                    let parent_group_inventory =
                        stack.last().map(|f| f.group_inventory).unwrap_or(false);
                    let group_tuple = !kind_is_list && parent_group_inventory;
                    pending_group_list = false;
                    cursor += 1;
                    stack.push(Frame {
                        kind_is_list,
                        close: if kind_is_list { ']' } else { '}' },
                        group_inventory,
                        group_start: if group_inventory {
                            Some(value_start as usize)
                        } else {
                            None
                        },
                        group_tuple,
                        phase: Phase::First,
                        list_items: None,
                        group_id_seen: false,
                    });
                    true
                }
            } else {
                false
            }
        }};
    }

    loop {
        if stack.is_empty() {
            if cursor == chars.len() {
                break;
            }
            if chars.get(cursor) != Some(',') {
                return None;
            }
            cursor += 1;
            let name_end = read_name(cursor);
            if name_end == cursor || chars.get(name_end) != Some('=') {
                return None;
            }
            let name = chars.slice(cursor, name_end);
            if name == "groups" {
                if group_seen {
                    return None;
                }
                group_seen = true;
                value_start = (name_end + 1) as isize;
                pending_group_list = true;
            }
            cursor = name_end + 1;
            if !begin_value!() {
                return None;
            }
            continue;
        }

        let frame_phase = stack.last().unwrap().phase;
        let frame_close = stack.last().unwrap().close;
        let frame_kind_is_list = stack.last().unwrap().kind_is_list;

        if frame_phase == Phase::AfterItem {
            if chars.get(cursor) == Some(',') {
                cursor += 1;
                stack.last_mut().unwrap().phase = Phase::AfterComma;
                continue;
            }
            if chars.get(cursor) != Some(frame_close) {
                return None;
            }
            let frame = stack.last().unwrap();
            if frame.group_tuple && !frame.group_id_seen {
                return None;
            }
            cursor += 1;
            let frame = stack.pop().unwrap();
            if frame.group_inventory {
                let start = frame.group_start?;
                group_span = Some(Span { start, end: cursor });
            }
            complete_value!();
            continue;
        }

        if frame_phase == Phase::First && chars.get(cursor) == Some(frame_close) {
            let frame = stack.last().unwrap();
            if frame.group_tuple && !frame.group_id_seen {
                return None;
            }
            cursor += 1;
            let frame = stack.pop().unwrap();
            if frame.group_inventory {
                let start = frame.group_start?;
                group_span = Some(Span { start, end: cursor });
            }
            complete_value!();
            continue;
        }

        if frame_phase == Phase::First || frame_phase == Phase::AfterComma {
            if !frame_kind_is_list {
                // tuple
                let name_end = read_name(cursor);
                if name_end == cursor || chars.get(name_end) != Some('=') {
                    return None;
                }
                let frame = stack.last_mut().unwrap();
                if frame.group_tuple && chars.slice(cursor, name_end) == "id" {
                    if frame.group_id_seen || chars.get(name_end + 1) != Some('"') {
                        return None;
                    }
                    frame.group_id_seen = true;
                }
                cursor = name_end + 1;
                if !begin_value!() {
                    return None;
                }
                continue;
            }
            // list
            let name_end = read_name(cursor);
            let item_is_result = name_end > cursor && chars.get(name_end) == Some('=');
            let item_kind = if item_is_result {
                ListItems::Result
            } else {
                ListItems::Value
            };
            {
                let frame = stack.last_mut().unwrap();
                if let Some(existing) = frame.list_items {
                    if existing != item_kind {
                        return None;
                    }
                }
                frame.list_items = Some(item_kind);
                if frame.group_inventory && (item_is_result || chars.get(cursor) != Some('{')) {
                    return None;
                }
            }
            if item_is_result {
                cursor = name_end + 1;
            }
            if !begin_value!() {
                return None;
            }
            continue;
        }

        return None;
    }

    group_span
}

/// Parse live PIDs in recursive GDB MI thread groups (`gdbThreadGroupPids`).
pub(super) fn gdb_thread_group_pids(mi: &str) -> Option<Vec<String>> {
    let groups_span = gdb_mi_groups_list_span(mi)?;
    let chars = Chars::new(mi);
    let start = groups_span.start + 1;
    let mut square_depth = 1i64;
    let mut object_depth = 0i64;
    let mut quoted = false;
    let mut escaped = false;
    let mut pids: Vec<String> = Vec::new();
    let mut field_start = start;
    let mut pid_start: Option<usize> = None;
    let mut has_live_pid = false;
    let mut current_pid: Option<String> = None;

    let mut index = start;
    while index < chars.len() {
        let ch = chars.get(index).unwrap();
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
                if let Some(ps) = pid_start {
                    let pid = chars.slice(ps, index);
                    if !is_positive_decimal(&pid) {
                        return None;
                    }
                    has_live_pid = true;
                    current_pid = Some(pid);
                    pid_start = None;
                }
            }
            index += 1;
            continue;
        }
        if (index > 0 && (chars.get(index - 1) == Some('{') || chars.get(index - 1) == Some(',')))
            && chars.starts_with_at("groups=", index)
        {
            return None;
        }
        if ch == '"' {
            if square_depth == 1 && object_depth == 1 && chars.slice(field_start, index) == "pid=" {
                if has_live_pid {
                    return None;
                }
                pid_start = Some(index + 1);
            }
            quoted = true;
            index += 1;
            continue;
        }
        if ch == '[' {
            square_depth += 1;
        } else if ch == ']' {
            square_depth -= 1;
            if square_depth == 0 {
                if object_depth != 0 || index + 1 != groups_span.end {
                    return None;
                }
                return Some(pids);
            }
        } else if ch == '{' {
            if square_depth == 1 && object_depth == 0 {
                has_live_pid = false;
                current_pid = None;
                field_start = index + 1;
            }
            object_depth += 1;
        } else if ch == '}' {
            if square_depth == 1 && object_depth == 1 {
                let field = chars.slice(field_start, index);
                if field.starts_with("pid=") && !is_pid_field(&field) {
                    return None;
                }
            }
            object_depth -= 1;
            if object_depth < 0 {
                return None;
            }
            if square_depth == 1 && object_depth == 0 && has_live_pid {
                match &current_pid {
                    None => return None,
                    Some(pid) => pids.push(pid.clone()),
                }
            }
        } else if ch == ',' && square_depth == 1 && object_depth == 1 {
            let field = chars.slice(field_start, index);
            if field.starts_with("pid=") && !is_pid_field(&field) {
                return None;
            }
            field_start = index + 1;
        }
        index += 1;
    }
    None
}

/// Count recursive GDB MI groups with live PIDs (`gdbThreadGroupCount`).
pub(super) fn gdb_thread_group_count(mi: &str) -> Option<usize> {
    gdb_thread_group_pids(mi).map(|pids| pids.len())
}

fn is_positive_decimal(value: &str) -> bool {
    !value.is_empty() && value.as_bytes()[0] != b'0' && value.bytes().all(|b| b.is_ascii_digit())
}

/// `pid="[1-9]\d*"` exact match on a whole field.
fn is_pid_field(field: &str) -> bool {
    let inner = match field
        .strip_prefix("pid=\"")
        .and_then(|f| f.strip_suffix('"'))
    {
        Some(inner) => inner,
        None => return false,
    };
    is_positive_decimal(inner)
}

/// Decode one unambiguous GDB MI C-string field (`miStringField`).
pub(super) fn mi_string_field(record: &str, field: &str) -> Option<String> {
    // Count occurrences of `(?:^|,)field="..."`; require exactly one, then the
    // whole record must be `^\d+\^done,field="..."$`.
    let occurrences = count_field_occurrences(record, field);
    if occurrences != 1 {
        return None;
    }
    let raw = whole_record_field_value(record, field)?;
    decode_mi_cstring(&raw)
}

fn count_field_occurrences(record: &str, field: &str) -> usize {
    // Matches /(?:^|,)field="(?:\\.|[^"\\])*"/ globally (non-overlapping).
    let chars: Vec<char> = record.chars().collect();
    let field_chars: Vec<char> = field.chars().collect();
    let mut count = 0usize;
    let mut index = 0usize;
    while index < chars.len() {
        let at_boundary = index == 0 || chars[index - 1] == ',';
        if at_boundary && slice_eq(&chars, index, &field_chars) {
            let after = index + field_chars.len();
            if chars.get(after) == Some(&'=') && chars.get(after + 1) == Some(&'"') {
                // consume the quoted value
                let mut c = after + 2;
                let mut ok = false;
                while c < chars.len() {
                    match chars[c] {
                        '\\' => {
                            c += 2;
                        }
                        '"' => {
                            ok = true;
                            c += 1;
                            break;
                        }
                        _ => c += 1,
                    }
                }
                if ok {
                    count += 1;
                    index = c;
                    continue;
                }
            }
        }
        index += 1;
    }
    count
}

fn slice_eq(haystack: &[char], at: usize, needle: &[char]) -> bool {
    if at + needle.len() > haystack.len() {
        return false;
    }
    haystack[at..at + needle.len()] == needle[..]
}

/// Match the whole record `^\d+\^done,field="VALUE"$` and return raw VALUE.
fn whole_record_field_value(record: &str, field: &str) -> Option<String> {
    let chars: Vec<char> = record.chars().collect();
    let mut cursor = 0usize;
    let mut digits = 0usize;
    while matches!(chars.get(cursor), Some(c) if c.is_ascii_digit()) {
        cursor += 1;
        digits += 1;
    }
    if digits == 0 {
        return None;
    }
    let prefix = "^done,";
    if !slice_eq(&chars, cursor, &prefix.chars().collect::<Vec<_>>()) {
        return None;
    }
    cursor += prefix.chars().count();
    let field_chars: Vec<char> = field.chars().collect();
    if !slice_eq(&chars, cursor, &field_chars) {
        return None;
    }
    cursor += field_chars.len();
    if chars.get(cursor) != Some(&'=') || chars.get(cursor + 1) != Some(&'"') {
        return None;
    }
    cursor += 2;
    let value_start = cursor;
    // consume (?:\\.|[^"\\])* then require closing " at end of record
    while cursor < chars.len() {
        match chars[cursor] {
            '\\' => {
                if cursor + 1 >= chars.len() {
                    return None;
                }
                cursor += 2;
            }
            '"' => {
                // must be the last character
                if cursor + 1 != chars.len() {
                    return None;
                }
                let raw: String = chars[value_start..cursor].iter().collect();
                return Some(raw);
            }
            _ => cursor += 1,
        }
    }
    None
}

/// Decode the C-string escapes of an MI field value into UTF-8 text, or `None`
/// when a byte sequence is not valid UTF-8 or a surrogate is present.
fn decode_mi_cstring(raw: &str) -> Option<String> {
    let chars: Vec<char> = raw.chars().collect();
    let mut bytes: Vec<u8> = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        if ch != '\\' {
            // surrogate code points cannot appear in a Rust char; push UTF-8.
            let mut buf = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buf);
            bytes.extend_from_slice(encoded.as_bytes());
            index += 1;
            continue;
        }
        index += 1;
        let escaped = *chars.get(index)?;
        let simple = match escaped {
            'a' => Some(7u8),
            'b' => Some(8),
            'f' => Some(12),
            'n' => Some(10),
            'r' => Some(13),
            't' => Some(9),
            'v' => Some(11),
            '\\' => Some(92),
            '"' => Some(34),
            '\'' => Some(39),
            '?' => Some(63),
            _ => None,
        };
        if let Some(byte) = simple {
            bytes.push(byte);
            index += 1;
            continue;
        }
        if escaped == 'x' {
            let mut hex = String::new();
            let mut c = index + 1;
            while matches!(chars.get(c), Some(h) if h.is_ascii_hexdigit()) {
                hex.push(chars[c]);
                c += 1;
            }
            if hex.is_empty() {
                return None;
            }
            let value = u32::from_str_radix(&hex, 16).ok()?;
            bytes.push((value & 0xff) as u8);
            index = c;
            continue;
        }
        if ('0'..='7').contains(&escaped) {
            let mut octal = String::new();
            octal.push(escaped);
            let mut c = index + 1;
            while octal.len() < 3 && matches!(chars.get(c), Some(o) if ('0'..='7').contains(o)) {
                octal.push(chars[c]);
                c += 1;
            }
            let value = u32::from_str_radix(&octal, 8).ok()?;
            bytes.push((value & 0xff) as u8);
            index = index + octal.len();
            continue;
        }
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Classify commands that can invalidate the configured output sink
/// (`commandMayChangeInferiorOutput`).
pub(super) fn command_may_change_inferior_output(command: &str) -> bool {
    let setting = regex_set_with_first(command);
    let may_set_inferior_tty = setting
        .as_ref()
        .map(|s| "inferior-tty".starts_with(&s.to_lowercase()))
        .unwrap_or(false);
    let first_token = first_token(command).map(|t| t.to_lowercase());
    let may_be_tty_command = first_token
        .as_ref()
        .map(|t| "tty".starts_with(t.as_str()))
        .unwrap_or(false);
    let may_define_alias = first_token
        .as_ref()
        .map(|t| "alias".starts_with(t.as_str()))
        .unwrap_or(false);
    let may_run_with_output_redirection = first_token
        .as_ref()
        .map(|first| {
            ["run", "start", "starti"]
                .iter()
                .any(|n| n.starts_with(first.as_str()))
                && contains_redirection(&command[first.len().min(command.len())..])
        })
        .unwrap_or(false);

    may_set_inferior_tty
        || may_be_tty_command
        || may_define_alias
        || contains_inferior_tty_word(command)
        || matches_output_sink_commands(command)
        || may_run_with_output_redirection
}

/// `/^\s*(?:set|with)\s+(\S+)/i` → first setting token.
fn regex_set_with_first(command: &str) -> Option<String> {
    let trimmed = command.trim_start();
    let lower = trimmed.to_lowercase();
    let rest = if let Some(rest) = lower.strip_prefix("set") {
        rest
    } else if let Some(rest) = lower.strip_prefix("with") {
        rest
    } else {
        return None;
    };
    // original keyword must be followed by whitespace, then \S+
    let keyword_len = trimmed.len() - rest.len();
    let after = &trimmed[keyword_len..];
    if !after.starts_with(char::is_whitespace) {
        return None;
    }
    let after = after.trim_start();
    if after.is_empty() {
        return None;
    }
    let token: String = after.chars().take_while(|c| !c.is_whitespace()).collect();
    if token.is_empty() { None } else { Some(token) }
}

/// `/^\s*([^\s;]+)/` → first token.
fn first_token(command: &str) -> Option<String> {
    let trimmed = command.trim_start();
    let token: String = trimmed
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ';')
        .collect();
    if token.is_empty() { None } else { Some(token) }
}

fn contains_redirection(value: &str) -> bool {
    // /[<>]{1,2}|&>/
    value.contains('<') || value.contains('>') || value.contains("&>")
}

fn contains_inferior_tty_word(command: &str) -> bool {
    // /\binferior-tty\b/i
    command.to_lowercase().contains("inferior-tty")
}

/// `/^\s*(?:wit(?:h)?(?:\s|$)|tty(?:\s|$)|source\b|py\w*|define\b)/i`.
fn matches_output_sink_commands(command: &str) -> bool {
    let trimmed = command.trim_start().to_lowercase();
    // wit or with followed by whitespace or end
    for prefix in ["with", "wit"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                return true;
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("tty") {
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            return true;
        }
    }
    if let Some(rest) = trimmed.strip_prefix("source") {
        if rest.is_empty() || !starts_word_char(rest) {
            return true;
        }
    }
    if let Some(rest) = trimmed.strip_prefix("py") {
        // py\w* : py followed by zero or more word chars at the start
        let _ = rest;
        return true;
    }
    if let Some(rest) = trimmed.strip_prefix("define") {
        if rest.is_empty() || !starts_word_char(rest) {
            return true;
        }
    }
    false
}

fn starts_word_char(value: &str) -> bool {
    value
        .chars()
        .next()
        .map(|c| c.is_alphanumeric() || c == '_')
        .unwrap_or(false)
}
