//! Output formatting ported from incur's `Formatter`, `Filter` and `tokenx`.
//!
//! REA's CLI advertises five formats: `toon` (default), `json`, `jsonl`,
//! `yaml`, and `md`. `toon` is ported from `@toon-format/toon` with REA's
//! fixed options (indent 2, comma delimiter, key folding off). The token
//! helpers mirror `tokenx` for `--token-count`/`--token-limit`/`--token-offset`.
use serde_json::Value;

/// Supported CLI output formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Toon,
    Json,
    Yaml,
    Md,
    Jsonl,
}

impl Format {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "toon" => Some(Self::Toon),
            "json" => Some(Self::Json),
            "yaml" => Some(Self::Yaml),
            "md" => Some(Self::Md),
            "jsonl" => Some(Self::Jsonl),
            _ => None,
        }
    }
}

/// Serialize a value to the requested format. `null` renders as the empty
/// string, matching `Formatter.format`.
pub fn format(value: &Value, fmt: Format) -> String {
    if value.is_null() {
        return String::new();
    }
    match fmt {
        Format::Json => json_pretty(value),
        Format::Jsonl => {
            if let Some(items) = value.as_array() {
                items
                    .iter()
                    .map(json_compact)
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                json_compact(value)
            }
        }
        Format::Yaml => yaml::stringify(value),
        Format::Md => md::format_markdown(value, &[]),
        Format::Toon => {
            if is_scalar(value) {
                scalar_to_string(value)
            } else {
                toon::encode(value)
            }
        }
    }
}

fn is_scalar(value: &Value) -> bool {
    !value.is_object() && !value.is_array()
}

fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// Pretty two-space JSON (human and `--format json`).
pub fn json_pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_owned())
}

/// Compact JSON (one line).
pub fn json_compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

// ---------------------------------------------------------------------------
// TOON encoder (REA options: indent 2, delimiter ',', key folding off)
// ---------------------------------------------------------------------------
mod toon {
    use serde_json::Value;

    pub fn encode(value: &Value) -> String {
        let mut lines = Vec::new();
        match value {
            Value::Array(items) => encode_array(None, items, 0, &mut lines),
            Value::Object(_) => encode_object(value, 0, &mut lines),
            _ => lines.push(encode_primitive(value)),
        }
        lines.join("\n")
    }

    fn indent(depth: usize) -> String {
        " ".repeat(2 * depth)
    }

    fn encode_primitive(value: &Value) -> String {
        match value {
            Value::Null => "null".to_owned(),
            Value::Bool(flag) => flag.to_string(),
            Value::Number(number) => number.to_string(),
            Value::String(text) => encode_string_literal(text),
            // Nested containers never reach here through the primitive paths.
            other => other.to_string(),
        }
    }

    fn encode_string_literal(value: &str) -> String {
        if is_safe_unquoted(value) {
            value.to_owned()
        } else {
            format!("\"{}\"", escape_string(value))
        }
    }

    fn escape_string(value: &str) -> String {
        let mut out = String::with_capacity(value.len() + 2);
        for ch in value.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out
    }

    fn is_boolean_or_null_literal(value: &str) -> bool {
        matches!(value, "true" | "false" | "null")
    }

    fn is_numeric_like(value: &str) -> bool {
        // ^-?\d+(?:\.\d+)?(?:e[+-]?\d+)?$  (case-insensitive) OR ^0\d+$
        let bytes = value.as_bytes();
        if bytes.len() >= 2 && bytes[0] == b'0' && bytes[1].is_ascii_digit() {
            return value[1..].bytes().all(|b| b.is_ascii_digit());
        }
        let mut chars = value.chars().peekable();
        if chars.peek() == Some(&'-') {
            chars.next();
        }
        let mut saw_digit = false;
        while matches!(chars.peek(), Some(c) if c.is_ascii_digit()) {
            chars.next();
            saw_digit = true;
        }
        if !saw_digit {
            return false;
        }
        if chars.peek() == Some(&'.') {
            chars.next();
            let mut frac = false;
            while matches!(chars.peek(), Some(c) if c.is_ascii_digit()) {
                chars.next();
                frac = true;
            }
            if !frac {
                return false;
            }
        }
        if matches!(chars.peek(), Some('e') | Some('E')) {
            chars.next();
            if matches!(chars.peek(), Some('+') | Some('-')) {
                chars.next();
            }
            let mut exp = false;
            while matches!(chars.peek(), Some(c) if c.is_ascii_digit()) {
                chars.next();
                exp = true;
            }
            if !exp {
                return false;
            }
        }
        chars.peek().is_none()
    }

    fn is_safe_unquoted(value: &str) -> bool {
        if value.is_empty() {
            return false;
        }
        if value != value.trim() {
            return false;
        }
        if is_boolean_or_null_literal(value) || is_numeric_like(value) {
            return false;
        }
        if value.contains(':') || value.contains('"') || value.contains('\\') {
            return false;
        }
        if value.contains(['[', ']', '{', '}']) {
            return false;
        }
        if value.chars().any(|c| (c as u32) < 0x20) {
            return false;
        }
        if value.contains(',') {
            return false;
        }
        if value.starts_with('-') {
            return false;
        }
        true
    }

    fn is_valid_unquoted_key(key: &str) -> bool {
        // ^[A-Z_][\w.]*$  case-insensitive (word char = [A-Za-z0-9_])
        let mut chars = key.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    }

    fn encode_key(key: &str) -> String {
        if is_valid_unquoted_key(key) {
            key.to_owned()
        } else {
            format!("\"{}\"", escape_string(key))
        }
    }

    fn is_json_primitive(value: &Value) -> bool {
        !value.is_object() && !value.is_array()
    }

    fn format_header(len: usize, key: Option<&str>, fields: Option<&[String]>) -> String {
        let mut header = String::new();
        if let Some(key) = key {
            header.push_str(&encode_key(key));
        }
        header.push_str(&format!("[{len}]"));
        if let Some(fields) = fields {
            let joined = fields
                .iter()
                .map(|field| encode_key(field))
                .collect::<Vec<_>>()
                .join(",");
            header.push('{');
            header.push_str(&joined);
            header.push('}');
        }
        header.push(':');
        header
    }

    fn join_primitives(items: &[Value]) -> String {
        items
            .iter()
            .map(encode_primitive)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn inline_array_line(items: &[Value], key: Option<&str>) -> String {
        let header = format_header(items.len(), key, None);
        if items.is_empty() {
            header
        } else {
            format!("{header} {}", join_primitives(items))
        }
    }

    fn array_of_primitives(items: &[Value]) -> bool {
        items.iter().all(is_json_primitive)
    }

    fn array_of_arrays(items: &[Value]) -> bool {
        items.iter().all(Value::is_array)
    }

    fn array_of_objects(items: &[Value]) -> bool {
        items.iter().all(Value::is_object)
    }

    fn tabular_header(items: &[Value]) -> Option<Vec<String>> {
        let first = items.first()?.as_object()?;
        if first.is_empty() {
            return None;
        }
        let header: Vec<String> = first.keys().cloned().collect();
        for row in items {
            let object = row.as_object()?;
            if object.len() != header.len() {
                return None;
            }
            for key in &header {
                match object.get(key) {
                    Some(value) if is_json_primitive(value) => {}
                    _ => return None,
                }
            }
        }
        Some(header)
    }

    fn encode_object(value: &Value, depth: usize, lines: &mut Vec<String>) {
        let Some(object) = value.as_object() else {
            return;
        };
        for (key, val) in object {
            encode_pair(key, val, depth, lines);
        }
    }

    fn encode_pair(key: &str, value: &Value, depth: usize, lines: &mut Vec<String>) {
        let encoded_key = encode_key(key);
        match value {
            Value::Array(items) => encode_array(Some(key), items, depth, lines),
            Value::Object(object) => {
                lines.push(format!("{}{encoded_key}:", indent(depth)));
                if !object.is_empty() {
                    encode_object(value, depth + 1, lines);
                }
            }
            primitive => lines.push(format!(
                "{}{encoded_key}: {}",
                indent(depth),
                encode_primitive(primitive)
            )),
        }
    }

    fn encode_array(key: Option<&str>, items: &[Value], depth: usize, lines: &mut Vec<String>) {
        if items.is_empty() {
            let body = match key {
                Some(key) => format!("{}: []", encode_key(key)),
                None => "[]".to_owned(),
            };
            lines.push(format!("{}{body}", indent(depth)));
            return;
        }
        if array_of_primitives(items) {
            lines.push(format!(
                "{}{}",
                indent(depth),
                inline_array_line(items, key)
            ));
            return;
        }
        if array_of_arrays(items)
            && items
                .iter()
                .all(|arr| array_of_primitives(arr.as_array().unwrap()))
        {
            lines.push(format!(
                "{}{}",
                indent(depth),
                format_header(items.len(), key, None)
            ));
            for arr in items {
                let inner = arr.as_array().unwrap();
                lines.push(format!(
                    "{}- {}",
                    indent(depth + 1),
                    inline_array_line(inner, None)
                ));
            }
            return;
        }
        if array_of_objects(items) {
            if let Some(header) = tabular_header(items) {
                lines.push(format!(
                    "{}{}",
                    indent(depth),
                    format_header(items.len(), key, Some(&header))
                ));
                for row in items {
                    let object = row.as_object().unwrap();
                    let cells: Vec<Value> = header
                        .iter()
                        .map(|k| object.get(k).cloned().unwrap_or(Value::Null))
                        .collect();
                    lines.push(format!("{}{}", indent(depth + 1), join_primitives(&cells)));
                }
                return;
            }
        }
        lines.push(format!(
            "{}{}",
            indent(depth),
            format_header(items.len(), key, None)
        ));
        for item in items {
            encode_list_item(item, depth + 1, lines);
        }
    }

    fn encode_list_item(value: &Value, depth: usize, lines: &mut Vec<String>) {
        match value {
            Value::Array(items) => {
                if array_of_primitives(items) {
                    lines.push(format!(
                        "{}- {}",
                        indent(depth),
                        inline_array_line(items, None)
                    ));
                } else {
                    lines.push(format!(
                        "{}- {}",
                        indent(depth),
                        format_header(items.len(), None, None)
                    ));
                    for item in items {
                        encode_list_item(item, depth + 1, lines);
                    }
                }
            }
            Value::Object(_) => encode_object_as_list_item(value, depth, lines),
            primitive => lines.push(format!(
                "{}- {}",
                indent(depth),
                encode_primitive(primitive)
            )),
        }
    }

    fn encode_object_as_list_item(value: &Value, depth: usize, lines: &mut Vec<String>) {
        let object = value.as_object().unwrap();
        if object.is_empty() {
            lines.push(format!("{}-", indent(depth)));
            return;
        }
        let mut entries = object.iter();
        let (first_key, first_value) = entries.next().unwrap();
        let encoded_key = encode_key(first_key);
        match first_value {
            Value::Array(items) if array_of_objects(items) && tabular_header(items).is_some() => {
                let header = tabular_header(items).unwrap();
                lines.push(format!(
                    "{}- {}",
                    indent(depth),
                    format_header(items.len(), Some(first_key), Some(&header))
                ));
                for row in items {
                    let row_object = row.as_object().unwrap();
                    let cells: Vec<Value> = header
                        .iter()
                        .map(|k| row_object.get(k).cloned().unwrap_or(Value::Null))
                        .collect();
                    lines.push(format!("{}{}", indent(depth + 2), join_primitives(&cells)));
                }
            }
            Value::Array(items) if items.is_empty() => {
                lines.push(format!("{}- {encoded_key}: []", indent(depth)));
            }
            Value::Array(items) if array_of_primitives(items) => {
                lines.push(format!(
                    "{}- {encoded_key}{}",
                    indent(depth),
                    inline_array_line(items, None)
                ));
            }
            Value::Array(items) => {
                lines.push(format!(
                    "{}- {encoded_key}{}",
                    indent(depth),
                    format_header(items.len(), None, None)
                ));
                for item in items {
                    encode_list_item(item, depth + 2, lines);
                }
            }
            Value::Object(inner) => {
                lines.push(format!("{}- {encoded_key}:", indent(depth)));
                if !inner.is_empty() {
                    encode_object(first_value, depth + 2, lines);
                }
            }
            primitive => lines.push(format!(
                "{}- {encoded_key}: {}",
                indent(depth),
                encode_primitive(primitive)
            )),
        }
        // Remaining entries render as ordinary object lines one level deeper.
        if object.len() > 1 {
            let mut rest = serde_json::Map::new();
            for (key, val) in object.iter().skip(1) {
                rest.insert(key.clone(), val.clone());
            }
            encode_object(&Value::Object(rest), depth + 1, lines);
        }
    }
}

// ---------------------------------------------------------------------------
// YAML block emitter (practical subset of the `yaml` package defaults)
// ---------------------------------------------------------------------------
mod yaml {
    use serde_json::Value;

    pub fn stringify(value: &Value) -> String {
        let mut out = String::new();
        match value {
            Value::Object(object) if object.is_empty() => out.push_str("{}"),
            Value::Array(items) if items.is_empty() => out.push_str("[]"),
            Value::Object(_) | Value::Array(_) => emit(value, 0, &mut out),
            other => out.push_str(&scalar(other)),
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out
    }

    fn scalar(value: &Value) -> String {
        match value {
            Value::Null => "null".to_owned(),
            Value::Bool(flag) => flag.to_string(),
            Value::Number(number) => number.to_string(),
            Value::String(text) => scalar_string(text),
            other => other.to_string(),
        }
    }

    fn scalar_string(value: &str) -> String {
        if needs_quoting(value) {
            serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""))
        } else {
            value.to_owned()
        }
    }

    fn needs_quoting(value: &str) -> bool {
        if value.is_empty() {
            return true;
        }
        if value != value.trim() {
            return true;
        }
        if matches!(
            value,
            "null" | "Null" | "NULL" | "~" | "true" | "false" | "True" | "False"
        ) {
            return true;
        }
        if is_number_like(value) {
            return true;
        }
        let first = value.chars().next().unwrap();
        if "!&*?|>%@`\"'#,[]{}:-".contains(first) {
            return true;
        }
        value
            .chars()
            .any(|c| c == '\n' || c == ':' || (c as u32) < 0x20)
    }

    fn is_number_like(value: &str) -> bool {
        value.parse::<f64>().is_ok()
    }

    fn emit(value: &Value, depth: usize, out: &mut String) {
        match value {
            Value::Object(object) => {
                for (key, val) in object {
                    emit_pair(key, val, depth, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    emit_item(item, depth, out);
                }
            }
            _ => {}
        }
    }

    fn pad(depth: usize) -> String {
        "  ".repeat(depth)
    }

    fn emit_pair(key: &str, value: &Value, depth: usize, out: &mut String) {
        let key_text = scalar_string(key);
        match value {
            Value::Object(object) if object.is_empty() => {
                out.push_str(&format!("{}{key_text}: {{}}\n", pad(depth)));
            }
            Value::Array(items) if items.is_empty() => {
                out.push_str(&format!("{}{key_text}: []\n", pad(depth)));
            }
            Value::Object(_) | Value::Array(_) => {
                out.push_str(&format!("{}{key_text}:\n", pad(depth)));
                let child = if value.is_array() { depth } else { depth + 1 };
                emit(value, child, out);
            }
            scalar_value => {
                out.push_str(&format!(
                    "{}{key_text}: {}\n",
                    pad(depth),
                    scalar(scalar_value)
                ));
            }
        }
    }

    fn emit_item(value: &Value, depth: usize, out: &mut String) {
        match value {
            Value::Object(object) if object.is_empty() => {
                out.push_str(&format!("{}- {{}}\n", pad(depth)));
            }
            Value::Array(items) if items.is_empty() => {
                out.push_str(&format!("{}- []\n", pad(depth)));
            }
            Value::Object(object) => {
                let mut first = true;
                for (key, val) in object {
                    let key_text = scalar_string(key);
                    if first {
                        first = false;
                        match val {
                            Value::Object(inner) if inner.is_empty() => {
                                out.push_str(&format!("{}- {key_text}: {{}}\n", pad(depth)));
                            }
                            Value::Array(inner) if inner.is_empty() => {
                                out.push_str(&format!("{}- {key_text}: []\n", pad(depth)));
                            }
                            Value::Object(_) | Value::Array(_) => {
                                out.push_str(&format!("{}- {key_text}:\n", pad(depth)));
                                let child = if val.is_array() { depth + 1 } else { depth + 2 };
                                emit(val, child, out);
                            }
                            scalar_value => out.push_str(&format!(
                                "{}- {key_text}: {}\n",
                                pad(depth),
                                scalar(scalar_value)
                            )),
                        }
                    } else {
                        emit_pair(key, val, depth + 1, out);
                    }
                }
            }
            Value::Array(_) => {
                out.push_str(&format!("{}-\n", pad(depth)));
                emit(value, depth + 1, out);
            }
            scalar_value => out.push_str(&format!("{}- {}\n", pad(depth), scalar(scalar_value))),
        }
    }
}

// ---------------------------------------------------------------------------
// Markdown formatter (port of incur Formatter.formatMarkdown)
// ---------------------------------------------------------------------------
mod md {
    use serde_json::{Map, Value};

    fn is_scalar(value: &Value) -> bool {
        !value.is_object() && !value.is_array()
    }

    fn scalar_text(value: &Value) -> String {
        match value {
            Value::Null => "null".to_owned(),
            Value::Bool(flag) => flag.to_string(),
            Value::Number(number) => number.to_string(),
            Value::String(text) => text.clone(),
            other => other.to_string(),
        }
    }

    fn is_array_of_objects(value: &Value) -> bool {
        matches!(value, Value::Array(items) if !items.is_empty() && items.iter().all(Value::is_object))
    }

    fn is_flat(object: &Map<String, Value>) -> bool {
        object.values().all(is_scalar)
    }

    fn table(headers: &[String], rows: &[Vec<String>]) -> String {
        let widths: Vec<usize> = headers
            .iter()
            .enumerate()
            .map(|(index, header)| {
                rows.iter()
                    .map(|row| row.get(index).map_or(0, |cell| cell.len()))
                    .max()
                    .unwrap_or(0)
                    .max(header.len())
            })
            .collect();
        let pad = |text: &str, index: usize| format!("{text:<width$}", width = widths[index]);
        let header_row = format!(
            "| {} |",
            headers
                .iter()
                .enumerate()
                .map(|(index, header)| pad(header, index))
                .collect::<Vec<_>>()
                .join(" | ")
        );
        let separator = format!(
            "|{}|",
            widths
                .iter()
                .map(|width| "-".repeat(width + 2))
                .collect::<Vec<_>>()
                .join("|")
        );
        let body = rows
            .iter()
            .map(|row| {
                format!(
                    "| {} |",
                    headers
                        .iter()
                        .enumerate()
                        .map(|(index, _)| pad(
                            row.get(index).map_or("", |cell| cell.as_str()),
                            index
                        ))
                        .collect::<Vec<_>>()
                        .join(" | ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!("{header_row}\n{separator}\n{body}")
    }

    fn kv_table(object: &Map<String, Value>) -> String {
        let rows: Vec<Vec<String>> = object
            .iter()
            .map(|(key, value)| vec![key.clone(), scalar_text(value)])
            .collect();
        table(&["Key".to_owned(), "Value".to_owned()], &rows)
    }

    fn columnar_table(items: &[Value]) -> String {
        let mut keys: Vec<String> = Vec::new();
        for item in items {
            if let Some(object) = item.as_object() {
                for key in object.keys() {
                    if !keys.contains(key) {
                        keys.push(key.clone());
                    }
                }
            }
        }
        let rows: Vec<Vec<String>> = items
            .iter()
            .map(|item| {
                keys.iter()
                    .map(|key| item.get(key).map_or(String::new(), scalar_text))
                    .collect()
            })
            .collect();
        table(&keys, &rows)
    }

    pub fn format_markdown(value: &Value, path: &[String]) -> String {
        if is_scalar(value) {
            if path.is_empty() {
                return scalar_text(value);
            }
            return format!("## {}\n\n{}", path.join("."), scalar_text(value));
        }
        if let Value::Array(items) = value {
            if is_array_of_objects(value) {
                let rendered = columnar_table(items);
                if path.is_empty() {
                    return rendered;
                }
                return format!("## {}\n\n{rendered}", path.join("."));
            }
            return format_markdown(&Value::String(scalar_text(value)), path);
        }
        let object = value.as_object().unwrap();
        let entries: Vec<(&String, &Value)> = object.iter().collect();
        if path.is_empty() && is_flat(object) {
            return kv_table(object);
        }
        let needs_headings = !path.is_empty()
            || entries.len() > 1
            || entries.iter().any(|(_, value)| !is_scalar(value));
        if needs_headings {
            let sections: Vec<String> = entries
                .iter()
                .map(|(key, val)| {
                    let mut child = path.to_vec();
                    child.push((*key).clone());
                    if is_scalar(val) {
                        format!("## {}\n\n{}", child.join("."), scalar_text(val))
                    } else if is_array_of_objects(val) {
                        format!(
                            "## {}\n\n{}",
                            child.join("."),
                            columnar_table(val.as_array().unwrap())
                        )
                    } else if let Value::Object(nested) = val {
                        if is_flat(nested) {
                            format!("## {}\n\n{}", child.join("."), kv_table(nested))
                        } else {
                            format_markdown(val, &child)
                        }
                    } else {
                        format!("## {}\n\n{}", child.join("."), scalar_text(val))
                    }
                })
                .collect();
            return sections.join("\n\n");
        }
        kv_table(object)
    }
}

// ---------------------------------------------------------------------------
// Filter (port of incur Filter.parse / Filter.apply)
// ---------------------------------------------------------------------------
pub mod filter {
    use serde_json::{Map, Value};

    #[derive(Clone, Debug)]
    pub enum Segment {
        Key(String),
        Slice { start: i64, end: i64 },
    }

    pub type FilterPath = Vec<Segment>;

    pub fn parse(expression: &str) -> Vec<FilterPath> {
        let mut paths: Vec<FilterPath> = Vec::new();
        let mut tokens: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut depth = 0i32;
        for ch in expression.chars() {
            if ch == '[' {
                depth += 1;
            } else if ch == ']' {
                depth -= 1;
            }
            if ch == ',' && depth == 0 {
                tokens.push(std::mem::take(&mut current));
            } else {
                current.push(ch);
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }
        for token in tokens {
            let mut path: FilterPath = Vec::new();
            let mut remaining = token.as_str();
            while !remaining.is_empty() {
                match remaining.find('[') {
                    None => {
                        for part in remaining.split('.') {
                            if !part.is_empty() {
                                path.push(Segment::Key(part.to_owned()));
                            }
                        }
                        break;
                    }
                    Some(bracket) => {
                        let before = &remaining[..bracket];
                        for part in before.split('.') {
                            if !part.is_empty() {
                                path.push(Segment::Key(part.to_owned()));
                            }
                        }
                        let close = remaining[bracket..].find(']').map(|index| bracket + index);
                        let Some(close) = close else {
                            break;
                        };
                        let inner = &remaining[bracket + 1..close];
                        let mut pieces = inner.split(',');
                        let start = pieces
                            .next()
                            .unwrap_or("")
                            .trim()
                            .parse::<i64>()
                            .unwrap_or(0);
                        let end = pieces
                            .next()
                            .unwrap_or("")
                            .trim()
                            .parse::<i64>()
                            .unwrap_or(0);
                        path.push(Segment::Slice { start, end });
                        remaining = &remaining[close + 1..];
                        if let Some(stripped) = remaining.strip_prefix('.') {
                            remaining = stripped;
                        }
                    }
                }
            }
            paths.push(path);
        }
        paths
    }

    pub fn apply(data: &Value, paths: &[FilterPath]) -> Value {
        if paths.is_empty() {
            return data.clone();
        }
        if paths.len() == 1
            && paths[0].len() == 1
            && let Segment::Key(key) = &paths[0][0]
        {
            if let Value::Array(items) = data {
                return Value::Array(items.iter().map(|item| apply(item, paths)).collect());
            }
            if let Value::Object(object) = data {
                return match object.get(key) {
                    Some(value) if value.is_object() || value.is_array() => {
                        let mut single = Map::new();
                        single.insert(key.clone(), value.clone());
                        Value::Object(single)
                    }
                    Some(value) => value.clone(),
                    None => Value::Null,
                };
            }
            return Value::Null;
        }
        if let Value::Array(items) = data {
            return Value::Array(items.iter().map(|item| apply(item, paths)).collect());
        }
        let mut result = Map::new();
        for path in paths {
            merge(&mut result, data, path, 0);
        }
        Value::Object(result)
    }

    fn slice(items: &[Value], start: i64, end: i64) -> Vec<Value> {
        let len = items.len() as i64;
        let normalize = |index: i64| {
            if index < 0 {
                (len + index).max(0)
            } else {
                index.min(len)
            }
        };
        let start = normalize(start);
        let end = normalize(end);
        if start >= end {
            return Vec::new();
        }
        items[start as usize..end as usize].to_vec()
    }

    fn merge(target: &mut Map<String, Value>, data: &Value, segments: &[Segment], index: usize) {
        if index >= segments.len() {
            return;
        }
        let Value::Object(object) = data else {
            return;
        };
        let Segment::Key(key) = &segments[index] else {
            return;
        };
        let Some(value) = object.get(key) else {
            return;
        };
        if index + 1 >= segments.len() {
            target.insert(key.clone(), value.clone());
            return;
        }
        if let Segment::Slice { start, end } = &segments[index + 1] {
            let Value::Array(items) = value else {
                return;
            };
            let sliced = slice(items, *start, *end);
            if index + 2 >= segments.len() {
                target.insert(key.clone(), Value::Array(sliced));
                return;
            }
            let mapped: Vec<Value> = sliced
                .iter()
                .map(|item| {
                    let mut sub = Map::new();
                    merge(&mut sub, item, segments, index + 2);
                    Value::Object(sub)
                })
                .collect();
            target.insert(key.clone(), Value::Array(mapped));
            return;
        }
        if !value.is_object() {
            return;
        }
        let nested = target
            .entry(key.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if !nested.is_object() {
            *nested = Value::Object(Map::new());
        }
        if let Value::Object(nested_object) = nested {
            merge(nested_object, value, segments, index + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Token estimation (port of tokenx estimateTokenCount / sliceByTokens)
// ---------------------------------------------------------------------------
pub mod tokens {
    const DEFAULT_CHARS_PER_TOKEN: f64 = 6.0;
    const SHORT_TOKEN_THRESHOLD: usize = 3;

    fn is_whitespace(segment: &str) -> bool {
        !segment.is_empty() && segment.chars().all(char::is_whitespace)
    }

    fn is_cjk(segment: &str) -> bool {
        segment.chars().any(|c| {
            let code = c as u32;
            (0x4E00..=0x9FFF).contains(&code)
                || (0x3400..=0x4DBF).contains(&code)
                || (0x3000..=0x303F).contains(&code)
                || (0xFF00..=0xFFEF).contains(&code)
                || (0x30A0..=0x30FF).contains(&code)
                || (0x2E80..=0x2EFF).contains(&code)
                || (0x31C0..=0x31EF).contains(&code)
                || (0x3200..=0x33FF).contains(&code)
                || (0xAC00..=0xD7AF).contains(&code)
                || (0x1100..=0x11FF).contains(&code)
                || (0x3130..=0x318F).contains(&code)
                || (0xA960..=0xA97F).contains(&code)
                || (0xD7B0..=0xD7FF).contains(&code)
        })
    }

    fn is_numeric(segment: &str) -> bool {
        let mut chars = segment.chars();
        let mut saw = false;
        for c in chars.by_ref() {
            if c.is_ascii_digit() {
                saw = true;
            } else if c == '.' || c == ',' {
            } else {
                return false;
            }
        }
        saw
    }

    fn is_punctuation(segment: &str) -> bool {
        segment
            .chars()
            .any(|c| ".,!?;(){}[]<>:/\\|@#$%^&*+=`~_-".contains(c))
    }

    fn split_segments(text: &str) -> Vec<String> {
        // Split on whitespace runs and punctuation runs, keeping the separators,
        // mirroring tokenx's TOKEN_SPLIT_PATTERN.
        let mut segments: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut current_kind: Option<bool> = None; // Some(true)=separator run
        let is_sep = |c: char| c.is_whitespace() || ".,!?;(){}[]<>:/\\|@#$%^&*+=`~_-".contains(c);
        for c in text.chars() {
            let sep = is_sep(c);
            match current_kind {
                Some(kind) if kind == sep => current.push(c),
                _ => {
                    if !current.is_empty() {
                        segments.push(std::mem::take(&mut current));
                    }
                    current.push(c);
                    current_kind = Some(sep);
                }
            }
        }
        if !current.is_empty() {
            segments.push(current);
        }
        segments
    }

    fn segment_tokens(segment: &str) -> usize {
        if is_whitespace(segment) {
            return 0;
        }
        if is_cjk(segment) {
            return segment.chars().count();
        }
        if is_numeric(segment) {
            return 1;
        }
        if segment.chars().count() <= SHORT_TOKEN_THRESHOLD {
            return 1;
        }
        if is_punctuation(segment) {
            let count = segment.chars().count();
            return if count > 1 { count.div_ceil(2) } else { 1 };
        }
        let count = segment.chars().count() as f64;
        (count / DEFAULT_CHARS_PER_TOKEN).ceil() as usize
    }

    pub fn estimate(text: &str) -> usize {
        if text.is_empty() {
            return 0;
        }
        split_segments(text)
            .iter()
            .map(|segment| segment_tokens(segment))
            .sum()
    }

    pub fn slice(text: &str, start: usize, end: Option<usize>) -> String {
        if text.is_empty() {
            return String::new();
        }
        let end = end.unwrap_or(usize::MAX);
        if start >= end {
            return String::new();
        }
        let mut parts = String::new();
        let mut position = 0usize;
        for segment in split_segments(text) {
            if position >= end {
                break;
            }
            let count = segment_tokens(segment.as_str());
            let seg_end = position + count;
            if count == 0 {
                if position >= start && position < end {
                    parts.push_str(&segment);
                }
            } else if !(position >= end || seg_end <= start) {
                let overlap_start = start.saturating_sub(position).min(count);
                let overlap_end = (end - position).min(count);
                if overlap_start == 0 && overlap_end == count {
                    parts.push_str(&segment);
                } else {
                    let chars: Vec<char> = segment.chars().collect();
                    let char_start =
                        (overlap_start as f64 / count as f64 * chars.len() as f64).floor() as usize;
                    let char_end =
                        (overlap_end as f64 / count as f64 * chars.len() as f64).ceil() as usize;
                    let slice: String = chars
                        [char_start.min(chars.len())..char_end.min(chars.len())]
                        .iter()
                        .collect();
                    parts.push_str(&slice);
                }
            }
            position += count;
        }
        parts
    }
}
