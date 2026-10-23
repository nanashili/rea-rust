//! JavaScript-faithful JSON text facts shared by CDP capture owners.
//!
//! Compatibility owners: `src/domain/jsonShape.ts` (`inferJsonShape`),
//! `src/domain/paddedBase64.ts`, `src/domain/stringPatterns.ts`
//! (`isPaddedBase64`), the `canonicalize` package (RFC 8785 JCS) as used by
//! `src/domain/webInventory.ts` and `CdpCaptureStorageFingerprints.ts`, and
//! ECMAScript `Number.prototype.toString`.
//!
//! `inferJsonShape` parses with `JSON.parse` semantics (unbounded depth,
//! duplicate names keep their first position and last value, out-of-range
//! numbers are still numbers) through an explicit-stack scanner, so the
//! value-free shape never depends on a recursion limit.
use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

/// ECMAScript `Number::toString(10)`.
pub(crate) fn js_number_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if value == 0.0 {
        return "0".to_owned();
    }
    let sign = if value < 0.0 { "-" } else { "" };
    // Rust's `{:e}` is the shortest round-tripping digit string.
    let formatted = format!("{:e}", value.abs());
    let (mantissa, exponent) = formatted.split_once('e').unwrap_or((&formatted, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i64 = exponent.parse().unwrap_or(0);
    let k = digits.len() as i64;
    let n = exponent + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let e_sign = if e < 0 { "-" } else { "+" };
        if k == 1 {
            format!("{digits}e{e_sign}{}", e.abs())
        } else {
            format!("{}.{}e{e_sign}{}", &digits[..1], &digits[1..], e.abs())
        }
    };
    format!("{sign}{body}")
}

/// `canonicalize(value)` (RFC 8785): keys in UTF-16 code-unit order and
/// numbers in ECMAScript form.
pub(crate) fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&match number.as_f64() {
            Some(float) if float.is_finite() => js_number_string(float),
            _ => "null".to_owned(),
        }),
        Value::String(text) => out.push_str(&Value::String(text.clone()).to_string()),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
    }
}

/// `paddedBase64ByteLength`.
pub(crate) fn padded_base64_byte_length(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    if bytes.len() % 4 != 0
        || bytes
            .iter()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')))
        || value.contains("===")
        || bytes
            .windows(2)
            .any(|pair| pair[0] == b'=' && pair[1] != b'=')
    {
        return None;
    }
    let padding = if value.ends_with("==") {
        2
    } else {
        usize::from(value.ends_with('='))
    };
    Some(bytes.len() / 4 * 3 - padding)
}

/// `decodePaddedBase64` (`Buffer.from(value, "base64")` after validation).
pub(crate) fn decode_padded_base64(value: &str) -> Option<Vec<u8>> {
    padded_base64_byte_length(value)?;
    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    LENIENT.decode(value).ok()
}

/// `String.prototype.length` (UTF-16 code units).
pub(crate) fn utf16_length(text: &str) -> usize {
    text.encode_utf16().count()
}

/// One parsed JSON value, reduced to the structure `inferJsonShape` reads.
enum Node {
    Object(Vec<(String, Node)>),
    Array(Vec<Node>),
    String,
    Number,
    Boolean,
    Null,
}

impl Node {
    fn type_name(&self) -> &'static str {
        match self {
            Node::Object(_) => "object",
            Node::Array(_) => "array",
            Node::String => "string",
            Node::Number => "number",
            Node::Boolean => "boolean",
            Node::Null => "null",
        }
    }
}

enum Frame {
    Object {
        entries: Vec<(String, Node)>,
        index: HashMap<String, usize>,
        key: Option<String>,
    },
    Array(Vec<Node>),
}

struct Scanner<'a> {
    bytes: &'a [u8],
    text: &'a str,
    at: usize,
}

impl Scanner<'_> {
    fn skip_ws(&mut self) {
        while self.at < self.bytes.len()
            && matches!(self.bytes[self.at], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.at += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
    fn literal(&mut self, word: &str) -> Option<()> {
        if self.text[self.at..].starts_with(word) {
            self.at += word.len();
            Some(())
        } else {
            None
        }
    }
    fn number(&mut self) -> Option<()> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek()? {
            b'0' => self.at += 1,
            b'1'..=b'9' => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.at += 1;
                }
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            let digits = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
            if self.at == digits {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            let digits = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
            if self.at == digits {
                return None;
            }
        }
        (self.at > start).then_some(())
    }
    /// A JSON string; lone surrogate escapes decode to U+FFFD.
    fn string(&mut self) -> Option<String> {
        self.at += 1;
        let mut units: Vec<u16> = Vec::new();
        loop {
            let byte = self.peek()?;
            match byte {
                b'"' => {
                    self.at += 1;
                    return Some(String::from_utf16_lossy(&units));
                }
                b'\\' => {
                    self.at += 1;
                    let escape = self.peek()?;
                    self.at += 1;
                    match escape {
                        b'"' => units.push(0x22),
                        b'\\' => units.push(0x5c),
                        b'/' => units.push(0x2f),
                        b'b' => units.push(0x08),
                        b'f' => units.push(0x0c),
                        b'n' => units.push(0x0a),
                        b'r' => units.push(0x0d),
                        b't' => units.push(0x09),
                        b'u' => {
                            let hex = self.text.get(self.at..self.at + 4)?;
                            if !hex.bytes().all(|digit| digit.is_ascii_hexdigit()) {
                                return None;
                            }
                            units.push(u16::from_str_radix(hex, 16).ok()?);
                            self.at += 4;
                        }
                        _ => return None,
                    }
                }
                0x00..=0x1f => return None,
                _ => {
                    let character = self.text[self.at..].chars().next()?;
                    let mut buffer = [0_u16; 2];
                    units.extend_from_slice(character.encode_utf16(&mut buffer));
                    self.at += character.len_utf8();
                }
            }
        }
    }
}

/// `JSON.parse` admission into a structural tree, without recursion.
fn parse_json(text: &str) -> Option<Node> {
    let mut scanner = Scanner {
        bytes: text.as_bytes(),
        text,
        at: 0,
    };
    let mut stack: Vec<Frame> = Vec::new();
    let mut completed: Option<Node>;
    loop {
        scanner.skip_ws();
        // Parse one value start.
        let value = match scanner.peek()? {
            b'{' => {
                scanner.at += 1;
                scanner.skip_ws();
                if scanner.peek() == Some(b'}') {
                    scanner.at += 1;
                    Some(Node::Object(Vec::new()))
                } else {
                    if scanner.peek() != Some(b'"') {
                        return None;
                    }
                    let key = scanner.string()?;
                    scanner.skip_ws();
                    if scanner.peek() != Some(b':') {
                        return None;
                    }
                    scanner.at += 1;
                    stack.push(Frame::Object {
                        entries: Vec::new(),
                        index: HashMap::new(),
                        key: Some(key),
                    });
                    None
                }
            }
            b'[' => {
                scanner.at += 1;
                scanner.skip_ws();
                if scanner.peek() == Some(b']') {
                    scanner.at += 1;
                    Some(Node::Array(Vec::new()))
                } else {
                    stack.push(Frame::Array(Vec::new()));
                    None
                }
            }
            b'"' => {
                scanner.string()?;
                Some(Node::String)
            }
            b't' => scanner.literal("true").map(|()| Node::Boolean),
            b'f' => scanner.literal("false").map(|()| Node::Boolean),
            b'n' => scanner.literal("null").map(|()| Node::Null),
            _ => {
                scanner.number()?;
                Some(Node::Number)
            }
        };
        let Some(mut value) = value else {
            continue;
        };
        // Attach completed values and close containers.
        loop {
            let Some(frame) = stack.last_mut() else {
                completed = Some(value);
                break;
            };
            scanner.skip_ws();
            match frame {
                Frame::Array(items) => {
                    items.push(value);
                    match scanner.peek()? {
                        b',' => {
                            scanner.at += 1;
                            completed = None;
                            break;
                        }
                        b']' => {
                            scanner.at += 1;
                            let Some(Frame::Array(items)) = stack.pop() else {
                                return None;
                            };
                            value = Node::Array(items);
                        }
                        _ => return None,
                    }
                }
                Frame::Object {
                    entries,
                    index,
                    key,
                } => {
                    let name = key.take()?;
                    match index.get(&name) {
                        Some(&position) => entries[position].1 = value,
                        None => {
                            index.insert(name.clone(), entries.len());
                            entries.push((name, value));
                        }
                    }
                    match scanner.peek()? {
                        b',' => {
                            scanner.at += 1;
                            scanner.skip_ws();
                            if scanner.peek() != Some(b'"') {
                                return None;
                            }
                            let next = scanner.string()?;
                            scanner.skip_ws();
                            if scanner.peek() != Some(b':') {
                                return None;
                            }
                            scanner.at += 1;
                            *key = Some(next);
                            completed = None;
                            break;
                        }
                        b'}' => {
                            scanner.at += 1;
                            let Some(Frame::Object { entries, .. }) = stack.pop() else {
                                return None;
                            };
                            value = Node::Object(entries);
                        }
                        _ => return None,
                    }
                }
            }
        }
        if let Some(root) = completed {
            scanner.skip_ws();
            return (scanner.at == scanner.bytes.len()).then_some(root);
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum ShapeKey {
    Property(String),
    ArrayElement,
}

struct ShapeNode {
    path: Vec<ShapeKey>,
    types: Vec<&'static str>,
    observations: u64,
    children: Vec<usize>,
    child_index: HashMap<ShapeKey, usize>,
}

/// `inferJsonShape`: a value-free structural summary, or `None` for text
/// `JSON.parse` rejects.
pub(crate) fn infer_json_shape(text: &str) -> Option<Value> {
    let root = parse_json(text)?;
    let mut shapes = vec![ShapeNode {
        path: Vec::new(),
        types: Vec::new(),
        observations: 0,
        children: Vec::new(),
        child_index: HashMap::new(),
    }];
    let child = |shapes: &mut Vec<ShapeNode>, parent: usize, key: ShapeKey| -> usize {
        if let Some(&existing) = shapes[parent].child_index.get(&key) {
            return existing;
        }
        let mut path = shapes[parent].path.clone();
        path.push(key.clone());
        let id = shapes.len();
        shapes.push(ShapeNode {
            path,
            types: Vec::new(),
            observations: 0,
            children: Vec::new(),
            child_index: HashMap::new(),
        });
        shapes[parent].child_index.insert(key, id);
        shapes[parent].children.push(id);
        id
    };
    let root_type = root.type_name();
    let mut pending: Vec<(Node, usize)> = vec![(root, 0)];
    let mut node_count: u64 = 0;
    let mut max_depth = 0_usize;
    while let Some((value, shape)) = pending.pop() {
        node_count += 1;
        max_depth = max_depth.max(shapes[shape].path.len());
        let name = value.type_name();
        if !shapes[shape].types.contains(&name) {
            shapes[shape].types.push(name);
        }
        shapes[shape].observations += 1;
        match value {
            Node::Array(items) => {
                if items.is_empty() {
                    continue;
                }
                let element = child(&mut shapes, shape, ShapeKey::ArrayElement);
                for item in items.into_iter().rev() {
                    pending.push((item, element));
                }
            }
            Node::Object(entries) => {
                // Accumulators are created in entry order; values are pushed
                // in reverse so they are visited in declaration order.
                let ids: Vec<usize> = entries
                    .iter()
                    .map(|(name, _)| child(&mut shapes, shape, ShapeKey::Property(name.clone())))
                    .collect();
                for ((_, item), id) in entries.into_iter().zip(ids).rev() {
                    pending.push((item, id));
                }
            }
            _ => {}
        }
    }
    let ordered = |shapes: &Vec<ShapeNode>, id: usize| -> Vec<usize> {
        let mut children = shapes[id].children.clone();
        // Reverse sibling order for the stack; array elements sort first.
        children.sort_by(|left, right| {
            let (left_key, right_key) = (shapes[*left].path.last(), shapes[*right].path.last());
            match (left_key, right_key) {
                (Some(ShapeKey::ArrayElement), Some(ShapeKey::ArrayElement)) => {
                    std::cmp::Ordering::Equal
                }
                (Some(ShapeKey::ArrayElement), _) => std::cmp::Ordering::Greater,
                (_, Some(ShapeKey::ArrayElement)) => std::cmp::Ordering::Less,
                (Some(ShapeKey::Property(left)), Some(ShapeKey::Property(right))) => {
                    right.cmp(left)
                }
                _ => std::cmp::Ordering::Equal,
            }
        });
        children
    };
    let mut properties = Vec::new();
    let mut stack = ordered(&shapes, 0);
    while let Some(id) = stack.pop() {
        let shape = &shapes[id];
        let path: Vec<Value> = shape
            .path
            .iter()
            .map(|segment| match segment {
                ShapeKey::Property(name) => json!({ "kind": "property", "name": name }),
                ShapeKey::ArrayElement => json!({ "kind": "array-element" }),
            })
            .collect();
        let mut types = shape.types.clone();
        types.sort_unstable();
        properties
            .push(json!({ "path": path, "types": types, "observations": shape.observations }));
        stack.extend(ordered(&shapes, id));
    }
    let mut shape = Map::new();
    shape.insert("root_type".into(), json!(root_type));
    shape.insert("node_count".into(), json!(node_count));
    shape.insert("max_depth_observed".into(), json!(max_depth));
    shape.insert("properties".into(), Value::Array(properties));
    Some(Value::Object(shape))
}
