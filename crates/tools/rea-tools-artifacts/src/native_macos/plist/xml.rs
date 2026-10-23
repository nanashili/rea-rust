//! XML property-list decoding.
//!
//! Compatibility owners: `src/domain/propertyListXml.ts`
//! (`decodeXmlPropertyList`), `src/domain/propertyListXmlSource.ts`
//! (source-span scalar literals and depth bound) and
//! `src/domain/propertyListKeys.ts` (`parseXmlPropertyList`,
//! `omitPrototypeKeys`, `__proto__` accounting).
//!
//! The input is plutil's canonical `-convert xml1` output: a well-formed XML
//! document whose scalar elements hold plain character data. The decoder
//! preserves each scalar's raw source literal so integer, real and date
//! classification matches the TypeScript source-span reader.

use super::numbers::{MAX_SAFE_INTEGER, MIN_SAFE_INTEGER, PlistNumberLiterals};
use super::scalar::{self, DataError};
use super::value::{NonFiniteLabel, PlistNode, UnknownScalarElement, UnknownScalarReason};

const PROTOTYPE_KEY: &str = "__proto__";

/// A decoded XML property list: its value graph, the omitted `__proto__` count
/// and the collected source number literals.
pub(crate) struct DecodedXml {
    pub value: PlistNode,
    pub omitted_prototype_keys: usize,
    pub number_literals: PlistNumberLiterals,
}

/// A decode failure. The message mirrors the `TypeError`/`RangeError` text the
/// TypeScript decoder throws so downstream error translation is unchanged.
#[derive(Debug)]
pub(crate) struct XmlError(pub String);

impl XmlError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// One parsed XML element and its children.
#[derive(Debug)]
struct Element {
    name: String,
    children: Vec<Node>,
    /// Raw source text between the opening and closing tags, before any entity
    /// expansion. `None` for a self-closing element.
    inner_source: Option<String>,
}

#[derive(Debug)]
enum Node {
    Element(Element),
    /// Character data (text or CDATA content), already entity-expanded for
    /// text runs; CDATA content is retained verbatim.
    Text(String),
    /// A comment or processing instruction retained as a non-character node so
    /// unsupported-markup checks see it.
    OtherMarkup,
}

/// `parseXmlPropertyList(text)` for the XML (non-OpenStep) branch:
/// `decodeXmlPropertyList` followed by `omitPrototypeKeys`.
pub(crate) fn decode_xml_property_list(text: &str) -> Result<DecodedXml, XmlError> {
    let normalized = normalize_line_endings(text);
    let mut parser = Parser::new(&normalized);
    let root = parser.parse_document()?;
    if root.name != "plist" {
        return Err(XmlError::new(
            "malformed document. First element should be <plist>",
        ));
    }
    let mut decoder = Decoder::default();
    let values = element_members(&root)
        .map(|member| decoder.decode(member, 0))
        .collect::<Result<Vec<_>, _>>()?;
    let value = if values.len() == 1 {
        values.into_iter().next().unwrap()
    } else {
        PlistNode::Array(values)
    };
    let (value, omitted_prototype_keys) = omit_prototype_keys(value);
    Ok(DecodedXml {
        value,
        omitted_prototype_keys,
        number_literals: decoder.numbers,
    })
}

/// Normalize line endings the way the DOM source reader does
/// (`LINE_ENDING` → `\n`).
fn normalize_line_endings(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\r' => {
                if matches!(chars.peek(), Some('\n' | '\u{0085}')) {
                    chars.next();
                }
                output.push('\n');
            }
            '\u{0085}' | '\u{2028}' | '\u{2029}' => output.push('\n'),
            other => output.push(other),
        }
    }
    output
}

/// Iterate an element's element children (the decoder's `members` generator
/// skips text, CDATA, comment and processing-instruction nodes).
fn element_members(element: &Element) -> impl Iterator<Item = &Element> {
    element.children.iter().filter_map(|node| match node {
        Node::Element(child) => Some(child),
        _ => None,
    })
}

#[derive(Default)]
struct Decoder {
    numbers: PlistNumberLiterals,
}

impl Decoder {
    fn decode(&mut self, element: &Element, depth: usize) -> Result<PlistNode, XmlError> {
        match element.name.as_str() {
            "plist" => {
                // Nested <plist> decodes as an array of its members.
                let members = element_members(element)
                    .map(|member| self.decode(member, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PlistNode::Array(members))
            }
            "array" => {
                let mut values = Vec::new();
                for member in element_members(element) {
                    let value = self.decode(member, depth + 1)?;
                    // The TypeScript decoder drops members decoding to null.
                    if !matches!(value, PlistNode::Null) {
                        values.push(value);
                    }
                }
                Ok(PlistNode::Array(values))
            }
            "dict" => {
                let mut entries: Vec<(String, PlistNode)> = Vec::new();
                let mut pending_key: Option<String> = None;
                for child in element_members(element) {
                    match pending_key.take() {
                        None => {
                            if child.name != "key" {
                                return Err(XmlError::new("Missing key while parsing <dict/>"));
                            }
                            pending_key = Some(dictionary_key(child));
                        }
                        Some(key) => {
                            if child.name == "key" {
                                return Err(XmlError::new(
                                    "Unexpected <key> while parsing <dict/>. Keys and values must alternate.",
                                ));
                            }
                            let value = self.decode(child, depth + 1)?;
                            entries.push((key, value));
                        }
                    }
                }
                if let Some(key) = pending_key {
                    entries.push((key, PlistNode::String(String::new())));
                }
                Ok(dict_from_entries(entries))
            }
            "key" => {
                // A key element decoded as a scalar keeps its first-child text.
                let value = first_child_text(element);
                if value == PROTOTYPE_KEY {
                    return Err(XmlError::new("__proto__ is not a scalar plist key"));
                }
                Ok(PlistNode::String(value))
            }
            "string" => Ok(PlistNode::String(character_content(element))),
            "integer" => {
                let raw = scalar_literal(element);
                let unsupported_markup = has_unsupported_markup(element, text_only);
                let exact = if unsupported_markup {
                    None
                } else {
                    scalar::parse_integer_literal(&raw)
                };
                match exact {
                    None => Ok(PlistNode::UnknownScalar {
                        element: UnknownScalarElement::Integer,
                        literal: raw,
                        reason: if unsupported_markup {
                            UnknownScalarReason::UnsupportedMarkup
                        } else {
                            UnknownScalarReason::InvalidLiteral
                        },
                    }),
                    Some(exact) => {
                        self.numbers.record_integer(exact);
                        // The TypeScript decoder returns `Number(exact)`, a JS
                        // double. Integers whose double is not finite are a REA
                        // extension retained exactly.
                        Ok(integer_node(exact))
                    }
                }
            }
            "real" => {
                let raw = scalar_literal(element);
                if has_unsupported_markup(element, character_node) {
                    return Ok(PlistNode::UnknownScalar {
                        element: UnknownScalarElement::Real,
                        literal: raw,
                        reason: UnknownScalarReason::UnsupportedMarkup,
                    });
                }
                match scalar::parse_real_literal(&raw) {
                    Ok(value) => {
                        self.numbers.record_real(value);
                        Ok(real_node(value))
                    }
                    Err(reason) => Ok(PlistNode::UnknownScalar {
                        element: UnknownScalarElement::Real,
                        literal: raw,
                        reason,
                    }),
                }
            }
            "data" => {
                let raw = scalar_literal(element);
                if has_non_text_child(element) {
                    return Err(XmlError::new("Cannot decode XML plist <data>: markup"));
                }
                if element.inner_source.is_none() {
                    return Err(XmlError::new(
                        "Cannot decode XML plist <data>: empty-element",
                    ));
                }
                match scalar::decode_data(&raw) {
                    Ok(bytes) => Ok(PlistNode::Data(bytes)),
                    Err(DataError::NonAscii) => {
                        Err(XmlError::new("Cannot decode XML plist <data>: non-ascii"))
                    }
                }
            }
            "date" => {
                let raw = scalar_literal(element);
                if has_unsupported_markup(element, text_only) {
                    return Ok(PlistNode::UnknownScalar {
                        element: UnknownScalarElement::Date,
                        literal: raw,
                        reason: UnknownScalarReason::UnsupportedMarkup,
                    });
                }
                match scalar::parse_date_literal(&raw) {
                    Ok(iso8601) => Ok(PlistNode::Date(iso8601)),
                    Err(reason) => Ok(PlistNode::UnknownScalar {
                        element: UnknownScalarElement::Date,
                        literal: raw,
                        reason,
                    }),
                }
            }
            "null" => Ok(PlistNode::Null),
            "true" | "false" => {
                let raw = scalar_literal(element);
                if raw.is_empty() {
                    Ok(PlistNode::Bool(element.name == "true"))
                } else {
                    Ok(PlistNode::UnknownScalar {
                        element: if element.name == "true" {
                            UnknownScalarElement::True
                        } else {
                            UnknownScalarElement::False
                        },
                        literal: raw,
                        reason: if has_unsupported_markup(element, text_only) {
                            UnknownScalarReason::UnsupportedMarkup
                        } else {
                            UnknownScalarReason::InvalidLiteral
                        },
                    })
                }
            }
            other => Err(XmlError::new(format!("Invalid PLIST tag {other}"))),
        }
    }
}

/// `dictionaryKey(node)`: the first child element's value, or the character
/// content when the key holds only text.
fn dictionary_key(element: &Element) -> String {
    for child in &element.children {
        if let Node::Element(_) = child {
            return first_child_text(element);
        }
    }
    character_content(element)
}

/// The text of an element's first child, or an empty string when it has none.
fn first_child_text(element: &Element) -> String {
    match element.children.first() {
        Some(Node::Text(text)) => text.clone(),
        Some(Node::Element(child)) => character_content(child),
        _ => String::new(),
    }
}

/// `content(node, characterNode)`: the concatenation of text and CDATA runs.
fn character_content(element: &Element) -> String {
    let mut text = String::new();
    for child in &element.children {
        if let Node::Text(value) = child {
            text.push_str(value);
        }
    }
    text
}

/// The raw source literal between the open and close tags (`scalarLiteral`).
fn scalar_literal(element: &Element) -> String {
    element.inner_source.clone().unwrap_or_default()
}

/// Whether a child node is accepted by the text-only predicate (`textNode`).
/// Canonical plutil scalars carry no CDATA, so a CDATA run here is already
/// retained as `Node::Text`; comments and PIs are `Node::OtherMarkup`.
fn text_only(node: &Node) -> bool {
    matches!(node, Node::Text(_))
}

/// Whether a child node is accepted by the character predicate (`characterNode`
/// = text or CDATA). Canonical plutil output never emits CDATA in scalars.
fn character_node(node: &Node) -> bool {
    matches!(node, Node::Text(_))
}

/// `hasUnsupportedMarkup(node, accepts)`.
fn has_unsupported_markup(element: &Element, accepts: fn(&Node) -> bool) -> bool {
    element.children.iter().any(|child| !accepts(child))
}

/// Whether a `<data>` element has any non-text child (the TypeScript source
/// reader rejects such markup before decoding).
fn has_non_text_child(element: &Element) -> bool {
    element
        .children
        .iter()
        .any(|child| !matches!(child, Node::Text(_)))
}

/// Build a dictionary node. The XML decoder uses `Object.fromEntries`, so a
/// later duplicate key overwrites an earlier one while keeping its position.
fn dict_from_entries(entries: Vec<(String, PlistNode)>) -> PlistNode {
    let mut ordered: Vec<(String, PlistNode)> = Vec::new();
    for (key, value) in entries {
        if let Some(position) = ordered.iter().position(|(existing, _)| existing == &key) {
            ordered[position].1 = value;
        } else {
            ordered.push((key, value));
        }
    }
    PlistNode::Dict(ordered)
}

/// `omitPrototypeKeys(value)`: remove own `__proto__` entries and count them.
fn omit_prototype_keys(value: PlistNode) -> (PlistNode, usize) {
    let mut omitted = 0;
    let stripped = strip_prototype(value, &mut omitted);
    (stripped, omitted)
}

fn strip_prototype(value: PlistNode, omitted: &mut usize) -> PlistNode {
    match value {
        PlistNode::Array(items) => PlistNode::Array(
            items
                .into_iter()
                .map(|item| strip_prototype(item, omitted))
                .collect(),
        ),
        PlistNode::Dict(entries) => {
            let mut kept = Vec::with_capacity(entries.len());
            for (key, child) in entries {
                if key == PROTOTYPE_KEY {
                    *omitted += 1;
                    continue;
                }
                kept.push((key, strip_prototype(child, omitted)));
            }
            PlistNode::Dict(kept)
        }
        other => other,
    }
}

/// Decode one integer element's exact value into a node, mirroring
/// `Number(exact)` and the big-integer extension.
fn integer_node(exact: i128) -> PlistNode {
    if (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&exact) {
        // Exactly representable as a JS number and as an i64.
        PlistNode::Integer(exact as i64)
    } else {
        let decoded = exact as f64;
        if decoded.is_finite() {
            // `Number(exact)` rounds beyond the safe range; the double is used.
            PlistNode::Real(decoded)
        } else {
            PlistNode::BigInteger(exact.to_string())
        }
    }
}

/// A finite or non-finite real decoded from the source.
fn real_node(value: f64) -> PlistNode {
    if value.is_finite() {
        PlistNode::Real(value)
    } else if value.is_nan() {
        PlistNode::NonFiniteReal(NonFiniteLabel::Nan)
    } else if value > 0.0 {
        PlistNode::NonFiniteReal(NonFiniteLabel::PositiveInfinity)
    } else {
        PlistNode::NonFiniteReal(NonFiniteLabel::NegativeInfinity)
    }
}

// ----------------------------------------------------------------------------
// XML tokenizer
// ----------------------------------------------------------------------------

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            cursor: 0,
        }
    }

    /// Parse the document prolog and return its single root element.
    fn parse_document(&mut self) -> Result<Element, XmlError> {
        loop {
            self.skip_whitespace();
            if self.starts_with("<?") {
                self.skip_until("?>")?;
                continue;
            }
            if self.starts_with("<!--") {
                self.skip_until("-->")?;
                continue;
            }
            if self.starts_with("<!") {
                // DOCTYPE or other declaration; skip to its closing `>`,
                // accounting for an internal subset.
                self.skip_declaration()?;
                continue;
            }
            break;
        }
        if !self.starts_with("<") {
            return Err(XmlError::new(
                "malformed document. First element should be <plist>",
            ));
        }
        self.parse_element()
    }

    fn parse_element(&mut self) -> Result<Element, XmlError> {
        debug_assert_eq!(self.bytes.get(self.cursor), Some(&b'<'));
        self.cursor += 1;
        let name = self.read_name()?;
        // Skip attributes until `>` or `/>`.
        let self_closing = self.skip_attributes()?;
        if self_closing {
            return Ok(Element {
                name,
                children: Vec::new(),
                inner_source: None,
            });
        }
        let inner_start = self.cursor;
        let mut children = Vec::new();
        loop {
            if self.cursor >= self.bytes.len() {
                return Err(XmlError::new("unexpected end of XML input"));
            }
            if self.starts_with("</") {
                let inner_end = self.cursor;
                self.cursor += 2;
                let close = self.read_name()?;
                self.skip_whitespace();
                if self.bytes.get(self.cursor) != Some(&b'>') {
                    return Err(XmlError::new("malformed closing tag"));
                }
                self.cursor += 1;
                if close != name {
                    return Err(XmlError::new("mismatched XML tags"));
                }
                return Ok(Element {
                    name,
                    inner_source: Some(self.text[inner_start..inner_end].to_owned()),
                    children,
                });
            }
            if self.starts_with("<!--") {
                self.skip_until("-->")?;
                children.push(Node::OtherMarkup);
                continue;
            }
            if self.starts_with("<![CDATA[") {
                let start = self.cursor + "<![CDATA[".len();
                let relative = self.text[start..]
                    .find("]]>")
                    .ok_or_else(|| XmlError::new("unterminated CDATA section"))?;
                children.push(Node::Text(self.text[start..start + relative].to_owned()));
                self.cursor = start + relative + "]]>".len();
                continue;
            }
            if self.starts_with("<?") {
                self.skip_until("?>")?;
                children.push(Node::OtherMarkup);
                continue;
            }
            if self.starts_with("<") {
                let child = self.parse_element()?;
                children.push(Node::Element(child));
                continue;
            }
            // Character data up to the next `<`.
            let next = self.text[self.cursor..]
                .find('<')
                .map(|relative| self.cursor + relative)
                .unwrap_or(self.bytes.len());
            let run = &self.text[self.cursor..next];
            children.push(Node::Text(expand_text_entities(run)));
            self.cursor = next;
        }
    }

    fn read_name(&mut self) -> Result<String, XmlError> {
        let start = self.cursor;
        while self.cursor < self.bytes.len() {
            let byte = self.bytes[self.cursor];
            if byte == b'>' || byte == b'/' || byte == b'=' || byte.is_ascii_whitespace() {
                break;
            }
            self.cursor += 1;
        }
        if self.cursor == start {
            return Err(XmlError::new("malformed XML element name"));
        }
        Ok(self.text[start..self.cursor].to_owned())
    }

    /// Skip element attributes, returning whether the tag was self-closing.
    fn skip_attributes(&mut self) -> Result<bool, XmlError> {
        let mut quote: Option<u8> = None;
        while self.cursor < self.bytes.len() {
            let byte = self.bytes[self.cursor];
            match quote {
                Some(open) => {
                    if byte == open {
                        quote = None;
                    }
                    self.cursor += 1;
                }
                None => match byte {
                    b'"' | b'\'' => {
                        quote = Some(byte);
                        self.cursor += 1;
                    }
                    b'/' if self.bytes.get(self.cursor + 1) == Some(&b'>') => {
                        self.cursor += 2;
                        return Ok(true);
                    }
                    b'>' => {
                        self.cursor += 1;
                        return Ok(false);
                    }
                    _ => self.cursor += 1,
                },
            }
        }
        Err(XmlError::new("unterminated XML tag"))
    }

    fn skip_declaration(&mut self) -> Result<(), XmlError> {
        // `<! ... >`, allowing a `[ ... ]` internal subset to carry `>`.
        self.cursor += 2;
        let mut depth = 0usize;
        while self.cursor < self.bytes.len() {
            match self.bytes[self.cursor] {
                b'[' => depth += 1,
                b']' if depth > 0 => depth -= 1,
                b'>' if depth == 0 => {
                    self.cursor += 1;
                    return Ok(());
                }
                _ => {}
            }
            self.cursor += 1;
        }
        Err(XmlError::new("unterminated XML declaration"))
    }

    fn skip_until(&mut self, terminator: &str) -> Result<(), XmlError> {
        match self.text[self.cursor..].find(terminator) {
            Some(relative) => {
                self.cursor += relative + terminator.len();
                Ok(())
            }
            None => Err(XmlError::new("unterminated XML markup")),
        }
    }

    fn skip_whitespace(&mut self) {
        while self.cursor < self.bytes.len() && self.bytes[self.cursor].is_ascii_whitespace() {
            self.cursor += 1;
        }
    }

    fn starts_with(&self, prefix: &str) -> bool {
        self.text[self.cursor..].starts_with(prefix)
    }
}

/// Expand the XML entities admitted in text runs of plutil output.
fn expand_text_entities(run: &str) -> String {
    if !run.contains('&') {
        return run.to_owned();
    }
    let bytes = run.as_bytes();
    let mut output = String::with_capacity(run.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'&'
            && let Some(end) = run[index..].find(';')
        {
            let body = &run[index + 1..index + end];
            let expansion =
                if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
                    u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                } else if let Some(decimal) = body.strip_prefix('#') {
                    decimal.parse::<u32>().ok().and_then(char::from_u32)
                } else {
                    match body {
                        "amp" => Some('&'),
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "apos" => Some('\''),
                        "quot" => Some('"'),
                        _ => None,
                    }
                };
            if let Some(character) = expansion {
                output.push(character);
                index += end + 1;
                continue;
            }
        }
        let character = run[index..].chars().next().unwrap();
        output.push(character);
        index += character.len_utf8();
    }
    output
}
