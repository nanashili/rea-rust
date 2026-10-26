//! Ordered JSON values with JavaScript serialization semantics.
//!
//! The graph producers derive identities from two different encodings:
//! `JSON.stringify` (insertion order, used for composite keys and path digests)
//! and RFC 8785-style canonical JSON (UTF-16 code-unit key order, used for every
//! content digest). [`Json`] keeps producer key order so both are reproducible.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write as _};
use std::ops::Index;
use std::sync::Arc;

use super::super::semantic::value_types::JsString;
use serde::de::{Deserialize, Deserializer, Error as _};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

thread_local! {
    /// Static graph field names share one `JsString` allocation per worker
    /// thread. The key set is bounded by compiled graph producers.
    static STATIC_KEYS: RefCell<HashMap<&'static str, JsString>> =
        RefCell::new(HashMap::new());
}

fn static_key(key: &'static str) -> JsString {
    STATIC_KEYS.with(|keys| {
        keys.borrow_mut()
            .entry(key)
            .or_insert_with(|| JsString::from(key))
            .clone()
    })
}

/// One JSON value whose objects retain producer insertion order.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A finite IEEE-754 number, as JavaScript holds it.
    Number(f64),
    /// A string.
    String(JsString),
    /// An array.
    Array(Arc<Vec<Json>>),
    /// An object in insertion order.
    Object(Obj),
}

/// A JSON object with JavaScript property-assignment semantics.
///
/// Graph projections share immutable object contents. A mutation detaches its
/// property list first, preserving independent value semantics for every clone.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Obj(Arc<Vec<(JsString, Json)>>);

impl Obj {
    /// An empty object.
    pub fn new() -> Self {
        Self(Arc::new(Vec::new()))
    }

    /// Reserve space for a known number of properties without changing order.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Vec::with_capacity(capacity)))
    }

    /// Read one own property.
    pub fn get<K: ?Sized>(&self, key: &K) -> Option<&Json>
    where
        JsString: PartialEq<K>,
    {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// Mutably access one own property without changing its insertion order.
    pub fn get_mut<K: ?Sized>(&mut self, key: &K) -> Option<&mut Json>
    where
        JsString: PartialEq<K>,
    {
        let index = self.0.iter().position(|(name, _)| name == key)?;
        Some(&mut Arc::make_mut(&mut self.0)[index].1)
    }

    /// Whether the property exists (JavaScript `key in value`).
    pub fn has<K: ?Sized>(&self, key: &K) -> bool
    where
        JsString: PartialEq<K>,
    {
        self.get(key).is_some()
    }

    /// Assign a property: an existing key keeps its position, as in JavaScript.
    pub fn set(&mut self, key: impl Into<JsString>, value: impl Into<Json>) {
        let key = key.into();
        let value = value.into();
        let properties = Arc::make_mut(&mut self.0);
        if let Some(slot) = properties.iter_mut().find(|(name, _)| *name == key) {
            slot.1 = value;
        } else {
            properties.push((key, value));
        }
    }

    /// Builder form of [`Obj::set`].
    #[must_use]
    pub fn with(mut self, key: impl Into<JsString>, value: impl Into<Json>) -> Self {
        self.set(key, value);
        self
    }

    /// Builder form for a compiled graph field name.
    #[must_use]
    pub fn with_static(mut self, key: &'static str, value: impl Into<Json>) -> Self {
        self.set_static(key, value);
        self
    }

    /// Assign a compiled graph field name using the bounded static-key pool.
    pub fn set_static(&mut self, key: &'static str, value: impl Into<Json>) {
        self.set(static_key(key), value);
    }

    /// Spread another object's properties (`{...this, ...other}`).
    pub fn extend_from(&mut self, other: &Obj) {
        for (key, value) in other.0.iter() {
            self.set(key.clone(), value.clone());
        }
    }

    /// Remove one property by exact JavaScript UTF-16 key.
    pub fn remove_js(&mut self, key: &JsString) -> Option<Json> {
        let index = self.0.iter().position(|(name, _)| name == key)?;
        Some(Arc::make_mut(&mut self.0).remove(index).1)
    }

    /// Remove one property addressed by a valid UTF-8 key.
    pub fn remove(&mut self, key: &str) -> Option<Json> {
        self.remove_js(&JsString::from(key))
    }

    /// Properties in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&JsString, &Json)> {
        self.0.iter().map(|(key, value)| (key, value))
    }

    /// Number of properties.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the object has no properties.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Obj> for Json {
    fn from(value: Obj) -> Self {
        Json::Object(value)
    }
}
impl From<&str> for Json {
    fn from(value: &str) -> Self {
        Json::String(JsString::from(value))
    }
}
impl From<String> for Json {
    fn from(value: String) -> Self {
        Json::String(JsString::from(value))
    }
}
impl From<JsString> for Json {
    fn from(value: JsString) -> Self {
        Json::String(value)
    }
}
impl From<&JsString> for Json {
    fn from(value: &JsString) -> Self {
        Json::String(value.clone())
    }
}
impl From<&String> for Json {
    fn from(value: &String) -> Self {
        Json::String(JsString::from(value.as_str()))
    }
}
impl From<bool> for Json {
    fn from(value: bool) -> Self {
        Json::Bool(value)
    }
}
impl From<f64> for Json {
    fn from(value: f64) -> Self {
        Json::Number(value)
    }
}
impl From<usize> for Json {
    fn from(value: usize) -> Self {
        #[allow(clippy::cast_precision_loss)]
        Json::Number(value as f64)
    }
}
impl From<i64> for Json {
    fn from(value: i64) -> Self {
        #[allow(clippy::cast_precision_loss)]
        Json::Number(value as f64)
    }
}
impl From<Vec<Json>> for Json {
    fn from(value: Vec<Json>) -> Self {
        Self::array(value)
    }
}
impl From<&Json> for Json {
    fn from(value: &Json) -> Self {
        value.clone()
    }
}

impl From<u32> for Json {
    fn from(value: u32) -> Self {
        Self::Number(f64::from(value))
    }
}

impl<T: Into<Json>> From<Option<T>> for Json {
    fn from(value: Option<T>) -> Self {
        value.map_or(Json::Null, Into::into)
    }
}

/// Build an array of strings.
pub fn strings<I, S>(values: I) -> Json
where
    I: IntoIterator<Item = S>,
    S: Into<JsString>,
{
    Json::array(
        values
            .into_iter()
            .map(|value| Json::String(value.into()))
            .collect(),
    )
}

static NULL: Json = Json::Null;
static EMPTY_JS_STRING: JsString = JsString::new_const();

impl Json {
    /// Build an immutable array whose storage is shared by cheap clones.
    pub fn array(values: Vec<Json>) -> Self {
        Self::Array(Arc::new(values))
    }

    /// Mutably access an array, detaching shared storage first.
    pub fn array_mut(&mut self) -> Option<&mut Vec<Json>> {
        match self {
            Self::Array(values) => Some(Arc::make_mut(values)),
            _ => None,
        }
    }

    /// Read an object property; absent and non-object values read as `undefined` (`None`).
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(object) => object.get(key),
            _ => None,
        }
    }

    /// Read an object property by exact JavaScript UTF-16 key.
    pub fn get_js_string(&self, key: &JsString) -> Option<&Json> {
        match self {
            Json::Object(object) => object.get(key),
            _ => None,
        }
    }

    /// Read an object property, treating `undefined` as `null`.
    pub fn at(&self, key: &str) -> &Json {
        self.get(key).unwrap_or(&NULL)
    }

    /// Whether this is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    /// The string value, if any.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(value) => value.as_str(),
            _ => None,
        }
    }

    /// The valid string value or `""` for absent/non-string values.
    ///
    /// A string containing an unpaired UTF-16 unit cannot be represented as a
    /// Rust `str`; callers that need exact source identity must use
    /// [`Json::as_js_string`] instead of silently replacing it.
    pub fn str(&self) -> &str {
        match self {
            Json::String(value) => value.as_str().expect(
                "graph JSON string contains unpaired UTF-16 units; use as_js_string() for exact text",
            ),
            _ => "",
        }
    }

    /// The exact JavaScript string, including unpaired UTF-16 units.
    pub fn as_js_string(&self) -> Option<&JsString> {
        match self {
            Json::String(value) => Some(value),
            _ => None,
        }
    }

    /// Read exact JavaScript text, using an empty value for absent/non-string
    /// fields. This accessor never converts unpaired UTF-16 units.
    pub fn text(&self) -> &JsString {
        self.as_js_string().unwrap_or(&EMPTY_JS_STRING)
    }

    /// The numeric value, if any.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(value) => Some(*value),
            _ => None,
        }
    }

    /// Whether this value is an array.
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    /// Whether this value is an object.
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    /// Borrow the object entries, when this is an object.
    pub fn as_object(&self) -> Option<&Obj> {
        self.as_obj()
    }

    /// The numeric value or zero.
    pub fn num(&self) -> f64 {
        self.as_f64().unwrap_or(0.0)
    }

    /// The boolean value, if any.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// The array items, or an empty slice.
    pub fn arr(&self) -> &[Json] {
        match self {
            Json::Array(values) => values,
            _ => &[],
        }
    }

    /// Borrow array storage without treating non-array values as empty.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Self::Array(values) => Some(values.as_slice()),
            _ => None,
        }
    }

    /// Integer projection used by schema-compatible callers.
    pub fn as_u64(&self) -> Option<u64> {
        self.as_f64().and_then(|value| {
            (value.is_finite()
                && value >= 0.0
                && value < 18_446_744_073_709_551_616.0
                && value.fract() == 0.0)
                .then_some(value as u64)
        })
    }

    /// The object, if any.
    pub fn as_obj(&self) -> Option<&Obj> {
        match self {
            Json::Object(object) => Some(object),
            _ => None,
        }
    }

    /// A clone of the object or an empty object.
    pub fn obj(&self) -> Obj {
        self.as_obj().cloned().unwrap_or_default()
    }

    /// JavaScript `JSON.stringify` of this value.
    pub fn stringify(&self) -> String {
        let mut output = String::new();
        stringify_into(self, &mut output);
        output
    }

    /// RFC 8785 canonical JSON, matching the `canonicalize` package and the
    /// streaming digest producers.
    pub fn canonical(&self) -> String {
        let mut output = String::new();
        canonical_into(self, &mut output);
        output
    }

    /// SHA-256 hex digest of [`Json::canonical`].
    pub fn digest(&self) -> String {
        sha256_hex(self.canonical().as_bytes())
    }
}

impl Index<&str> for Json {
    type Output = Json;

    fn index(&self, key: &str) -> &Self::Output {
        self.at(key)
    }
}

/// Lowercase SHA-256 hex digest of UTF-8 bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Hash the canonical object used for semantic node identities without
/// cloning the identity tree into a temporary [`Json`] value.
pub fn digest_kind_identity(kind: &str, identity: &Json) -> String {
    let mut canonical = String::new();
    canonical.push_str("{\"identity\":");
    canonical_into(identity, &mut canonical);
    canonical.push_str(",\"kind\":");
    canonical_into(&Json::String(JsString::from(kind)), &mut canonical);
    canonical.push('}');
    sha256_hex(canonical.as_bytes())
}

/// SHA-256 of a JavaScript string encoded as UTF-8 (`createHash().update(text)`).
pub fn sha256_text(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn stringify_into(value: &Json, output: &mut String) {
    match value {
        Json::Null => output.push_str("null"),
        Json::Bool(true) => output.push_str("true"),
        Json::Bool(false) => output.push_str("false"),
        Json::Number(number) => write_js_number(*number, output),
        Json::String(text) => quote_js_string_into(text, output),
        Json::Array(values) => {
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                stringify_into(item, output);
            }
            output.push(']');
        }
        Json::Object(object) => {
            output.push('{');
            for (index, (key, item)) in javascript_key_order(object).into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                quote_js_string_into(key, output);
                output.push(':');
                stringify_into(item, output);
            }
            output.push('}');
        }
    }
}

/// JavaScript own-property order: array-index keys ascending, then insertion order.
fn javascript_key_order(object: &Obj) -> Vec<(&JsString, &Json)> {
    let mut indices: Vec<(u32, &JsString, &Json)> = Vec::new();
    let mut names: Vec<(&JsString, &Json)> = Vec::new();
    for (key, value) in object.iter() {
        match array_index(key) {
            Some(index) => indices.push((index, key, value)),
            None => names.push((key, value)),
        }
    }
    indices.sort_by_key(|(index, _, _)| *index);
    indices
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .chain(names)
        .collect()
}

fn array_index(key: &JsString) -> Option<u32> {
    let key = key.as_str()?;
    if key.is_empty() || (key.len() > 1 && key.starts_with('0')) {
        return None;
    }
    let value: u32 = key.parse().ok()?;
    (value != u32::MAX && value.to_string() == key).then_some(value)
}

fn canonical_into(value: &Json, output: &mut String) {
    match value {
        Json::Object(object) => {
            let mut entries: Vec<(&JsString, &Json)> = object.iter().collect();
            entries.sort_by(|left, right| compare_utf16(left.0, right.0));
            output.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                quote_js_string_into(key, output);
                output.push(':');
                canonical_into(item, output);
            }
            output.push('}');
        }
        Json::Array(values) => {
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                canonical_into(item, output);
            }
            output.push(']');
        }
        scalar => stringify_into(scalar, output),
    }
}

/// `JSON.stringify` of one string.
pub fn quote(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    quote_into(value, &mut output);
    output
}

/// Quote exact JavaScript UTF-16 units, including lone surrogate escapes.
pub fn quote_units(units: &[u16]) -> String {
    let mut output = String::with_capacity(units.len() + 2);
    quote_units_into(units, &mut output);
    output
}

fn quote_js_string_into(value: &JsString, output: &mut String) {
    if let Some(text) = value.as_str() {
        quote_into(text, output);
    } else {
        quote_units_into(value.units(), output);
    }
}

fn quote_units_into(units: &[u16], output: &mut String) {
    output.push('"');
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if (0xd800..=0xdbff).contains(&unit)
            && units
                .get(index + 1)
                .is_some_and(|next| (0xdc00..=0xdfff).contains(next))
        {
            let low = units[index + 1];
            let code_point =
                0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
            output.push(char::from_u32(code_point).expect("valid surrogate pair"));
            index += 2;
            continue;
        }

        match unit {
            0x22 => output.push_str("\\\""),
            0x5c => output.push_str("\\\\"),
            0x08 => output.push_str("\\b"),
            0x0c => output.push_str("\\f"),
            0x0a => output.push_str("\\n"),
            0x0d => output.push_str("\\r"),
            0x09 => output.push_str("\\t"),
            0..=0x1f | 0xd800..=0xdfff => {
                let _ = write!(output, "\\u{unit:04x}");
            }
            value => output.push(char::from_u32(u32::from(value)).unwrap_or('\u{fffd}')),
        }
        index += 1;
    }
    output.push('"');
}

fn quote_into(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let _ = write!(output, "\\u{:04x}", control as u32);
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

/// JavaScript JSON number spelling, including `null` for non-finite values.
pub fn js_number(value: f64) -> String {
    let mut output = String::new();
    write_js_number(value, &mut output);
    output
}

fn write_js_number(value: f64, output: &mut String) {
    if value.is_finite() {
        let mut buffer = ryu_js::Buffer::new();
        output.push_str(buffer.format_finite(value));
    } else {
        output.push_str("null");
    }
}

/// JavaScript `String(number)` for an integer-valued count or position.
pub fn js_int(value: f64) -> String {
    js_number(value)
}

/// Compare two strings by UTF-16 code units (`Array.prototype.sort` order).
pub fn compare_utf16(left: &JsString, right: &JsString) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

pub fn compare_utf16_str(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// Compare two strings by Unicode code point (`compareUnicodeCodePoints`).
pub fn compare_code_points(left: &str, right: &str) -> Ordering {
    left.cmp(right)
}

/// `uniqueSorted`: deduplicate and sort by code point.
pub fn unique_sorted(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values: Vec<String> = values.into_iter().collect();
    values.sort();
    values.dedup();
    values
}

/// Deduplicate and sort exact JavaScript strings by Unicode code point.
pub fn unique_sorted_js(values: impl IntoIterator<Item = JsString>) -> Vec<JsString> {
    let mut values: Vec<JsString> = values.into_iter().collect();
    values.sort_by(|left, right| left.compare_code_points(right));
    values.dedup();
    values
}

/// `compositeKey`: a JSON tuple of the parts.
pub fn composite_key(parts: Vec<Json>) -> String {
    Json::array(parts).stringify()
}

/// UTF-16 length of a JavaScript string.
pub fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

impl fmt::Display for Json {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.stringify())
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        parse(raw.get()).map_err(D::Error::custom)
    }
}

/// Parse JSON text while retaining object key order.
pub fn parse(text: &str) -> Result<Json, serde_json::Error> {
    RawParser::new(text)
        .parse()
        .map_err(serde_json::Error::custom)
}

enum StringBuilder {
    Utf8(String),
    Utf16(Vec<u16>),
}

impl StringBuilder {
    fn new() -> Self {
        Self::Utf8(String::new())
    }

    fn push_char(&mut self, character: char) {
        match self {
            Self::Utf8(value) => value.push(character),
            Self::Utf16(units) => {
                let mut encoded = [0; 2];
                units.extend(character.encode_utf16(&mut encoded).iter().copied());
            }
        }
    }

    fn push_unit(&mut self, unit: u16) {
        if let Self::Utf8(value) = self {
            if let Some(character) = char::from_u32(u32::from(unit)) {
                value.push(character);
                return;
            }

            let mut units = value.encode_utf16().collect::<Vec<_>>();
            units.push(unit);
            *self = Self::Utf16(units);
            return;
        }

        if let Self::Utf16(units) = self {
            units.push(unit);
        }
    }

    fn finish(self) -> JsString {
        match self {
            Self::Utf8(value) => JsString::from(value),
            Self::Utf16(units) => JsString::from_utf16(units),
        }
    }
}

struct RawParser<'a> {
    input: &'a [u8],
    position: usize,
    depth: usize,
    interned_keys: HashSet<JsString>,
    interned_key_bytes: usize,
}

const MAX_INTERNED_KEYS: usize = 1024;
const MAX_INTERNED_KEY_BYTES: usize = 256 * 1024;

impl<'a> RawParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            position: 0,
            depth: 0,
            interned_keys: HashSet::new(),
            interned_key_bytes: 0,
        }
    }

    fn parse(mut self) -> Result<Json, String> {
        let value = self.value()?;
        self.whitespace();
        if self.position != self.input.len() {
            return self.error("trailing characters");
        }
        Ok(value)
    }

    fn value(&mut self) -> Result<Json, String> {
        self.whitespace();
        match self.peek() {
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b'[') => {
                self.enter_depth()?;
                let result = self.array();
                self.leave_depth();
                result
            }
            Some(b'{') => {
                self.enter_depth()?;
                let result = self.object();
                self.leave_depth();
                result
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.error("expected a JSON value"),
            None => self.error("unexpected end of input"),
        }
    }

    fn literal(&mut self, expected: &[u8], value: Json) -> Result<Json, String> {
        if self
            .input
            .get(self.position..self.position + expected.len())
            == Some(expected)
        {
            self.position += expected.len();
            Ok(value)
        } else {
            self.error("invalid literal")
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.position += 1;
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.position += 1;
                }
            }
            _ => return self.error("invalid number"),
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            let fraction_start = self.position;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.position += 1;
            }
            if fraction_start == self.position {
                return self.error("invalid number fraction");
            }
        }
        if self.peek().is_some_and(|byte| byte == b'e' || byte == b'E') {
            self.position += 1;
            if self.peek().is_some_and(|byte| byte == b'+' || byte == b'-') {
                self.position += 1;
            }
            let exponent_start = self.position;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.position += 1;
            }
            if exponent_start == self.position {
                return self.error("invalid number exponent");
            }
        }
        let text = std::str::from_utf8(&self.input[start..self.position])
            .map_err(|_| "invalid number bytes".to_owned())?;
        let number = text
            .parse::<f64>()
            .map_err(|_| "invalid number".to_owned())?;
        if !number.is_finite() {
            return self.error("number is outside JavaScript's finite range");
        }
        Ok(Json::Number(number))
    }

    fn string(&mut self) -> Result<JsString, String> {
        self.expect(b'"')?;
        let mut value = StringBuilder::new();
        loop {
            match self.next() {
                Some(b'"') => return Ok(value.finish()),
                Some(b'\\') => self.escape(&mut value)?,
                Some(byte @ 0..=0x1f) => {
                    return self.error(&format!("control character {byte:#x} in string"));
                }
                Some(byte) => {
                    let start = self.position - 1;
                    let character = self.decode_character(byte, start)?;
                    value.push_char(character);
                }
                None => return self.error("unterminated string"),
            }
        }
    }

    fn escape(&mut self, value: &mut StringBuilder) -> Result<(), String> {
        match self.next() {
            Some(b'"') => value.push_unit(u16::from(b'"')),
            Some(b'\\') => value.push_unit(u16::from(b'\\')),
            Some(b'/') => value.push_unit(u16::from(b'/')),
            Some(b'b') => value.push_unit(0x08),
            Some(b'f') => value.push_unit(0x0c),
            Some(b'n') => value.push_unit(b'\n' as u16),
            Some(b'r') => value.push_unit(b'\r' as u16),
            Some(b't') => value.push_unit(b'\t' as u16),
            Some(b'u') => value.push_unit(self.hex_escape()?),
            _ => return self.error("invalid string escape"),
        }
        Ok(())
    }

    fn hex_escape(&mut self) -> Result<u16, String> {
        let start = self.position;
        let mut value = 0u16;
        for _ in 0..4 {
            let digit = self
                .next()
                .ok_or_else(|| "incomplete unicode escape".to_owned())?;
            value = value
                .checked_mul(16)
                .and_then(|current| current.checked_add(hex_digit(digit)?))
                .ok_or_else(|| "invalid unicode escape".to_owned())?;
        }
        if self.position - start != 4 {
            return self.error("invalid unicode escape");
        }
        Ok(value)
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        self.whitespace();
        let mut values = Vec::new();
        if self.consume(b']') {
            return Ok(Json::array(values));
        }
        loop {
            values.push(self.value()?);
            self.whitespace();
            if self.consume(b']') {
                return Ok(Json::array(values));
            }
            self.expect(b',')?;
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        self.whitespace();
        let mut object = Obj::new();
        if self.consume(b'}') {
            return Ok(Json::Object(object));
        }
        loop {
            self.whitespace();
            if self.peek() != Some(b'"') {
                return self.error("object key must be a string");
            }
            let parsed_key = self.string()?;
            let key = self.intern_key(parsed_key);
            self.whitespace();
            self.expect(b':')?;
            object.set(key, self.value()?);
            self.whitespace();
            if self.consume(b'}') {
                return Ok(Json::Object(object));
            }
            self.expect(b',')?;
        }
    }

    fn intern_key(&mut self, key: JsString) -> JsString {
        if let Some(existing) = self.interned_keys.get(&key) {
            return existing.clone();
        }

        let key_bytes = key
            .as_str()
            .map_or_else(|| key.len().saturating_mul(2), str::len);
        if self.interned_keys.len() < MAX_INTERNED_KEYS
            && self.interned_key_bytes.saturating_add(key_bytes) <= MAX_INTERNED_KEY_BYTES
        {
            self.interned_key_bytes += key_bytes;
            self.interned_keys.insert(key.clone());
        }
        key
    }

    fn decode_character(&mut self, first: u8, start: usize) -> Result<char, String> {
        let width = utf8_width(first).ok_or_else(|| "invalid UTF-8 in string".to_owned())?;
        while self.position - start < width {
            let byte = self
                .next()
                .ok_or_else(|| "incomplete UTF-8 in string".to_owned())?;
            if byte & 0xc0 != 0x80 {
                return self.error("invalid UTF-8 continuation byte");
            }
        }
        let text = std::str::from_utf8(&self.input[start..self.position])
            .map_err(|_| "invalid UTF-8 in string".to_owned())?;
        text.chars()
            .next()
            .ok_or_else(|| "empty UTF-8 character".to_owned())
    }

    fn whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), String> {
        if self.consume(expected) {
            Ok(())
        } else {
            self.error(&format!("expected `{}`", expected as char))
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn error<T>(&self, message: &str) -> Result<T, String> {
        Err(format!("{message} at byte {}", self.position))
    }

    fn enter_depth(&mut self) -> Result<(), String> {
        if self.depth >= 128 {
            return self.error("JSON nesting exceeds the supported depth of 128");
        }
        self.depth += 1;
        Ok(())
    }

    fn leave_depth(&mut self) {
        self.depth -= 1;
    }
}

fn hex_digit(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some(u16::from(byte - b'0')),
        b'a'..=b'f' => Some(u16::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u16::from(byte - b'A' + 10)),
        _ => None,
    }
}

fn utf8_width(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_follow_javascript_formatting() {
        for (value, expected) in [
            (1.0, "1"),
            (-0.0, "0"),
            (f64::NAN, "null"),
            (f64::INFINITY, "null"),
            (f64::NEG_INFINITY, "null"),
            (f64::from_bits(1), "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (1e20, "100000000000000000000"),
            (1e23, "1e+23"),
            (-0.5, "-0.5"),
            (123_456.789, "123456.789"),
            (1e21, "1e+21"),
            (1.5e-7, "1.5e-7"),
            (0.000_001, "0.000001"),
            (9_007_199_254_740_991.0, "9007199254740991"),
        ] {
            assert_eq!(js_number(value), expected);
            assert_eq!(Json::Number(value).canonical(), expected);
            assert_eq!(Json::Number(value).stringify(), expected);
        }
    }

    #[test]
    fn object_clones_preserve_independent_nested_values_and_key_order() {
        let original = parse(r#"{"nested":{"\ud800":1,"keep":2},"list":[{"value":3}],"tail":4}"#)
            .expect("valid JSON");
        let mut changed = original.obj();
        let Json::Object(nested) = changed.get_mut("nested").expect("nested object") else {
            panic!("expected object");
        };
        nested.remove_js(&JsString::from_utf16(vec![0xd800]));
        nested.set("keep", 5_usize);
        nested.set("added", 6_usize);

        let Some(list) = changed.get_mut("list").and_then(Json::array_mut) else {
            panic!("expected array");
        };
        let Json::Object(item) = &mut list[0] else {
            panic!("expected list object");
        };
        item.set("value", 7_usize);
        changed.remove("tail");

        assert_eq!(
            original.stringify(),
            r#"{"nested":{"\ud800":1,"keep":2},"list":[{"value":3}],"tail":4}"#,
        );
        assert_eq!(
            Json::from(changed).stringify(),
            r#"{"nested":{"keep":5,"added":6},"list":[{"value":7}]}"#,
        );
    }

    #[test]
    fn canonical_orders_keys_by_utf16() {
        let value = parse(r#"{"b":1,"a":{"\ud83d\ude00":1,"\uffff":2},"10":true,"2":false}"#)
            .expect("valid JSON");
        assert_eq!(
            value.canonical(),
            "{\"10\":true,\"2\":false,\"a\":{\"😀\":1,\"\u{ffff}\":2},\"b\":1}"
        );
        assert_eq!(
            value.stringify(),
            "{\"2\":false,\"10\":true,\"b\":1,\"a\":{\"😀\":1,\"\u{ffff}\":2}}"
        );
    }

    #[test]
    fn strings_and_keys_preserve_lone_surrogates_for_serialization_and_digest() {
        let surrogate = JsString::from_utf16([0xd800, b'x' as u16]);
        let value = Obj::new().with(surrogate.clone(), Json::String(surrogate));
        let value = Json::Object(value);

        assert_eq!(value.stringify(), r#"{"\ud800x":"\ud800x"}"#);
        assert_eq!(value.canonical(), r#"{"\ud800x":"\ud800x"}"#);
        assert_eq!(value.digest(), sha256_text(r#"{"\ud800x":"\ud800x"}"#));
    }

    #[test]
    fn pooled_static_keys_keep_assignment_order_and_replacement_semantics() {
        let value = Obj::new()
            .with_static("first", 1_usize)
            .with_static("second", 2_usize)
            .with_static("first", 3_usize);

        let keys = value
            .iter()
            .map(|(key, _)| key.as_str().expect("static key is valid UTF-8"))
            .collect::<Vec<_>>();
        assert_eq!(keys, ["first", "second"]);
        assert_eq!(value.get("first"), Some(&Json::from(3_usize)));
    }

    #[test]
    fn parser_retains_escaped_lone_surrogates() {
        let value = parse(r#"{"\ud800x":"\ud800x"}"#).expect("valid JSON");
        assert_eq!(value.stringify(), r#"{"\ud800x":"\ud800x"}"#);
        assert_eq!(value.canonical(), r#"{"\ud800x":"\ud800x"}"#);

        let decoded: Json = serde_json::from_str(r#"{"\ud800":"\ud800"}"#)
            .expect("raw JSON deserialization preserves surrogate units");
        assert_eq!(decoded.stringify(), r#"{"\ud800":"\ud800"}"#);
    }

    #[test]
    fn stringify_preserves_utf8_and_utf16_equivalent_output() {
        let source = format!("prefix\n\t{}\u{0000}suffix", "🚀".repeat(32));
        let utf8 = Json::String(JsString::from(source.as_str()));
        let exact = Json::String(JsString::from_utf16(
            source.encode_utf16().collect::<Vec<_>>(),
        ));

        assert_eq!(utf8.stringify(), exact.stringify());
        assert_eq!(utf8.canonical(), exact.canonical());
        assert_eq!(
            utf8.stringify(),
            format!("\"prefix\\n\\t{}\\u0000suffix\"", "🚀".repeat(32))
        );
    }

    #[test]
    fn stringify_keeps_lone_surrogate_escapes_byte_exact() {
        let value = Json::String(JsString::from_utf16([b'a' as u16, 0xd800, b'b' as u16]));

        assert_eq!(value.stringify().as_bytes(), b"\"a\\ud800b\"");
        assert_eq!(value.canonical().as_bytes(), b"\"a\\ud800b\"");
    }

    #[test]
    fn repeated_object_keys_share_storage_without_changing_assignment_order() {
        let value = parse(r#"[{"name":1,"\ud800":2},{"name":3,"name":4,"\ud800":5}]"#)
            .expect("valid repeated keys");
        let Json::Object(first) = &value.arr()[0] else {
            panic!("first object");
        };
        let Json::Object(second) = &value.arr()[1] else {
            panic!("second object");
        };

        for ((first_key, _), (second_key, _)) in first.iter().zip(second.iter()) {
            assert!(std::ptr::eq(first_key.units(), second_key.units()));
        }
        assert_eq!(
            value.stringify(),
            r#"[{"name":1,"\ud800":2},{"name":4,"\ud800":5}]"#
        );
    }

    #[test]
    fn key_cache_limits_do_not_limit_parsed_objects() {
        let members = (0..MAX_INTERNED_KEYS + 2)
            .map(|index| format!("\"key-{index}\":{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let source = format!("{{{members}}}");
        let mut parser = RawParser::new(&source);
        let value = parser.value().expect("all keys are parsed");

        assert_eq!(parser.interned_keys.len(), MAX_INTERNED_KEYS);
        assert_eq!(
            value.at(&format!("key-{}", MAX_INTERNED_KEYS + 1)).num(),
            (MAX_INTERNED_KEYS + 1) as f64
        );

        let large_key = JsString::from("x".repeat(MAX_INTERNED_KEY_BYTES + 1));
        let mut parser = RawParser::new("{}");
        assert_eq!(parser.intern_key(large_key.clone()), large_key);
        assert!(parser.interned_keys.is_empty());
    }

    #[test]
    fn parser_rejects_excessive_nesting_without_recursing_unboundedly() {
        let nested = format!("{}0{}", "[".repeat(129), "]".repeat(129));
        let error = parse(&nested).expect_err("nesting beyond the parser bound");
        assert!(error.to_string().contains("supported depth"));
    }
}
