//! plutil JSON decoding and bundle projection.
//!
//! Compatibility owner: `src/native/parsers/plist.ts`
//! (`parsePlistJson`, `parsePlistXml`, `plistJsonNeedsNumberTypes`,
//! `decodePlistJson`, `projectPlistBundle`, the number limitation helpers).

use super::numbers::{MAX_SAFE_INTEGER, MIN_SAFE_INTEGER, PlistNumberLiterals};
use super::value::{
    INCOMPLETE_PLIST_NUMBER_LIMITATION, PlistNode, ProjectionError, negative_zero_real,
    negative_zero_real_limitation, non_finite_real_limitation, project_plist_value,
    unknown_date_limitation, unknown_scalar_limitation,
};
use super::xml;
use serde_json::{Map, Number, Value, json};

/// `omittedPrototypeKeysLimitation(count)` (non-null form).
pub(super) fn omitted_prototype_keys_limitation(count: usize) -> String {
    let entry = if count == 1 { "entry" } else { "entries" };
    let was = if count == 1 { "was" } else { "were" };
    format!(
        "{count} dictionary {entry} keyed __proto__ {was} omitted because REA results cannot represent that key."
    )
}

/// Stable bundle metadata projected from one plist value (`PlistBundleMetadata`).
fn project_plist_bundle(value: &Value) -> Value {
    let field = |name: &str| -> Value {
        match value.get(name) {
            Some(Value::String(text)) => Value::String(text.clone()),
            _ => Value::Null,
        }
    };
    json!({
        "identifier": field("CFBundleIdentifier"),
        "executable": field("CFBundleExecutable"),
        "name": field("CFBundleName"),
        "version": field("CFBundleVersion"),
        "short_version": field("CFBundleShortVersionString"),
    })
}

/// One decoded plist with bundle metadata and decoding limitations
/// (`ParsedPlist`).
pub(super) struct ParsedPlist {
    pub value: Value,
    pub bundle: Value,
    pub limitations: Vec<String>,
}

/// `plistJsonNeedsNumberTypes(output)`: whether plutil JSON holds an integral
/// number beyond the exact range of a JSON number.
pub(super) fn plist_json_needs_number_types(output: &str) -> bool {
    let mut found = false;
    // Malformed JSON is reported later by `parse_plist_json`.
    let _ = JsonScanner::new(output).scan(&mut |literal| {
        if literal.is_integral_unsafe() {
            found = true;
        }
    });
    found
}

/// `parsePlistJson(output, xmlConversion?)`.
pub(super) fn parse_plist_json(
    output: &str,
    xml_conversion: Option<&str>,
) -> Result<ParsedPlist, String> {
    let literals = match xml_conversion {
        Some(text) => Some(
            xml::decode_xml_property_list(text)
                .map_err(|error| error.0)?
                .number_literals,
        ),
        None => None,
    };

    let mut exact_integer_count = 0usize;
    let mut ambiguous_number_count = 0usize;
    let mut negative_zero_real_count = 0usize;
    let mut omitted_prototype_keys = 0usize;

    let value = JsonScanner::new(output)
        .decode(&mut NumberClassifier {
            literals: literals.as_ref(),
            exact_integer_count: &mut exact_integer_count,
            ambiguous_number_count: &mut ambiguous_number_count,
            negative_zero_real_count: &mut negative_zero_real_count,
        })
        .map_err(|error| error)?;
    let value = omit_prototype_keys(value, &mut omitted_prototype_keys);

    let bundle = project_plist_bundle(&value);
    let mut limitations = Vec::new();
    if negative_zero_real_count != 0 {
        limitations.push(negative_zero_real_limitation(negative_zero_real_count));
    }
    if literals
        .as_ref()
        .is_some_and(|literals| literals.incomplete)
    {
        limitations.push(INCOMPLETE_PLIST_NUMBER_LIMITATION.to_owned());
    }
    limitations.extend(number_limitations(
        exact_integer_count,
        ambiguous_number_count,
    ));
    if omitted_prototype_keys != 0 {
        limitations.push(omitted_prototype_keys_limitation(omitted_prototype_keys));
    }

    Ok(ParsedPlist {
        value,
        bundle,
        limitations,
    })
}

/// `parsePlistXml(output)`.
pub(super) fn parse_plist_xml(output: &str) -> Result<ParsedPlist, String> {
    let decoded = xml::decode_xml_property_list(output)
        .map_err(|_| "plutil XML conversion was not a readable plist".to_owned())?;
    let literals = decoded.number_literals;
    let projected =
        project_plist_value(&decoded.value).map_err(|ProjectionError(message)| message)?;

    // The XML decoder turns <integer> and <real> into numbers before the
    // projection, rounding integers beyond the exact range.
    let mut exact_integer_count = 0usize;
    let mut ambiguous_number_count = 0usize;
    let value = map_json_numbers(projected.value, &mut |number| {
        let Some(item) = number.as_f64() else {
            return Value::Number(number.clone());
        };
        let decimals = literals.integers.get(&item.to_bits());
        let Some(decimals) = decimals else {
            return Value::Number(number.clone());
        };
        if literals.incomplete || decimals.len() != 1 || literals.has_real(item) {
            ambiguous_number_count += 1;
            return Value::Number(number.clone());
        }
        exact_integer_count += 1;
        json!({ "$plist_type": "integer", "decimal": decimals[0] })
    });

    let bundle = project_plist_bundle(&value);
    let mut limitations = vec![
        "plutil cannot express this plist as JSON, so it was decoded from plutil's XML conversion; data and date values are typed objects such as { \"$plist_type\": \"data\", \"base64\": ... }.".to_owned(),
    ];
    if projected.non_finite_real_count != 0 {
        limitations.push(non_finite_real_limitation(projected.non_finite_real_count));
    }
    if projected.negative_zero_real_count != 0 {
        limitations.push(negative_zero_real_limitation(
            projected.negative_zero_real_count,
        ));
    }
    if projected.unknown_date_count != 0 {
        limitations.push(unknown_date_limitation(projected.unknown_date_count));
    }
    if projected.unknown_scalar_count != 0 {
        limitations.push(unknown_scalar_limitation(projected.unknown_scalar_count));
    }
    if literals.incomplete {
        limitations.push(INCOMPLETE_PLIST_NUMBER_LIMITATION.to_owned());
    }
    limitations.extend(number_limitations(
        exact_integer_count,
        ambiguous_number_count,
    ));
    if decoded.omitted_prototype_keys != 0 {
        limitations.push(omitted_prototype_keys_limitation(
            decoded.omitted_prototype_keys,
        ));
    }

    Ok(ParsedPlist {
        value,
        bundle,
        limitations,
    })
}

fn number_limitations(exact_integer_count: usize, ambiguous_number_count: usize) -> Vec<String> {
    let mut limitations = Vec::new();
    if exact_integer_count != 0 {
        limitations.push(format!(
            "{exact_integer_count} integer value(s) exceed the exact range of a JSON number and are reported as {{ \"$plist_type\": \"integer\", \"decimal\": \"<exact digits>\" }}."
        ));
    }
    if ambiguous_number_count != 0 {
        limitations.push(format!(
            "{ambiguous_number_count} number(s) beyond the exact range of a JSON number are reported as decoded because the XML literal they came from, a rounded <integer> or a <real>, cannot be identified."
        ));
    }
    limitations
}

fn map_json_numbers(value: Value, map: &mut impl FnMut(&Number) -> Value) -> Value {
    match value {
        Value::Number(number) => map(&number),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| map_json_numbers(item, map))
                .collect(),
        ),
        Value::Object(object) => {
            let mut mapped = Map::new();
            for (key, child) in object {
                mapped.insert(key, map_json_numbers(child, map));
            }
            Value::Object(mapped)
        }
        other => other,
    }
}

/// `omitPrototypeKeys` for a JSON value tree (JSON objects cannot carry a
/// typed scalar, so every object is a plain dictionary here).
fn omit_prototype_keys(value: Value, omitted: &mut usize) -> Value {
    match value {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| omit_prototype_keys(item, omitted))
                .collect(),
        ),
        Value::Object(object) => {
            let mut mapped = Map::new();
            for (key, child) in object {
                if key == "__proto__" {
                    *omitted += 1;
                    continue;
                }
                mapped.insert(key, omit_prototype_keys(child, omitted));
            }
            Value::Object(mapped)
        }
        other => other,
    }
}

// ----------------------------------------------------------------------------
// JSON scanning with source-literal classification
// ----------------------------------------------------------------------------

/// One number literal observed during JSON decoding, with its source digits.
pub(super) struct NumberLiteral<'a> {
    /// The parsed double value.
    value: f64,
    /// The exact source text of the literal (`context.source`).
    source: &'a str,
}

impl NumberLiteral<'_> {
    /// Whether the literal is an integral spelling beyond the safe integer
    /// range (`!Number.isSafeInteger && INTEGRAL_LITERAL.test(source)`).
    fn is_integral_unsafe(&self) -> bool {
        is_integral_literal(self.source) && !is_safe_integer(self.value)
    }
}

/// Classify numbers during decode, mirroring the `decodePlistJson` reviver.
struct NumberClassifier<'a, 'c> {
    literals: Option<&'c PlistNumberLiterals>,
    exact_integer_count: &'a mut usize,
    ambiguous_number_count: &'a mut usize,
    negative_zero_real_count: &'a mut usize,
}

impl NumberClassifier<'_, '_> {
    fn classify(&mut self, literal: &NumberLiteral<'_>) -> Value {
        // `Object.is(item, -0)` — a plist integer has no signed zero.
        if literal.value == 0.0 && literal.value.is_sign_negative() {
            *self.negative_zero_real_count += 1;
            return negative_zero_real();
        }
        if !literal.is_integral_unsafe() {
            return number_value(literal);
        }
        // `classify(item, digits)` using the XML literals.
        let exact = parse_i128(literal.source);
        let integer = self.literals.is_some_and(|literals| {
            !literals.incomplete && integer_match(literals, literal.value, exact.as_ref())
        });
        let real = self
            .literals
            .is_some_and(|literals| !literals.incomplete && literals.has_real(literal.value));
        if integer && !real {
            *self.exact_integer_count += 1;
            return json!({ "$plist_type": "integer", "decimal": literal.source });
        }
        if real && !integer {
            // An integral <real> decodes exactly; only its JSON spelling is integral.
            return number_value(literal);
        }
        *self.ambiguous_number_count += 1;
        number_value(literal)
    }
}

/// Whether the XML literals hold the exact source digits for this rounded value
/// (`literals.integers.get(item)?.has(exact)`).
fn integer_match(literals: &PlistNumberLiterals, value: f64, exact: Option<&i128>) -> bool {
    let Some(exact) = exact else {
        return false;
    };
    let canonical = exact.to_string();
    literals
        .integers
        .get(&value.to_bits())
        .is_some_and(|decimals| decimals.iter().any(|decimal| decimal == &canonical))
}

/// Render a number literal as its decoded JSON number.
fn number_value(literal: &NumberLiteral<'_>) -> Value {
    serde_json::from_str::<Value>(literal.source).unwrap_or(Value::Null)
}

fn parse_i128(source: &str) -> Option<i128> {
    source.parse::<i128>().ok()
}

fn is_integral_literal(source: &str) -> bool {
    // `^-?\d+$`
    let digits = source.strip_prefix('-').unwrap_or(source);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_safe_integer(value: f64) -> bool {
    value.is_finite()
        && value.fract() == 0.0
        && (MIN_SAFE_INTEGER as f64..=MAX_SAFE_INTEGER as f64).contains(&value)
}

/// A minimal order-preserving JSON reader that exposes each number's source
/// text, matching the `JSON.parse` reviver behavior the TypeScript decoder
/// relies on. plutil emits UTF-8 that may carry a leading BOM.
struct JsonScanner<'a> {
    text: &'a str,
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> JsonScanner<'a> {
    fn new(output: &'a str) -> Self {
        // `output.replace(/^\uFEFF/u, "")` — strip a leading BOM.
        let text = output.strip_prefix('\u{feff}').unwrap_or(output);
        Self {
            text,
            bytes: text.as_bytes(),
            cursor: 0,
        }
    }

    /// Decode the document into a classified JSON value.
    fn decode(mut self, classifier: &mut NumberClassifier<'_, '_>) -> Result<Value, String> {
        self.skip_whitespace();
        let value = self.parse_value(classifier)?;
        self.skip_whitespace();
        if self.cursor != self.bytes.len() {
            return Err("Unexpected trailing characters in JSON".to_owned());
        }
        Ok(value)
    }

    /// Walk the document reporting every number literal without materializing
    /// the value tree (used by `plist_json_needs_number_types`).
    fn scan(mut self, visit: &mut impl FnMut(&NumberLiteral<'_>)) -> Result<(), String> {
        self.skip_whitespace();
        self.skip_value(visit)?;
        Ok(())
    }

    fn parse_value(&mut self, classifier: &mut NumberClassifier<'_, '_>) -> Result<Value, String> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.parse_object(classifier),
            Some(b'[') => self.parse_array(classifier),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => {
                let literal = self.read_number_literal()?;
                Ok(classifier.classify(&literal))
            }
            _ => Err("Unexpected token in JSON".to_owned()),
        }
    }

    fn skip_value(&mut self, visit: &mut impl FnMut(&NumberLiteral<'_>)) -> Result<(), String> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => {
                self.cursor += 1;
                self.skip_whitespace();
                if self.peek() == Some(b'}') {
                    self.cursor += 1;
                    return Ok(());
                }
                loop {
                    self.skip_whitespace();
                    let _ = self.parse_string()?;
                    self.skip_whitespace();
                    self.expect(b':')?;
                    self.skip_value(visit)?;
                    self.skip_whitespace();
                    match self.peek() {
                        Some(b',') => self.cursor += 1,
                        Some(b'}') => {
                            self.cursor += 1;
                            return Ok(());
                        }
                        _ => return Err("Expected ',' or '}' in JSON object".to_owned()),
                    }
                }
            }
            Some(b'[') => {
                self.cursor += 1;
                self.skip_whitespace();
                if self.peek() == Some(b']') {
                    self.cursor += 1;
                    return Ok(());
                }
                loop {
                    self.skip_value(visit)?;
                    self.skip_whitespace();
                    match self.peek() {
                        Some(b',') => self.cursor += 1,
                        Some(b']') => {
                            self.cursor += 1;
                            return Ok(());
                        }
                        _ => return Err("Expected ',' or ']' in JSON array".to_owned()),
                    }
                }
            }
            Some(b'"') => {
                let _ = self.parse_string()?;
                Ok(())
            }
            Some(b't') | Some(b'f') => {
                let _ = self.parse_bool()?;
                Ok(())
            }
            Some(b'n') => {
                let _ = self.parse_null()?;
                Ok(())
            }
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => {
                let literal = self.read_number_literal()?;
                visit(&literal);
                Ok(())
            }
            _ => Err("Unexpected token in JSON".to_owned()),
        }
    }

    fn parse_object(&mut self, classifier: &mut NumberClassifier<'_, '_>) -> Result<Value, String> {
        self.cursor += 1; // consume '{'
        let mut map = Map::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.cursor += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.parse_value(classifier)?;
            map.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.cursor += 1,
                Some(b'}') => {
                    self.cursor += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err("Expected ',' or '}' in JSON object".to_owned()),
            }
        }
    }

    fn parse_array(&mut self, classifier: &mut NumberClassifier<'_, '_>) -> Result<Value, String> {
        self.cursor += 1; // consume '['
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.cursor += 1;
            return Ok(Value::Array(items));
        }
        loop {
            let value = self.parse_value(classifier)?;
            items.push(value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.cursor += 1,
                Some(b']') => {
                    self.cursor += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err("Expected ',' or ']' in JSON array".to_owned()),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut output = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err("Unterminated JSON string".to_owned());
            };
            match byte {
                b'"' => {
                    self.cursor += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.cursor += 1;
                    let escape = self.peek().ok_or("Unterminated JSON escape")?;
                    self.cursor += 1;
                    match escape {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000c}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'u' => output.push(self.parse_unicode_escape()?),
                        _ => return Err("Invalid JSON escape".to_owned()),
                    }
                }
                _ => {
                    let character = self.text[self.cursor..]
                        .chars()
                        .next()
                        .ok_or("Invalid JSON string")?;
                    output.push(character);
                    self.cursor += character.len_utf8();
                }
            }
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, String> {
        let high = self.read_hex4()?;
        if (0xd800..=0xdbff).contains(&high) {
            // Surrogate pair.
            if self.text[self.cursor..].starts_with("\\u") {
                self.cursor += 2;
                let low = self.read_hex4()?;
                if (0xdc00..=0xdfff).contains(&low) {
                    let code = 0x10000 + (((high - 0xd800) << 10) | (low - 0xdc00));
                    return char::from_u32(code).ok_or_else(|| "Invalid surrogate pair".to_owned());
                }
            }
            return Err("Invalid surrogate pair".to_owned());
        }
        char::from_u32(high).ok_or_else(|| "Invalid unicode escape".to_owned())
    }

    fn read_hex4(&mut self) -> Result<u32, String> {
        if self.cursor + 4 > self.bytes.len() {
            return Err("Truncated unicode escape".to_owned());
        }
        let hex = &self.text[self.cursor..self.cursor + 4];
        let code = u32::from_str_radix(hex, 16).map_err(|_| "Invalid unicode escape".to_owned())?;
        self.cursor += 4;
        Ok(code)
    }

    fn parse_bool(&mut self) -> Result<Value, String> {
        if self.text[self.cursor..].starts_with("true") {
            self.cursor += 4;
            Ok(Value::Bool(true))
        } else if self.text[self.cursor..].starts_with("false") {
            self.cursor += 5;
            Ok(Value::Bool(false))
        } else {
            Err("Invalid JSON literal".to_owned())
        }
    }

    fn parse_null(&mut self) -> Result<Value, String> {
        if self.text[self.cursor..].starts_with("null") {
            self.cursor += 4;
            Ok(Value::Null)
        } else {
            Err("Invalid JSON literal".to_owned())
        }
    }

    fn read_number_literal(&mut self) -> Result<NumberLiteral<'a>, String> {
        let start = self.cursor;
        if self.peek() == Some(b'-') {
            self.cursor += 1;
        }
        while let Some(byte) = self.peek() {
            if byte.is_ascii_digit()
                || byte == b'.'
                || byte == b'e'
                || byte == b'E'
                || byte == b'+'
                || byte == b'-'
            {
                self.cursor += 1;
            } else {
                break;
            }
        }
        let source = &self.text[start..self.cursor];
        let value: f64 = source
            .parse()
            .map_err(|_| format!("Invalid JSON number: {source}"))?;
        Ok(NumberLiteral { value, source })
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.cursor += 1;
            Ok(())
        } else {
            Err(format!("Expected '{}' in JSON", byte as char))
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.cursor).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if byte == b' ' || byte == b'\t' || byte == b'\n' || byte == b'\r' {
                self.cursor += 1;
            } else {
                break;
            }
        }
    }
}

/// Convert a decoded [`PlistNode`] into a JSON value. Exposed so the signature
/// family can reuse the XML projection for entitlements.
pub(super) fn project_node(
    node: &PlistNode,
) -> Result<super::value::ProjectedPlistValue, ProjectionError> {
    project_plist_value(node)
}
