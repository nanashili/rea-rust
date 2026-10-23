//! Decoded property-list values and their JSON projection.
//!
//! Compatibility owners: `src/domain/apple/plistValue.ts`
//! (`projectPlistValue`, the limitation helpers and `negativeZeroReal`),
//! `src/domain/apple/unknownPlistScalar.ts` (`UnknownPlistScalar`) and
//! `src/domain/apple/plistNumbers.ts` (`createPlistNumberProjection`).

use serde_json::{Map, Number, Value, json};

/// `MAX_PLIST_DEPTH` in `src/domain/apple/plistValue.ts`.
pub(crate) const MAX_PLIST_DEPTH: usize = 128;

/// The reason an XML scalar literal could not be established, mirrored from
/// `UnknownPlistScalar`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnknownScalarReason {
    InvalidLiteral,
    UnsupportedMarkup,
    Unrepresentable,
}

impl UnknownScalarReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLiteral => "invalid-literal",
            Self::UnsupportedMarkup => "unsupported-markup",
            Self::Unrepresentable => "unrepresentable",
        }
    }
}

/// The XML element an unknown scalar came from, mirrored from
/// `UnknownPlistScalar.element`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnknownScalarElement {
    Integer,
    Real,
    Date,
    True,
    False,
}

impl UnknownScalarElement {
    fn as_str(self) -> &'static str {
        match self {
            Self::Integer => "integer",
            Self::Real => "real",
            Self::Date => "date",
            Self::True => "true",
            Self::False => "false",
        }
    }
}

/// A decoded plist value before JSON projection. This mirrors the JavaScript
/// value graph the TypeScript decoder produces, preserving the distinctions a
/// `serde_json::Value` cannot carry (dates, data, retained big integers,
/// non-finite and negative-zero reals, and unknown XML scalars).
#[derive(Clone, Debug)]
pub(crate) enum PlistNode {
    Null,
    Bool(bool),
    /// A finite real; `-0.0` keeps its sign for the negative-zero projection.
    Real(f64),
    /// A real the decoder could not express as a JSON number (non-finite).
    NonFiniteReal(NonFiniteLabel),
    /// An integer within the exact JSON range.
    Integer(i64),
    /// An integer beyond the finite double range, retained as exact digits.
    BigInteger(String),
    String(String),
    /// Raw bytes, projected as a `$plist_type: "data"` object.
    Data(Vec<u8>),
    /// A representable date, projected as `{ $plist_type: "date", iso8601 }`.
    Date(String),
    /// An XML scalar literal retained as an explicit unknown.
    UnknownScalar {
        element: UnknownScalarElement,
        literal: String,
        reason: UnknownScalarReason,
    },
    Array(Vec<PlistNode>),
    /// Insertion-ordered dictionary entries (`__proto__` omission is handled
    /// at the decoder boundary, so no entry here is named `__proto__`).
    Dict(Vec<(String, PlistNode)>),
}

/// The canonical label for a known non-finite real, mirrored from the
/// `nan/+infinity/-infinity` spellings in `projectPlistValue`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NonFiniteLabel {
    Nan,
    PositiveInfinity,
    NegativeInfinity,
}

impl NonFiniteLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nan => "nan",
            Self::PositiveInfinity => "+infinity",
            Self::NegativeInfinity => "-infinity",
        }
    }
}

/// Result of projecting a decoded plist into JSON (`ProjectedPlistValue`).
#[derive(Debug)]
pub(crate) struct ProjectedPlistValue {
    pub value: Value,
    pub non_finite_real_count: usize,
    pub negative_zero_real_count: usize,
    pub unknown_date_count: usize,
    pub unknown_scalar_count: usize,
}

/// `negativeZeroReal()`.
pub(crate) fn negative_zero_real() -> Value {
    json!({ "$plist_type": "real", "value": "-0" })
}

/// `unknownDateLimitation(count)`.
pub(crate) fn unknown_date_limitation(count: usize) -> String {
    format!(
        "{count} date value(s) are reported as {{ \"$plist_type\": \"date\", \"iso8601\": null }} because the decoder could not represent their timestamps."
    )
}

/// `unknownScalarLimitation(count)`.
pub(crate) fn unknown_scalar_limitation(count: usize) -> String {
    format!(
        "{count} XML scalar value(s) could not be established; their exact literals and reasons are retained in {{ \"$plist_type\": \"unknown\", \"element\": ..., \"literal\": ..., \"reason\": ... }} wrappers."
    )
}

/// `nonFiniteRealLimitation(count)`.
pub(crate) fn non_finite_real_limitation(count: usize) -> String {
    format!(
        "{count} non-finite real value(s) are reported as {{ \"$plist_type\": \"real\", \"value\": \"<spelling>\" }} using canonical numeric labels nan, +infinity or -infinity because a JSON number cannot carry them."
    )
}

/// `negativeZeroRealLimitation(count)`.
pub(crate) fn negative_zero_real_limitation(count: usize) -> String {
    format!(
        "{count} negative-zero real value(s) are reported as {{ \"$plist_type\": \"real\", \"value\": \"-0\" }} because a JSON number cannot carry the sign of zero."
    )
}

/// `incompletePlistNumberLimitation`.
pub(crate) const INCOMPLETE_PLIST_NUMBER_LIMITATION: &str = "Property-list number metadata could not be completely observed; decoded numbers may lose integer precision and exact integer/real association is unavailable.";

/// A projection error mirroring the `RangeError`/`TypeError` the TypeScript
/// projection throws for a plist beyond the supported nesting bound.
#[derive(Debug)]
pub(crate) struct ProjectionError(pub String);

/// `projectPlistValue(value)`.
///
/// Projects a decoded plist into JSON. Data, dates, retained big integers and
/// known non-finite reals become explicit `$plist_type` objects; unresolved
/// XML scalars remain explicit unknowns; a negative-zero real keeps its sign.
pub(crate) fn project_plist_value(
    node: &PlistNode,
) -> Result<ProjectedPlistValue, ProjectionError> {
    let mut projector = Projector::default();
    let value = projector.project(node, 0)?;
    Ok(ProjectedPlistValue {
        value,
        non_finite_real_count: projector.non_finite_real_count,
        negative_zero_real_count: projector.negative_zero_real_count,
        unknown_date_count: projector.unknown_date_count,
        unknown_scalar_count: projector.unknown_scalar_count,
    })
}

#[derive(Default)]
struct Projector {
    non_finite_real_count: usize,
    negative_zero_real_count: usize,
    unknown_date_count: usize,
    unknown_scalar_count: usize,
}

impl Projector {
    fn project(&mut self, node: &PlistNode, depth: usize) -> Result<Value, ProjectionError> {
        if depth > MAX_PLIST_DEPTH {
            return Err(ProjectionError(format!(
                "Plist exceeds {MAX_PLIST_DEPTH} nesting levels"
            )));
        }
        Ok(match node {
            PlistNode::Null => Value::Null,
            PlistNode::Bool(value) => Value::Bool(*value),
            PlistNode::String(value) => Value::String(value.clone()),
            PlistNode::Data(bytes) => {
                use base64::Engine as _;
                json!({
                    "$plist_type": "data",
                    "base64": base64::engine::general_purpose::STANDARD.encode(bytes),
                })
            }
            PlistNode::UnknownScalar {
                element,
                literal,
                reason,
            } => {
                self.unknown_scalar_count += 1;
                json!({
                    "$plist_type": "unknown",
                    "element": element.as_str(),
                    "literal": literal,
                    "reason": reason.as_str(),
                })
            }
            PlistNode::Date(iso8601) => json!({ "$plist_type": "date", "iso8601": iso8601 }),
            PlistNode::NonFiniteReal(label) => {
                self.non_finite_real_count += 1;
                json!({ "$plist_type": "real", "value": label.as_str() })
            }
            PlistNode::Real(value) => {
                // Integer decoders never yield -0, so a signed zero here is a real.
                if *value == 0.0 && value.is_sign_negative() {
                    self.negative_zero_real_count += 1;
                    negative_zero_real()
                } else {
                    js_number_to_json(*value)
                }
            }
            PlistNode::Integer(value) => json!(*value),
            PlistNode::BigInteger(decimal) => {
                json!({ "$plist_type": "integer", "decimal": decimal })
            }
            PlistNode::Array(items) => {
                let mut result = Vec::with_capacity(items.len());
                for item in items {
                    result.push(self.project(item, depth + 1)?);
                }
                Value::Array(result)
            }
            PlistNode::Dict(entries) => {
                let mut map = Map::new();
                for (key, item) in entries {
                    map.insert(key.clone(), self.project(item, depth + 1)?);
                }
                Value::Object(map)
            }
        })
    }
}

/// Project a finite `f64` into a JSON number the way `JSON.stringify` renders a
/// JavaScript number: an integral value serializes without a fractional part.
pub(crate) fn js_number_to_json(value: f64) -> Value {
    if value == 0.0 {
        // Positive zero (negative zero is handled by the caller as a real).
        return Value::Number(Number::from(0));
    }
    if value.fract() == 0.0 && value.abs() < 9.007_199_254_740_992e15 {
        // Exactly representable as an integer; render it as one.
        return Value::Number(Number::from(value as i64));
    }
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}
