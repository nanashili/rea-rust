//! Source numeric facts and the exact-integer projection.
//!
//! Compatibility owner: `src/domain/apple/plistNumbers.ts`
//! (`createPlistNumberCollector`, `createPlistNumberProjection`,
//! `PlistNumberLiterals`, `incompletePlistNumberLimitation`).

use super::value::INCOMPLETE_PLIST_NUMBER_LIMITATION;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashSet};

/// JavaScript `Number.MAX_SAFE_INTEGER`.
pub(crate) const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;
/// JavaScript `Number.MIN_SAFE_INTEGER`.
pub(crate) const MIN_SAFE_INTEGER: i128 = -9_007_199_254_740_991;

/// A decoded `f64` keyed by its bit pattern so `+0.0`, `-0.0` and distinct
/// doubles never collide, matching JavaScript `Map<number, ...>` identity.
type NumberKey = u64;

fn number_key(value: f64) -> NumberKey {
    value.to_bits()
}

/// `PlistNumberLiterals`: the source element types needed to distinguish large
/// integers from integral reals.
#[derive(Debug, Default, Clone)]
pub(crate) struct PlistNumberLiterals {
    /// Rounded integer values mapped to the exact decimal literals observed.
    pub integers: BTreeMap<NumberKey, Vec<String>>,
    /// Rounded real values observed in the source.
    pub reals: HashSet<NumberKey>,
    /// Integer literals beyond the exact JSON range in the original source.
    pub unsafe_integer_literals: usize,
    /// Whether source numeric facts could not all be established.
    pub incomplete: bool,
}

impl PlistNumberLiterals {
    /// `collector.integer(exact)`.
    pub(crate) fn record_integer(&mut self, exact: i128) {
        if (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&exact) {
            return;
        }
        self.unsafe_integer_literals += 1;
        let rounded = exact as f64;
        let decimals = self.integers.entry(number_key(rounded)).or_default();
        let decimal = exact.to_string();
        if !decimals.contains(&decimal) {
            decimals.push(decimal);
        }
    }

    /// `collector.real(value)`.
    pub(crate) fn record_real(&mut self, value: f64) {
        self.reals.insert(number_key(value));
    }

    pub(crate) fn has_integer_key(&self, value: f64) -> bool {
        self.integers.contains_key(&number_key(value))
    }

    fn integer_decimals(&self, value: f64) -> Option<&Vec<String>> {
        self.integers.get(&number_key(value))
    }

    pub(crate) fn has_real(&self, value: f64) -> bool {
        self.reals.contains(&number_key(value))
    }
}

/// Whether a decoded double is a JavaScript safe integer
/// (`Number.isSafeInteger`).
fn is_safe_integer(item: f64) -> bool {
    item.is_finite() && item.fract() == 0.0 && item.abs() <= MAX_SAFE_INTEGER as f64
}

/// Whether a decoded double is a JavaScript integer (`Number.isInteger`).
fn is_integer(item: f64) -> bool {
    item.is_finite() && item.fract() == 0.0
}

/// `createPlistNumberProjection(literals)`: preserve unambiguous exact integers
/// and disclose rounded or unclassified numbers. Operates over an already
/// JSON-projected value tree (as `parseEntitlements` does).
pub(crate) struct PlistNumberProjection {
    literals: PlistNumberLiterals,
    exact_integer_count: usize,
    ambiguous_number_count: usize,
}

impl PlistNumberProjection {
    pub(crate) fn new(literals: PlistNumberLiterals) -> Self {
        Self {
            literals,
            exact_integer_count: 0,
            ambiguous_number_count: 0,
        }
    }

    pub(crate) fn project(&mut self, value: Value) -> Value {
        self.map(value)
    }

    fn map_number(&mut self, number: &serde_json::Number) -> Value {
        let Some(item) = number.as_f64() else {
            return Value::Number(number.clone());
        };
        // `if (Number.isSafeInteger(item) || !Number.isInteger(item)) return item;`
        if is_safe_integer(item) || !is_integer(item) {
            return Value::Number(number.clone());
        }
        if self.literals.incomplete {
            self.ambiguous_number_count += 1;
            return Value::Number(number.clone());
        }
        let Some(decimals) = self.literals.integer_decimals(item) else {
            if !self.literals.has_real(item) {
                self.ambiguous_number_count += 1;
            }
            return Value::Number(number.clone());
        };
        if decimals.len() != 1 || self.literals.has_real(item) {
            self.ambiguous_number_count += 1;
            return Value::Number(number.clone());
        }
        let decimal = decimals[0].clone();
        self.exact_integer_count += 1;
        json!({ "$plist_type": "integer", "decimal": decimal })
    }

    fn map(&mut self, value: Value) -> Value {
        match value {
            Value::Number(number) => self.map_number(&number),
            Value::Array(items) => {
                Value::Array(items.into_iter().map(|item| self.map(item)).collect())
            }
            Value::Object(object) => {
                let keys: Vec<&String> = object.keys().collect();
                let reference = keys.len() == 1
                    && matches!(keys[0].as_str(), "UID" | "CF$UID")
                    && matches!(object.values().next(), Some(Value::Number(_)));
                if reference {
                    // Keep malformed numeric reference markers recognizable.
                    if let Some(Value::Number(number)) = object.values().next()
                        && let Some(item) = number.as_f64()
                        && !is_safe_integer(item)
                        && (self.literals.has_integer_key(item) || !self.literals.has_real(item))
                    {
                        self.ambiguous_number_count += 1;
                    }
                    return Value::Object(object);
                }
                let mut mapped = Map::new();
                for (key, child) in object {
                    mapped.insert(key, self.map(child));
                }
                Value::Object(mapped)
            }
            other => other,
        }
    }

    /// `projection.limitations()`.
    pub(crate) fn limitations(&self) -> Vec<String> {
        let mut limitations = Vec::new();
        if self.literals.incomplete {
            limitations.push(INCOMPLETE_PLIST_NUMBER_LIMITATION.to_owned());
        }
        if self.literals.unsafe_integer_literals != 0 {
            limitations.push(format!(
                "{} observed integer literal(s) in the original archive exceed the exact range of a JSON number. Decoded numbers may lose integer precision unless represented as {{ \"$plist_type\": \"integer\", \"decimal\": \"<exact digits>\" }}; the original archive bytes retain those literals.",
                self.literals.unsafe_integer_literals
            ));
        }
        if self.exact_integer_count != 0 {
            limitations.push(format!(
                "{} unambiguous integer value(s) are reported with exact decimal text as {{ \"$plist_type\": \"integer\", \"decimal\": \"<exact digits>\" }}.",
                self.exact_integer_count
            ));
        }
        if self.ambiguous_number_count != 0 {
            limitations.push(format!(
                "{} number(s) beyond the exact integer range remain as decoded because their source integer/real type or reference marker cannot be associated unambiguously; integer precision loss remains possible.",
                self.ambiguous_number_count
            ));
        }
        limitations
    }
}
