//! Public semantic value contracts.
//!
//! The mutation algorithms consume these types, but do not own them.

pub use rea_core::JsString;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceLimit {
    #[serde(rename = "primitive-candidates")]
    PrimitiveCandidates,
    #[serde(rename = "primitive-bytes")]
    PrimitiveBytes,
    #[serde(rename = "expression-depth")]
    ExpressionDepth,
    #[serde(rename = "getter-expansion")]
    GetterExpansion,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Property {
    pub name: JsString,
    pub value: SemanticValue,
    pub presence: SlotPresence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotPresence {
    #[serde(rename = "present")]
    Present,
    #[serde(rename = "absent")]
    Absent,
    #[serde(rename = "unknown-coverage")]
    UnknownCoverage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Coverage {
    Exact,
    Unknown { omitted: Option<usize> },
}

#[derive(Clone, Debug, PartialEq)]
pub enum SemanticValue {
    Literal {
        value: Primitive,
    },
    Union {
        values: Vec<Primitive>,
    },
    Object {
        properties: Vec<Property>,
        coverage: Coverage,
    },
    Array {
        items: Vec<Property>,
        coverage: Coverage,
    },
    Unknown {
        reason: JsString,
        resource_limit: Option<ResourceLimit>,
    },
    Ambiguous {
        reason: JsString,
        resource_limit: Option<ResourceLimit>,
    },
    Cycle {
        reason: JsString,
        resource_limit: Option<ResourceLimit>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Primitive {
    String(JsString),
    Number(f64),
    Boolean(bool),
    Null,
}

impl Serialize for Primitive {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::String(value) => value.serialize(serializer),
            Self::Number(value) => value.serialize(serializer),
            Self::Boolean(value) => value.serialize(serializer),
            Self::Null => serializer.serialize_unit(),
        }
    }
}

impl<'de> Deserialize<'de> for Primitive {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        let text = raw.get();

        if text == "null" {
            return Ok(Self::Null);
        }

        if text == "true" || text == "false" {
            let value = serde_json::from_str(text).map_err(serde::de::Error::custom)?;
            return Ok(Self::Boolean(value));
        }

        if text.starts_with('"') {
            let value = serde_json::from_str(text).map_err(serde::de::Error::custom)?;
            return Ok(Self::String(value));
        }

        let value = serde_json::from_str(text).map_err(serde::de::Error::custom)?;
        Ok(Self::Number(value))
    }
}

#[derive(Deserialize)]
struct SemanticValueWireRaw {
    status: String,
    #[serde(default)]
    value: RawField,
    #[serde(default)]
    values: RawField,
    #[serde(default)]
    properties: RawField,
    #[serde(default, rename = "unknownProperties")]
    unknown_properties: RawField,
    #[serde(default, rename = "omittedProperties")]
    omitted_properties: RawField,
    #[serde(default)]
    items: RawField,
    #[serde(default, rename = "unknownItems")]
    unknown_items: RawField,
    #[serde(default, rename = "omittedItems")]
    omitted_items: RawField,
    #[serde(default)]
    reason: RawField,
    #[serde(default, rename = "resourceLimit")]
    resource_limit: RawField,
}

// Buffer raw tokens rather than serde's enum content representation, which
// requires Unicode scalar strings before JsString can preserve their units.
// The outer option distinguishes an absent field from an explicit JSON null.
#[derive(Default)]
struct RawField(Option<Box<RawValue>>);

impl<'de> Deserialize<'de> for RawField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(Some(Box::<RawValue>::deserialize(deserializer)?)))
    }
}

impl<'de> Deserialize<'de> for SemanticValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = SemanticValueWireRaw::deserialize(deserializer)?;

        match raw.status.as_str() {
            "literal" => Ok(Self::Literal {
                value: decode_required(raw.value.0, "value")?,
            }),
            "union" => Ok(Self::Union {
                values: decode_required(raw.values.0, "values")?,
            }),
            "object" => {
                let properties = decode_required(raw.properties.0, "properties")?;
                let unknown = decode_required(raw.unknown_properties.0, "unknownProperties")?;
                let omitted = decode_optional(raw.omitted_properties.0)?;
                let coverage =
                    decode_coverage(unknown, omitted).map_err(serde::de::Error::custom)?;

                Ok(Self::Object {
                    properties,
                    coverage,
                })
            }
            "array" => {
                let items = decode_required(raw.items.0, "items")?;
                let unknown = decode_required(raw.unknown_items.0, "unknownItems")?;
                let omitted = decode_optional(raw.omitted_items.0)?;
                let coverage =
                    decode_coverage(unknown, omitted).map_err(serde::de::Error::custom)?;

                Ok(Self::Array { items, coverage })
            }
            "unknown" => Ok(Self::Unknown {
                reason: decode_required(raw.reason.0, "reason")?,
                resource_limit: decode_optional(raw.resource_limit.0)?,
            }),
            "ambiguous" => Ok(Self::Ambiguous {
                reason: decode_required(raw.reason.0, "reason")?,
                resource_limit: decode_optional(raw.resource_limit.0)?,
            }),
            "cycle" => Ok(Self::Cycle {
                reason: decode_required(raw.reason.0, "reason")?,
                resource_limit: decode_optional(raw.resource_limit.0)?,
            }),
            status => Err(serde::de::Error::unknown_variant(
                status,
                &[
                    "literal",
                    "union",
                    "object",
                    "array",
                    "unknown",
                    "ambiguous",
                    "cycle",
                ],
            )),
        }
    }
}

fn decode_required<T, E>(raw: Option<Box<RawValue>>, field: &'static str) -> Result<T, E>
where
    T: for<'de> Deserialize<'de>,
    E: serde::de::Error,
{
    let raw = raw.ok_or_else(|| serde::de::Error::missing_field(field))?;
    serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)
}

fn decode_optional<T, E>(raw: Option<Box<RawValue>>) -> Result<Option<T>, E>
where
    T: for<'de> Deserialize<'de>,
    E: serde::de::Error,
{
    let Some(raw) = raw else {
        return Ok(None);
    };

    if raw.get() == "null" {
        return Ok(None);
    }

    serde_json::from_str(raw.get())
        .map(Some)
        .map_err(serde::de::Error::custom)
}

#[derive(Serialize)]
#[serde(tag = "status")]
enum SemanticValueWireRef<'a> {
    #[serde(rename = "literal")]
    Literal { value: &'a Primitive },
    #[serde(rename = "union")]
    Union { values: &'a [Primitive] },
    #[serde(rename = "object")]
    Object {
        properties: &'a [Property],
        #[serde(rename = "unknownProperties")]
        unknown_properties: bool,
        #[serde(rename = "omittedProperties")]
        omitted_properties: Option<usize>,
    },
    #[serde(rename = "array")]
    Array {
        items: &'a [Property],
        #[serde(rename = "unknownItems")]
        unknown_items: bool,
        #[serde(rename = "omittedItems")]
        omitted_items: Option<usize>,
    },
    #[serde(rename = "unknown")]
    Unknown {
        reason: &'a JsString,
        #[serde(rename = "resourceLimit", skip_serializing_if = "Option::is_none")]
        resource_limit: Option<&'a ResourceLimit>,
    },
    #[serde(rename = "ambiguous")]
    Ambiguous {
        reason: &'a JsString,
        #[serde(rename = "resourceLimit", skip_serializing_if = "Option::is_none")]
        resource_limit: Option<&'a ResourceLimit>,
    },
    #[serde(rename = "cycle")]
    Cycle {
        reason: &'a JsString,
        #[serde(rename = "resourceLimit", skip_serializing_if = "Option::is_none")]
        resource_limit: Option<&'a ResourceLimit>,
    },
}

fn decode_coverage(unknown: bool, omitted: Option<usize>) -> Result<Coverage, String> {
    match (unknown, omitted) {
        (false, Some(0)) => Ok(Coverage::Exact),
        (true, omitted) => Ok(Coverage::Unknown { omitted }),
        (false, omitted) => Err(format!(
            "exact semantic coverage must use omittedProperties/items=0, got {omitted:?}"
        )),
    }
}

impl Serialize for SemanticValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wire = match self {
            Self::Literal { value } => SemanticValueWireRef::Literal { value },
            Self::Union { values } => SemanticValueWireRef::Union { values },
            Self::Object {
                properties,
                coverage,
            } => {
                let (unknown_properties, omitted_properties) = match coverage {
                    Coverage::Exact => (false, Some(0)),
                    Coverage::Unknown { omitted } => (true, *omitted),
                };
                SemanticValueWireRef::Object {
                    properties,
                    unknown_properties,
                    omitted_properties,
                }
            }
            Self::Array { items, coverage } => {
                let (unknown_items, omitted_items) = match coverage {
                    Coverage::Exact => (false, Some(0)),
                    Coverage::Unknown { omitted } => (true, *omitted),
                };
                SemanticValueWireRef::Array {
                    items,
                    unknown_items,
                    omitted_items,
                }
            }
            Self::Unknown {
                reason,
                resource_limit,
            } => SemanticValueWireRef::Unknown {
                reason,
                resource_limit: resource_limit.as_ref(),
            },
            Self::Ambiguous {
                reason,
                resource_limit,
            } => SemanticValueWireRef::Ambiguous {
                reason,
                resource_limit: resource_limit.as_ref(),
            },
            Self::Cycle {
                reason,
                resource_limit,
            } => SemanticValueWireRef::Cycle {
                reason,
                resource_limit: resource_limit.as_ref(),
            },
        };
        wire.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn nested_values_round_trip_without_changing_wire_shape() {
        let value = SemanticValue::Object {
            properties: vec![Property {
                name: "nested".into(),
                value: SemanticValue::Array {
                    items: vec![Property {
                        name: "0".into(),
                        value: SemanticValue::Unknown {
                            reason: "bounded".into(),
                            resource_limit: Some(ResourceLimit::GetterExpansion),
                        },
                        presence: SlotPresence::UnknownCoverage,
                    }],
                    coverage: Coverage::Unknown { omitted: None },
                },
                presence: SlotPresence::Present,
            }],
            coverage: Coverage::Exact,
        };
        let encoded = serde_json::to_value(&value).expect("serialize nested value");
        let decoded: SemanticValue =
            serde_json::from_value(encoded.clone()).expect("deserialize nested value");
        assert_eq!(decoded, value);
        assert_eq!(
            serde_json::to_value(decoded).expect("serialize decoded value"),
            encoded
        );
    }

    #[test]
    fn javascript_string_round_trip_preserves_utf16_units() {
        let value = Primitive::String(JsString::from_utf16(vec![0xd800, b'x' as u16]));
        let encoded = serde_json::to_string(&value).expect("serialize JavaScript string");
        assert_eq!(encoded, r#""\ud800x""#);
        let decoded: Primitive =
            serde_json::from_str(&encoded).expect("deserialize JavaScript string");
        assert_eq!(decoded, value);
    }

    #[test]
    fn semantic_reason_round_trip_preserves_utf16_units() {
        let value = SemanticValue::Unknown {
            reason: JsString::from_utf16([b'k' as u16, 0xd800]),
            resource_limit: None,
        };
        let encoded = serde_json::to_string(&value).expect("serialize exact reason");
        assert_eq!(encoded, r#"{"status":"unknown","reason":"k\ud800"}"#);
        let decoded: SemanticValue =
            serde_json::from_str(&encoded).expect("deserialize exact reason");
        assert_eq!(decoded, value);
    }

    #[test]
    fn nested_unpaired_strings_round_trip_without_changing_wire_shape() {
        let value = SemanticValue::Object {
            properties: vec![
                Property {
                    name: "array".into(),
                    value: SemanticValue::Array {
                        items: vec![Property {
                            name: "0".into(),
                            value: SemanticValue::Literal {
                                value: Primitive::String(JsString::from_utf16([0xd800, 0x0061])),
                            },
                            presence: SlotPresence::Present,
                        }],
                        coverage: Coverage::Exact,
                    },
                    presence: SlotPresence::Present,
                },
                Property {
                    name: "union".into(),
                    value: SemanticValue::Union {
                        values: vec![
                            Primitive::String(JsString::from_utf16([0xdc00])),
                            Primitive::Null,
                        ],
                    },
                    presence: SlotPresence::Present,
                },
                Property {
                    name: "reason".into(),
                    value: SemanticValue::Unknown {
                        reason: JsString::from_utf16([0xd800, 0xdc00, 0xdfff]),
                        resource_limit: None,
                    },
                    presence: SlotPresence::Present,
                },
            ],
            coverage: Coverage::Exact,
        };

        let encoded = serde_json::to_string(&value).expect("serialize nested surrogate value");
        let decoded: SemanticValue =
            serde_json::from_str(&encoded).expect("deserialize nested surrogate value");

        assert_eq!(decoded, value);
        assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
    }

    #[test]
    fn literal_null_round_trips_as_a_primitive_value() {
        let value = SemanticValue::Literal {
            value: Primitive::Null,
        };
        let encoded = serde_json::to_string(&value).expect("serialize null literal");
        let decoded: SemanticValue =
            serde_json::from_str(&encoded).expect("deserialize null literal");

        assert_eq!(decoded, value);
        assert!(serde_json::from_str::<SemanticValue>(r#"{"status":"literal"}"#).is_err());
    }

    #[test]
    fn code_point_order_differs_from_utf16_unit_order_for_supplementary_values() {
        let supplementary = JsString::from_utf16([0xd800, 0xdc00]);
        let bmp = JsString::from_utf16([0xe000]);

        assert_eq!(supplementary.cmp(&bmp), Ordering::Less);
        assert_eq!(supplementary.compare_code_points(&bmp), Ordering::Greater);
    }

    #[test]
    fn code_point_comparison_preserves_unpaired_surrogates() {
        let lone_surrogate = JsString::from_utf16([0xd800]);
        let paired_surrogate = JsString::from_utf16([0xd800, 0xdc00]);
        let bmp = JsString::from_utf16([0xe000]);

        assert_eq!(lone_surrogate.compare_code_points(&bmp), Ordering::Less);
        assert_eq!(
            lone_surrogate.compare_code_points(&paired_surrogate),
            Ordering::Less
        );
        assert_eq!(
            paired_surrogate.compare_code_points(&lone_surrogate),
            Ordering::Greater
        );
        assert_eq!(
            lone_surrogate.code_points().collect::<Vec<_>>(),
            vec![0xd800]
        );
    }
}
