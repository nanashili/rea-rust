//! Direct serde conversion into REA's ordered JSON representation.
//!
//! Ordinary values are built directly. `RawValue` and lone-surrogate strings
//! retain the existing parser boundary because their serialized representation
//! is already raw JSON and must preserve exact UTF-16 code units.

use std::fmt;

use serde::ser::{
    self, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
};

use super::super::semantic::value_types::JsString;
use super::json::{Json, Obj, parse, static_string};

const RAW_VALUE_TOKEN: &str = "$serde_json::private::RawValue";

#[derive(Debug)]
pub(crate) enum DirectJsonError {
    Unsupported(&'static str),
    InvalidNumber,
    InvalidKey,
    Raw(String),
    Message(String),
}

impl fmt::Display for DirectJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(name) => write!(f, "direct Json does not support {name}"),
            Self::InvalidNumber => f.write_str("non-finite JSON number"),
            Self::InvalidKey => f.write_str("object key was not a JavaScript string"),
            Self::Raw(error) | Self::Message(error) => f.write_str(error),
        }
    }
}
impl std::error::Error for DirectJsonError {}
impl ser::Error for DirectJsonError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Message(message.to_string())
    }
}

/// Fallback parser boundary for raw JSON and unpaired-surrogate strings.
///
/// `parse_raw` is used for `RawValue` and for `JsString`'s unpaired-surrogate
/// representation. It preserves existing parser semantics and is not used for
/// ordinary strings, arrays, objects, numbers, or enums.
type ParseRaw = fn(&str) -> Result<Json, DirectJsonError>;

pub(crate) fn serialize<T: ?Sized + Serialize>(value: &T) -> Result<Json, DirectJsonError> {
    serialize_with_parser(value, parse_raw)
}

fn serialize_with_parser<T: ?Sized + Serialize>(
    value: &T,
    parse_raw: ParseRaw,
) -> Result<Json, DirectJsonError> {
    DirectJsonSerializer::new(parse_raw).serialize(value)
}

fn parse_raw(text: &str) -> Result<Json, DirectJsonError> {
    parse(text).map_err(|error| DirectJsonError::Raw(error.to_string()))
}

struct DirectJsonSerializer {
    parse_raw: ParseRaw,
}

impl DirectJsonSerializer {
    fn new(parse_raw: ParseRaw) -> Self {
        Self { parse_raw }
    }

    fn serialize<T: ?Sized + Serialize>(self, value: &T) -> Result<Json, DirectJsonError> {
        value.serialize(self)
    }
}

impl ser::Serializer for DirectJsonSerializer {
    type Ok = Json;
    type Error = DirectJsonError;
    type SerializeSeq = Compound;
    type SerializeTuple = Compound;
    type SerializeTupleStruct = Compound;
    type SerializeTupleVariant = Compound;
    type SerializeMap = Compound;
    type SerializeStruct = Compound;
    type SerializeStructVariant = Compound;

    fn serialize_bool(self, value: bool) -> Result<Json, DirectJsonError> {
        Ok(Json::Bool(value))
    }
    fn serialize_i8(self, value: i8) -> Result<Json, DirectJsonError> {
        self.serialize_i64(value.into())
    }
    fn serialize_i16(self, value: i16) -> Result<Json, DirectJsonError> {
        self.serialize_i64(value.into())
    }
    fn serialize_i32(self, value: i32) -> Result<Json, DirectJsonError> {
        self.serialize_i64(value.into())
    }
    fn serialize_i64(self, value: i64) -> Result<Json, DirectJsonError> {
        Ok(Json::Number(value as f64))
    }
    fn serialize_i128(self, value: i128) -> Result<Json, DirectJsonError> {
        let value = value as f64;
        value
            .is_finite()
            .then_some(Json::Number(value))
            .ok_or(DirectJsonError::InvalidNumber)
    }
    fn serialize_u8(self, value: u8) -> Result<Json, DirectJsonError> {
        self.serialize_u64(value.into())
    }
    fn serialize_u16(self, value: u16) -> Result<Json, DirectJsonError> {
        self.serialize_u64(value.into())
    }
    fn serialize_u32(self, value: u32) -> Result<Json, DirectJsonError> {
        self.serialize_u64(value.into())
    }
    fn serialize_u64(self, value: u64) -> Result<Json, DirectJsonError> {
        Ok(Json::Number(value as f64))
    }
    fn serialize_u128(self, value: u128) -> Result<Json, DirectJsonError> {
        let value = value as f64;
        value
            .is_finite()
            .then_some(Json::Number(value))
            .ok_or(DirectJsonError::InvalidNumber)
    }
    fn serialize_f32(self, value: f32) -> Result<Json, DirectJsonError> {
        // serde_json formats f32 at f32 precision before the graph parser
        // stores it as f64. A direct cast would retain extra binary digits and
        // produce a different graph number for values such as 0.1.
        let text = serde_json::to_string(&value)
            .map_err(|error| DirectJsonError::Message(error.to_string()))?;
        if text == "null" {
            return Ok(Json::Null);
        }
        let number = text
            .parse::<f64>()
            .map_err(|error| DirectJsonError::Message(error.to_string()))?;
        Ok(Json::Number(number))
    }
    fn serialize_f64(self, value: f64) -> Result<Json, DirectJsonError> {
        if value.is_finite() {
            Ok(Json::Number(value))
        } else {
            Ok(Json::Null)
        }
    }
    fn serialize_char(self, value: char) -> Result<Json, DirectJsonError> {
        Ok(Json::String(JsString::from(value.to_string())))
    }
    fn serialize_str(self, value: &str) -> Result<Json, DirectJsonError> {
        Ok(Json::String(JsString::from(value)))
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<Json, DirectJsonError> {
        Ok(Json::array(
            value
                .iter()
                .map(|byte| Json::Number(f64::from(*byte)))
                .collect(),
        ))
    }
    fn serialize_none(self) -> Result<Json, DirectJsonError> {
        Ok(Json::Null)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Json, DirectJsonError> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Json, DirectJsonError> {
        Ok(Json::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Json, DirectJsonError> {
        Ok(Json::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Json, DirectJsonError> {
        Ok(Json::String(static_string(variant)))
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Json, DirectJsonError> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Json, DirectJsonError> {
        let variant_key = static_string(variant);
        let value = value.serialize(self)?;
        let mut object = Obj::new();
        object.set(variant_key, value);
        Ok(Json::Object(object))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Compound, DirectJsonError> {
        Ok(Compound::array(self.parse_raw, len))
    }
    fn serialize_tuple(self, len: usize) -> Result<Compound, DirectJsonError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Compound, DirectJsonError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Compound, DirectJsonError> {
        Ok(Compound::variant_array(self.parse_raw, variant, len))
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Compound, DirectJsonError> {
        Ok(Compound::object(self.parse_raw, len))
    }
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Compound, DirectJsonError> {
        if name == RAW_VALUE_TOKEN {
            return Ok(Compound::raw(self.parse_raw));
        }
        Ok(Compound::object(self.parse_raw, Some(len)))
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Compound, DirectJsonError> {
        Ok(Compound::variant_object(self.parse_raw, variant, len))
    }
}

enum Container {
    Array(Vec<Json>),
    Object(Obj),
    VariantArray(&'static str, Vec<Json>),
    VariantObject(&'static str, Obj),
    Raw(Option<String>),
}

struct Compound {
    parse_raw: ParseRaw,
    container: Container,
    pending_key: Option<JsString>,
}
impl Compound {
    fn array(parse_raw: ParseRaw, len: Option<usize>) -> Self {
        Self {
            parse_raw,
            container: Container::Array(Vec::with_capacity(len.unwrap_or(0))),
            pending_key: None,
        }
    }

    fn object(parse_raw: ParseRaw, len: Option<usize>) -> Self {
        Self {
            parse_raw,
            container: Container::Object(Obj::with_capacity(len.unwrap_or(0))),
            pending_key: None,
        }
    }

    fn variant_array(parse_raw: ParseRaw, variant: &'static str, len: usize) -> Self {
        Self {
            parse_raw,
            container: Container::VariantArray(variant, Vec::with_capacity(len)),
            pending_key: None,
        }
    }

    fn variant_object(parse_raw: ParseRaw, variant: &'static str, len: usize) -> Self {
        Self {
            parse_raw,
            container: Container::VariantObject(variant, Obj::with_capacity(len)),
            pending_key: None,
        }
    }

    fn raw(parse_raw: ParseRaw) -> Self {
        Self {
            parse_raw,
            container: Container::Raw(None),
            pending_key: None,
        }
    }

    fn finish(self) -> Result<Json, DirectJsonError> {
        let Compound {
            parse_raw,
            container,
            ..
        } = self;

        match container {
            Container::Array(values) => Ok(Json::array(values)),
            Container::Object(object) => Ok(Json::Object(object)),
            Container::VariantArray(variant, values) => Ok(Json::Object(
                Obj::new().with_static(variant, Json::array(values)),
            )),
            Container::VariantObject(variant, object) => Ok(Json::Object(
                Obj::new().with_static(variant, Json::Object(object)),
            )),
            Container::Raw(Some(raw)) => (parse_raw)(&raw),
            Container::Raw(None) => Err(DirectJsonError::Raw("RawValue had no payload".into())),
        }
    }
    fn push(&mut self, value: Json) -> Result<(), DirectJsonError> {
        match &mut self.container {
            Container::Array(values) | Container::VariantArray(_, values) => {
                values.push(value);
                Ok(())
            }
            _ => Err(DirectJsonError::Unsupported("sequence item")),
        }
    }
    fn set(&mut self, key: JsString, value: Json) -> Result<(), DirectJsonError> {
        match &mut self.container {
            Container::Object(object) | Container::VariantObject(_, object) => {
                object.set(key, value);
                Ok(())
            }
            _ => Err(DirectJsonError::Unsupported("object field")),
        }
    }

    fn set_static(&mut self, key: &'static str, value: Json) -> Result<(), DirectJsonError> {
        match &mut self.container {
            Container::Object(object) | Container::VariantObject(_, object) => {
                object.set_static(key, value);
                Ok(())
            }
            _ => Err(DirectJsonError::Unsupported("object field")),
        }
    }
}

impl SerializeSeq for Compound {
    type Ok = Json;
    type Error = DirectJsonError;
    fn serialize_element<T: ?Sized + Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), DirectJsonError> {
        let serialized = serialize_with_parser(value, self.parse_raw)?;
        self.push(serialized)
    }
    fn end(self) -> Result<Json, DirectJsonError> {
        self.finish()
    }
}
impl ser::SerializeTuple for Compound {
    type Ok = Json;
    type Error = DirectJsonError;
    fn serialize_element<T: ?Sized + Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), DirectJsonError> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Json, DirectJsonError> {
        self.finish()
    }
}
impl ser::SerializeTupleStruct for Compound {
    type Ok = Json;
    type Error = DirectJsonError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), DirectJsonError> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Json, DirectJsonError> {
        self.finish()
    }
}
impl ser::SerializeTupleVariant for Compound {
    type Ok = Json;
    type Error = DirectJsonError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), DirectJsonError> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Json, DirectJsonError> {
        self.finish()
    }
}

impl SerializeMap for Compound {
    type Ok = Json;
    type Error = DirectJsonError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), DirectJsonError> {
        self.pending_key = Some(key_to_js(key, self.parse_raw)?);
        Ok(())
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), DirectJsonError> {
        let key = self.pending_key.take().ok_or(DirectJsonError::InvalidKey)?;
        let value = serialize_with_parser(value, self.parse_raw)?;
        self.set(key, value)
    }
    fn serialize_entry<K: ?Sized + Serialize, V: ?Sized + Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), DirectJsonError> {
        self.serialize_key(key)?;
        self.serialize_value(value)
    }
    fn end(self) -> Result<Json, DirectJsonError> {
        self.finish()
    }
}
impl SerializeStruct for Compound {
    type Ok = Json;
    type Error = DirectJsonError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        field: &'static str,
        value: &T,
    ) -> Result<(), DirectJsonError> {
        if let Container::Raw(raw) = &mut self.container {
            if field != RAW_VALUE_TOKEN {
                return Err(DirectJsonError::Raw("unexpected RawValue field".into()));
            }
            raw.replace(raw_text(value)?);
            return Ok(());
        }
        let serialized = serialize_with_parser(value, self.parse_raw)?;
        self.set_static(field, serialized)
    }
    fn end(self) -> Result<Json, DirectJsonError> {
        self.finish()
    }
}
impl SerializeStructVariant for Compound {
    type Ok = Json;
    type Error = DirectJsonError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        field: &'static str,
        value: &T,
    ) -> Result<(), DirectJsonError> {
        let serialized = serialize_with_parser(value, self.parse_raw)?;
        self.set_static(field, serialized)
    }
    fn end(self) -> Result<Json, DirectJsonError> {
        self.finish()
    }
}

fn raw_text<T: ?Sized + Serialize>(value: &T) -> Result<String, DirectJsonError> {
    match serde_json::to_value(value)
        .map_err(|error| DirectJsonError::Message(error.to_string()))?
    {
        serde_json::Value::String(text) => Ok(text),
        _ => Err(DirectJsonError::Unsupported("RawValue payload")),
    }
}

struct KeyWrapper<'a, T: ?Sized>(&'a T);

impl<T: ?Sized + Serialize> Serialize for KeyWrapper<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(self.0, &())?;
        map.end()
    }
}

fn key_to_js<T: ?Sized + Serialize>(
    key: &T,
    parse_raw: ParseRaw,
) -> Result<JsString, DirectJsonError> {
    // Use serde_json's own map-key serializer so integer and other supported
    // key types retain its exact coercion and rejection rules.
    let encoded = serde_json::to_string(&KeyWrapper(key))
        .map_err(|error| DirectJsonError::Message(error.to_string()))?;
    match parse_raw(&encoded)? {
        Json::Object(object) => object
            .iter()
            .next()
            .map(|(key, _)| key.clone())
            .ok_or(DirectJsonError::InvalidKey),
        _ => Err(DirectJsonError::InvalidKey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::ser::SerializeMap;
    use std::collections::BTreeMap;

    #[derive(serde::Serialize)]
    struct Representative {
        text: JsString,
        variants: Vec<RepresentativeVariant>,
        newtype: Newtype,
        optional: Option<JsString>,
        numbers: Vec<f64>,
        f32_number: f32,
        key_map: BTreeMap<u32, ()>,
    }

    #[derive(serde::Serialize)]
    struct Newtype(JsString);

    #[derive(serde::Serialize)]
    enum RepresentativeVariant {
        Unit,
        Tuple(JsString, u32),
        Struct { value: JsString },
    }

    struct DuplicateKeys;

    impl Serialize for DuplicateKeys {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(3))?;
            map.serialize_entry("first", &1_u32)?;
            map.serialize_entry("second", &2_u32)?;
            map.serialize_entry("first", &3_u32)?;
            map.end()
        }
    }

    fn oracle<T: Serialize>(value: &T) -> Json {
        let text = serde_json::to_string(value).expect("fixture serializes");
        parse(&text).expect("fixture is valid JSON")
    }

    #[test]
    fn direct_serializer_matches_oracle_for_surrogates_enums_and_numbers() {
        let value = Representative {
            text: JsString::from_utf16([0x0061, 0xd800, 0x0062]),
            variants: vec![
                RepresentativeVariant::Unit,
                RepresentativeVariant::Tuple(JsString::from("ok"), 7),
                RepresentativeVariant::Struct {
                    value: JsString::from("struct"),
                },
            ],
            newtype: Newtype(JsString::from("newtype")),
            optional: None,
            numbers: vec![-0.0, 1.25, f64::NAN, 9_007_199_254_740_993.0],
            f32_number: 0.1,
            key_map: BTreeMap::from([(4, ()), (12, ())]),
        };

        let direct = serialize(&value).expect("direct serialization succeeds");
        assert_eq!(direct, oracle(&value));
        assert_eq!(direct.stringify(), oracle(&value).stringify());
    }

    #[test]
    fn direct_serializer_preserves_duplicate_key_assignment_order() {
        let direct = serialize(&DuplicateKeys).expect("direct serialization succeeds");
        let expected = parse(r#"{"first":3,"second":2}"#).expect("expected JSON");

        assert_eq!(direct, expected);
        assert_eq!(direct.stringify(), r#"{"first":3,"second":2}"#);
    }
}
